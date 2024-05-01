#!/usr/bin/env python3

import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed
import cloudgenix_settings
import sys
import logging
import os
import datetime
import collections
import csv
from csv import DictReader
import time
from datetime import datetime, timedelta
jdout = cloudgenix.jdout


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: LQM Apps'
SCRIPT_VERSION = "v1"
directory = 'path_data'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes network.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


def deploy(cgx, loss, latency, jitter):

    
    for site in cgx.get.sites().cgx_content["items"]:
        if site["element_cluster_role"] == "SPOKE":
            for element in cgx.get.elements().cgx_content["items"]:
                if element["site_id"] == site["id"]:
                    if "6.3" in element["software_version"]:
                        print("For element with version 6.3.1 please use performance policy")
                    else:
                        create_lqm = True
                        for item in cgx.get.element_extensions(site_id = site["id"], element_id = element["id"]).cgx_content["items"]:
                            if item["name"] == "All-Apps":
                                create_lqm = False
                                update_lqm = False
                                if item["conf"]['packet_loss'] != loss:
                                    item["conf"]['packet_loss'] = loss
                                    update_lqm = True
                                if item["conf"]['latency'] != latency:
                                    item["conf"]['latency'] = latency
                                    update_lqm = True
                                if item["conf"]['jitter'] != jitter:
                                    item["conf"]['jitter'] = app_check['jitter']
                                    item["conf"]['jitter_en'] = jitter
                                    update_lqm = True
                                if update_lqm:
                                    resp = cgx.put.element_extensions(site_id = site["id"], element_id = element["id"], extension_id=item['id'], data=item)
                                    if not resp:
                                        print ("Error updating LQM All Apps on site " + site['name'] + " ION " + element['name'])
                                    else:
                                        print ("Updating LQM All Apps on site " + site['name'] + " ION " + element['name'])
                                else:
                                    print ("LQM All Apps already created on site " + site['name'] + " ION " + element['name'])
                        if create_lqm:
                            data = {"name": "All-Apps", "namespace": "thresholds/lqm/app/all", "entity_id": None, "disabled": False, "conf": {"latency": latency, "latency_en": True, "jitter": jitter, "jitter_en": True, "packet_loss": loss, "packet_loss_en": True}}
                            resp = cgx.post.element_extensions(site_id = site["id"], element_id = element["id"], data=data)
                            if not resp:
                                print ("Error creating LQM All Apps on site " + site['name'] + " ION " + element['name'])
                                print (str(jdout(resp)))
                            else:
                                print ("Creating LQM All Apps on site " + site['name'] + " ION " + element['name'])
                        
def destroy(cgx):
    for site in cgx.get.sites().cgx_content["items"]:
        site_check = True
        if site["element_cluster_role"] != "SPOKE":
            site_check = False
        if site_check:
            for element in cgx.get.elements().cgx_content["items"]:
                if element["site_id"] == site["id"]:
                    for item in cgx.get.element_extensions(site_id = site["id"], element_id = element["id"]).cgx_content["items"]:
                        if item["name"] == "All-Apps":
                            resp = cgx.delete.element_extensions(site_id = site["id"], element_id = element["id"], extension_id=item['id'])
                            if not resp:
                                print ("Error deleteing LQM All Apps on site " + site['name'] + " ION " + element['name'] + '. Download log for details..')
                                print (str(jdout(resp)))
                            else:
                                print ("Deleting LQM All App on site " + site['name'] + " ION " + element['name'])
                                      
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))
    
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
    config_group.add_argument('--latency_value', '-latency', help='Latency value".', required=False, default=None)
    config_group.add_argument('--loss_value', '-loss', help='Loss value".', required=False, default=None)
    config_group.add_argument('--jitter_value', '-jitter', help='Jitter value".', required=False, default=None)
    config_group.add_argument('--delete', '-D', help='Delete Apps LQM settings', action='store_true', default=False)

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-DE", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    args = vars(parser.parse_args())
                             
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    
    delete = args['delete']
    latency = args['latency_value']
    loss = args['loss_value']
    jitter = args['jitter_value']
    cgx = cgx_session
    if delete:
        destroy(cgx)
    else:
        if latency == None or loss == None or jitter == None:
            print("Please enter a value for latency, loss and jitter")
        else:
            deploy(cgx, loss, latency, jitter)
    
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()
