# Prisma SD-WAN LQM All Apps (Preview)
The purpose of this script to set the LQM thresholds (loss, latency and jitter) for all apps. 

#### Features
 - ./lqm.py can be used to set or delete the LQM thresholds (loss, latency and jitter)

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 - Create All-Apps LQM thresholds 
 1. ./lqm.py -latency 250 -loss 5 -jitter 50
 
 - Update All-Apps LQM thresholds 
 2. ./lqm.py -latency 250 -loss 5 -jitter 50
 
 - Delete All-Apps LQM Extension 
 3. ./lqm.py -D
 
 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
