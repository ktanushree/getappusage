# Prisma SDWAN Get App Usage
This utility is used to download application usage across policies in the Prisma SDWAN Controller.

#### Synopsis
This script can be used to understand all the policy sets (Security, Policies Original, Path Stack, QoS Stack, NAT Stack) and the corresponding rules 
where the application is referenced. 

The script retrieves both explicit usage and implicit catch-all references. The CSV data lists the type of reference using the following types:
- **catchall-None**: This is an implicit reference to the application by using *None* in app_id filter in the rule
- **catchall-any**: This is an implicit reference to the application by using *any* in app_id filter in the rule
- **explicit-appid**: This is an explicit reference to the application by using the application ID in the app_id filter in the rule

#### Requirements
* Active CloudGenix Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.5.3b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getappusage.py`. 

### Examples of usage:
Get App Usage for a single App:
```
./getappusage.py -A WebEx 
```
Get App Usage for a single App only for policies bound to sites
``` 
./getappusage.py -A WebEx -DT BOUND
```
Get App Usage for a single App for ALL policies
```angular2
./getappusage.py -A WebEx -DT ALL
```
Get App Usage for all Apps only for policies bound to sites
```angular2
./getappusage.py -A ALL_APPS -DT BOUND
```
Get App Usage for all Apps only for all policies
```angular2
./getappusage.py -A ALL_APPS -DT ALL
```

Help Text:
```angular2
TanushreePro:getappusage tanushreekamath$ ./getappusage.py -h
usage: getappusage.py [-h] [--controller CONTROLLER] [--email EMAIL]
                      [--pass PASS] [--appname APPNAME] [--datatype DATATYPE]

Prisma SDWAN: Get App Usage.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod:
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

App Specific Information:
  Information shared here will be used to get details about the policy sets
  & its associated sites

  --appname APPNAME, -A APPNAME
                        Name of the App or use the special keyword ALL_APPS
  --datatype DATATYPE, -DT DATATYPE
                        Get data for policies bound to sites or all policies.
                        Pick from: ALL, BOUND
TanushreePro:getappusage tanushreekamath$ 
```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SDWAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan.html>
