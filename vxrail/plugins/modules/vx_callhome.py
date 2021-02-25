#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
author:  Dell EMC VxRail Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
module: vx_callhome
short_description: This module is used to deploy the Dell EMC Call Home configuration system and optionally establish the configuraiton with teh Dell EMC support Center

description: The module reliease upon the VxRail callhome API to obtain the current status, as well as perform the configuration of vxRail Call Home, sometimes referred to as ESRS for the VxRail Cluster.
dependencies:
 - VxRail Manager has been deployed and is in good health
 - DNS settings have been applied for the new node host name and IP IPv4Address
 - Network configuration has been performed to support the additional network space required for the nodes.
 - Customer Site ID has been established in Dell EMC support 
 - Routing beteen the call home system and the Dell EMC support site has been confirmed. 

options:

    name:
        description:
           - Name of the module. User defined name
        type: str
        required: false
    vcadmin:
        description:
            - The vcenter administrative user account defined to VxRail Manager
        type: str
        required: true
    vcpasswd:
        description:
            - The vcenter administrator password defined to VxRail Manager
        type: str
        required: true
    ip:
        description:
            - VxRail Manager IP address.
        type: str
        required: true
    root_passwd:
        description:
            - The root password which will be assigned to the ESRS virtual machine.
        type: str
        required: true
    company:
        description:
            - Company name associated with site ID.
        type: str
        required: true
    email:
        description:
            - email account or alias associated with the primary customer contact.
        type: str
        required: true
    phone:
        description:
            - Phone number for support contact.
        type: str
        required: true
    siteid:
        description:
            - The customer site id for this VxRail Cluster. There may be multiple sites associated with a customer. This must be the site ID for this cluster.
        type: str
        required: true
    first_name:
        description:
            - First Name of Customer Contact.
        type: str
        required: true
    last_name:
        description:
            - Last Name of Customer Contact.
        type: str
        required: true
    timeout:
        description:
            - The timeout value, in milliseconds, assigned to the REST URL request. Default value is 10.
        type: int
        required: false

version_added: "2.9"

'''
EXAMPLES = """
    - name: collect cluster network address usage
      vx_callhome:
        vcadmin: "{{ vcadmin }}"
        vcpasswd: "{{ vcpasswd}}"
        ip: "{{ vxm_ip }}"
        "company": "Dell PARTNER",
        "email": "admin@dellpartner.com",
        "first_name": "Support Manager",
        "last_name": "emc",
        "ip": "10.62.83.114",
        "phone": "508-435-1000",
        "root_passwd": "password123!",
        "site_id": 12345678

    register: output

   - debug:
     msg: "{{ output }}"
"""

RETURN = """
"""

import json
import logging
import requests
import chardet
import urllib3
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
    ''' Logging class for method '''
    info_fmt = "%(asctime)s [%(levelname)s]\t%(message)s"
    debug_fmt = "%(asctime)s [%(levelname)s]\t%(pathname)s:%(lineno)d\t%(message)s"

    def __init__(self, fmt="%(asctime)s [%(levelname)s]\t%(pathname)s:%(lineno)d\t%(message)s"):
        logging.Formatter.__init__(self, fmt)

    def format(self, record):
        if record.levelno == logging.INFO:
            self._fmt = CustomLogFormatter.info_fmt
            # python 3 compatibility
            if hasattr(self, '_style'):
                self._style._fmt = CustomLogFormatter.info_fmt
        else:
            self._fmt = CustomLogFormatter.debug_fmt
            # python 3 compatibility
            if hasattr(self, '_style'):
                self._style._fmt = CustomLogFormatter.debug_fmt
        result = logging.Formatter.format(self, record)
        return result

def byte_to_json(body):
    ''' conversion of http content to json format '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))

# Configurations
LOG_FILE_NAME = "esrs.log"
LOG_FORMAT = CustomLogFormatter()

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# file output
FILE_HANDLER = logging.FileHandler(LOG_FILE_NAME)
FILE_HANDLER.setLevel(logging.DEBUG)
FILE_HANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILE_HANDLER)

class ExpansionUrls():
    ''' vxrail Map api to python method '''
    esrs_info_tpl = 'https://{}/rest/vxm/v1/callhome/info'
    esrs_mode_tpl = 'https://{}/rest/vxm/v1/callhome/mode'
    esrs_deploy_tpl = 'https://{}/rest/vxm/v1/callhome/deployment'
    node_url_tpl = 'https://{}/rest/vxm/v1/hosts/{}'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def esrs_info(self):
        ''' get call home config info '''
        return ExpansionUrls.esrs_info_tpl.format(self.vxm_ip)

    def esrs_deploy(self):
        ''' deploy esrs tasks  '''
        return ExpansionUrls.esrs_deploy_tpl.format(self.vxm_ip)

    def esrs_mode(self):
        ''' get current mode '''
        return ExpansionUrls.esrs_mode_tpl.format(self.vxm_ip)

class vxrail():
    ''' Main Class for module execution '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.root_passwd = module.params.get('root_passwd')
        self.company = module.params.get('company')
        self.email = module.params.get('email')
        self.phone = module.params.get('phone')
        self.siteid = module.params.get('siteid')
        self.fname = module.params.get('first_name')
        self.last_name = module.params.get('last_name')
        self.ip = module.params.get('esrs_ip')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def get_esrs_info(self):
        ''' check the current esrs mode and settings '''
        try:
            response = requests.get(url=self.expansion_urls.esrs_info(),
                                    verify=False,
                                    auth=(self.vcadmin, self.vcpasswd),
                                    )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to vxrail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to vxrail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 200 or 404:
            data = byte_to_json(response.content)
            LOGGER.info(data)
            return data
        else:
            status = "Call Home not configured!"
            LOGGER.info(status)
            return status

    def create_payload(self):
        ''' build esrs deployment payload '''
        payload = {}
        payload['admin_pwd'] = self.vcpasswd
        payload['company'] = self.company
        payload['email'] = self.email
        payload['first_name'] = self.fname
        payload['ip'] = self.ip
        payload['last_name'] = self.last_name
        payload['phone'] = self.phone
        payload['root_pwd'] = self.root_passwd
        payload['site_id'] = self.siteid
        return payload

    def esrs_deployment(self, payload):
        ''' begin the configuration of the esrs service '''
        try:
            response = requests.post(url=self.expansion_urls.esrs_deploy(),
                                     verify=False,
                                     headers={'Content-type': 'application/json'},
                                     auth=(self.vcadmin, self.vcpasswd),
                                     data=json.dumps(payload)
                                     )

            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to vxrail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to vxrail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            return data or "No content in deployment response"
        else:
            LOGGER.error('Request resulted in unexpected result code %d.', response.status_code)
            LOGGER.info(response)
            return "Unexpected response from deployment request"

def main():
    ''' Entry point into execution flow '''
    result = ''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            vcadmin=dict(required=True),
            vcpasswd=dict(required=True, no_log=True),
            ip=dict(required=True),
            company=dict(required=True),
            email=dict(required=True),
            first_name=dict(required=True),
            last_name=dict(required=True),
            esrs_ip=dict(required=True),
            phone=dict(required=True),
            root_passwd=dict(required=True),
            siteid=dict(required=True),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    esrs_status = vxrail().get_esrs_info()
    if esrs_status == 'error':
        module.fail_json(msg="Module could not connect to VxRail Manager")
    LOGGER.info(esrs_status)
    if esrs_status['errorCode'] == 4:
        payload_data = vxrail().create_payload()
        LOGGER.info(payload_data)
        task_id = vxrail().esrs_deployment(payload_data)
        LOGGER.info(task_id)

    vx_facts = {'esrs' : result}
    vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
