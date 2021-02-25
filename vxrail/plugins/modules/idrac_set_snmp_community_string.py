#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: idrac_set_snmp_community_string
short_description: Set Community name string on SNMP alert settings under System Settings > SNMP Settings
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
---
- name: get os network info from iDRAC
  idrac_set_snmp_community_string:
    idrac_ip:   "{{ idrac_ip }}"
    idrac_user: "{{ idrac_user }}"
    idrac_password: "{{ idrac_password }}"
    community_string: "{{ community_string }}"
  register: result
'''

RETURN = '''
msg:
    description: The status of the resource
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.idrac_session import idrac_login, idrac_logout
from urllib3.exceptions import InsecureRequestWarning
import json, requests

SOCKET_TIMEOUT = 30

def set_snmp_string(module, idrac_cookie, idrac_token):
    community_string =  module.params['community_string']
    method = 'PUT'
    endpoint = module.params['idrac_ip']
    url = 'https://' + endpoint + '/sysmgmt/2012/server/configgroup/iDRAC.IPMILAN'
    headers = {
        'Content-Type':'application/json',
        'Accept':'application/json',
        'XSRF-TOKEN': idrac_token,
        'Cookie': idrac_cookie
    }
    body =  { "iDRAC.IPMILan": { "CommunityName": community_string } }
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    response = requests.put(url, data=json.dumps(body), headers=headers, verify=False)

    if response.status_code != 200:
        idrac_logout(module, idrac_cookie, idrac_token)
        module.fail_json(msg="Failed to set SNMP community string", info=response.text)
    
    return response

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            idrac_ip             = dict(required=True),
            idrac_user           = dict(required=True),
            idrac_password       = dict(required=True, no_log=True),
            community_string     = dict(required=True),
            validate_certs       = dict(required=False, type="bool", default=False)
        ),
        supports_check_mode = False
    )
    
    result = {}
    
    # Get iDRAC token
    login_info = idrac_login(module)

    if login_info['status'] != 201:
        module.fail_json(msg="Failed to get iDRAC token", info=login_info)

    idrac_cookie = login_info['set-cookie']
    idrac_token = login_info['xsrf-token']

    response = set_snmp_string(module, idrac_cookie, idrac_token)
    result['status_code'] = response.status_code
    result['info'] = response.text
    result['changed'] = True
    result['status'] = "SNMP Community string updated to %s" % module.params['community_string']

    # logout iDRAC Session
    idrac_logout(module, idrac_cookie, idrac_token)
    
    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()

