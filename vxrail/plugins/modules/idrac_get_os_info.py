#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: idrac_get_os_ip_info
short_description: Get Host OS Informations
requirements: iDRAC package/Vib need to be installed on OS 
description:
    -  Get Host OS Informations
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
---
- name: get os info from iDRAC
  idrac_get_os_info:
    idrac_ip:   "{{ idrac_ip }}"
    idrac_user: "{{ idrac_user }}"
    idrac_password: "{{ idrac_password }}"
  register: result
'''

RETURN = '''
msg:
    description: The status of the resource
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec
from ansible.module_utils.idrac_session import idrac_login, idrac_logout
import json

SOCKET_TIMEOUT = 30

def get_network_info(module, idrac_cookie, idrac_token):
    os_info = {}
    method = 'GET'
    endpoint = module.params['idrac_ip']
    url = 'https://' + endpoint + '/sysmgmt/2012/server/configgroup/System.ServerOS'
    headers = {
        'content-type': 'application/json',
        'XSRF-TOKEN': idrac_token,
        'Cookie': idrac_cookie
    }

    response, info = fetch_url(module,
                                url,
                                data={},
                                headers=headers,
                                method=method,
                                timeout=SOCKET_TIMEOUT)

    if info['status'] != 200:
        idrac_logout(module, idrac_cookie, idrac_token)
        module.fail_json(msg="Failed to get os network info from idrac ", info=info)

    try:
        response_content = response.read()
        response_json = json.loads(response_content)
    
    except Exception as e:
        idrac_logout(module, idrac_cookie, idrac_token)
        module.fail_json(msg="Failed to get os network info from idrac", info=info, error=e)
    
    if response_json['System.ServerOS'] != None and response_json['System.ServerOS'] != "": 
        os_info['HostName'] = response_json['System.ServerOS']['HostName']
        os_info['OSName'] = response_json['System.ServerOS']['OSName']
        os_info['OSVersion'] = response_json['System.ServerOS']['OSVersion']
        return os_info
    else:
        return None

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            idrac_ip             = dict(required=True),
            idrac_user           = dict(required=True),
            idrac_password       = dict(required=True, no_log=True),
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

    # Get network information
    os_info = get_network_info(module, idrac_cookie, idrac_token)
    result['os_info'] = os_info

    # logout iDRAC Session
    idrac_logout(module, idrac_cookie, idrac_token)
    
    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()

