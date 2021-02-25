#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: idrac_get_os_ip_info
short_description: Get Host OS IP Informations
requirements: iDRAC package/Vib need to be installed on OS 
description:
    -  Get Host OS IP Informations
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
---
- name: get os network info from iDRAC
  idrac_get_os_ip_info:
    idrac_ip:   "{{ idrac_ip }}"
    idrac_user: "{{ idrac_user }}"
    idrac_password: "{{ idrac_password }}"
    vmk_interface: "{{ vmk_interface }}"
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

def get_os_ip_info(module, idrac_cookie, idrac_token):
    vmk_interface = None
    if module.params['vmk_interface']:
        vmk_interface = module.params['vmk_interface']
    interfaces = {}
    method = 'GET'
    endpoint = module.params['idrac_ip']
    url = 'https://' + endpoint + '/sysmgmt/2013/os/network/interfaces'
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
    
    NWInterfaces = response_json['NWInterfaces']
    #result['keys'] = response_json['NWInterfaces'].keys()
    for interface in NWInterfaces.keys():
        if len(NWInterfaces[interface]['ipv4_addresses']) > 0:
            interfaces[interface] = NWInterfaces[interface]['ipv4_addresses'][0]['address']

    if vmk_interface != None and (vmk_interface in interfaces):
        return  interfaces, interfaces[vmk_interface]
    else:
        return  interfaces, None

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            idrac_ip             = dict(required=True),
            idrac_user           = dict(required=True),
            idrac_password       = dict(required=True, no_log=True),
            vmk_interface        = dict(required=False),
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

    # Make the REST call to get network information
    interfaces, mgmt_ip = get_os_ip_info(module, idrac_cookie, idrac_token) 
    result['interfaces'] = interfaces
    result['mgmt_ip'] = mgmt_ip
    
    # logout iDRAC Session
    idrac_logout(module, idrac_cookie, idrac_token)
    
    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()

