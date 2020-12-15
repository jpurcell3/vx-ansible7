#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: idrac_system_power
short_description: Change system power state
requirements: 
description:
    -  Power on, off, shutdown or reboot system using iDRAC
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
---
- name: Power On System
  idrac_system_power:
    idrac_ip:   "{{ idrac_ip }}"
    idrac_user: "{{ idrac_user }}"
    idrac_password:  "{{ idrac_password }}"
    power_state: "ON"
  register: result
  delegate_to: localhost
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

def get_system_state(module, idrac_cookie, idrac_token):
    method = 'GET'
    endpoint = module.params['idrac_ip']
    url = 'https://' + endpoint + '/sysmgmt/2015/server/power'
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
        module.fail_json(msg="Failed to system power status", info=info)

    response_content = response.read()
    response_json = json.loads(response_content)
    current_state = response_json['powerState']
    return current_state

def change_system_state(module, power_state, idrac_cookie, idrac_token):
    # Make the REST call to set Power State of system
    method = 'PUT'
    endpoint = module.params['idrac_ip']
    url = 'https://' + endpoint + '/sysmgmt/2015/server/power?action=' + power_state
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
        module.fail_json(msg="Failed to change system state to %s " % power_state, info=info)

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            idrac_ip             = dict(required=True),
            idrac_user           = dict(required=True),
            idrac_password       = dict(required=True, no_log=True),
            power_state          = dict(required=True),
            validate_certs       = dict(required=False, type="bool", default=False)
        ),
        supports_check_mode = False
    )

    result = {}
    
    endpoint = module.params['idrac_ip']
    
    if module.params['power_state'].lower() == "on":
        power_state = "ForceOn"
    elif module.params['power_state'].lower() == "off":
        power_state = "ForceOff"
    elif module.params['power_state'].lower() == "reboot":
        power_state = "ForceRestart"
    elif module.params['power_state'].lower() == "shutdown":
        power_state = "PushPowerButton"
    else:
        module.fail_json(msg="Unkown Power State %s" % module.params['power_state'])
        
    # Make the REST call to get token
    login_info = idrac_login(module)

    if login_info['status'] != 201:
        module.fail_json(msg="Failed to get iDRAC token", info=login_info)

    idrac_cookie = login_info['set-cookie']
    idrac_token = login_info['xsrf-token']

    # Get current state of system
    current_state = get_system_state(module, idrac_cookie, idrac_token)
    
    perform_action = True

    if current_state.lower() == "off" and (power_state == "ForceOff" or power_state == "ForceRestart" or power_state == "PushPowerButton"):
        perform_action = False
        message = "System already powerd off"
    elif current_state.lower() == "on" and power_state == "ForceOn":
        perform_action = False
        message = "System already powerd On"

    if perform_action:
        # Set Power State of system
        change_system_state(module, power_state, idrac_cookie, idrac_token)
        message = "System power state changed to %s" % module.params['power_state']
        
    result['changed'] = perform_action
    result['status'] = message

    # logout iDRAC Session
    idrac_logout(module, idrac_cookie, idrac_token)
    
    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()