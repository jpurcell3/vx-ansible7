#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
Shim module for testing withing CyberArk
author: jeff@dell.com
'''

from ansible.module_utils.basic import AnsibleModule
import os, json

SOCKET_TIMEOUT = 30

def get_user_info(module):
    username = module.params['username']
    vaultfile = "./vars/test.yml"
#    vaultfile = "/root/vars/test.yml"

    accounts = {}

    data = open(vaultfile, 'r')
    for line in data:
        if username in line:
            items = line.rstrip('\n').split(':')
            accounts['username'] = items[0]
            accounts['Content'] = items[1]
    return accounts

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(required=True),
        ),
        supports_check_mode=False
    )

    # Get user information from cyberarc endpoint
    result = get_user_info(module)

    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()
