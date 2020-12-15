#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'vxansible@dell.com'
}

DOCUMENTATION = '''
---
module: vxrail_switch_mtu_change
requirements: [pyvmomi module]
description:
    - Change vDS Switch MTU on VXRAIL VC
author: 
supported_by: 
    
'''

EXAMPLES = '''
---
'''

RETURN = '''
    results:
        description: Change results
'''

try:
    from pyVmomi import vim, vmodl
    from pyVim.connect import SmartConnect, Disconnect
    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import (vmware_argument_spec, wait_for_task)
import ssl, atexit, requests

def connect_to_vcenter(module, disconnect_atexit=True):
    hostname = module.params['vcenter']
    username = module.params['vcadmin'] 
    password = module.params['vcpasswd']
    port     = module.params['port']
    
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        service_instance = SmartConnect(
            host=hostname,
            user=username,
            pwd=password,
            port=port
        )

        if disconnect_atexit:
            atexit.register(Disconnect, service_instance)

        return service_instance.RetrieveContent()
    except vim.fault.InvalidLogin as invalid_login:
        module.fail_json(msg=invalid_login.msg, apierror=str(invalid_login))
    except requests.ConnectionError as connection_error:
        module.fail_json(msg="Unable to connect to vCenter or ESXi API on TCP/443.", apierror=str(connection_error))

def get_all_objects(content, vimtype):
    obj = []
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for managed_object_ref in container.view:
        obj.append(managed_object_ref)
    return obj
    

def update_dvs_mtu(module, dvs, mtu):
    spec = vim.dvs.VmwareDistributedVirtualSwitch.ConfigSpec()
    spec.configVersion = dvs.config.configVersion
    spec.maxMtu = mtu
    task = dvs.ReconfigureDvs_Task(spec)
    changed, result = wait_for_task(task)

    return changed, result

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            vcenter   = dict(type='str', required=True),
            vcadmin   = dict(type='str', required=True),
            vcpasswd    = dict(type='str', required=True, no_log=True),
            port   = dict(type='int', required=False, default='443'),
            mtu       = dict(type='int', required=True)
        ),
        supports_check_mode = False
    )

    if not HAS_PYVMOMI:
        module.fail_json(msg='pyvmomi is required for this module')

    changed = False
    mtu = module.params['mtu']

    # Get DV Switch Switches            
    content = connect_to_vcenter(module)
    dv_switches = get_all_objects(content, [vim.dvs.VmwareDistributedVirtualSwitch])

    if (len(dv_switches) == 0): 
        module.fail_json(msg='No DV Switch found on vCenter')
    elif (len(dv_switches) >= 1):
        dv_switch = dv_switches[0]

    changed, result = update_dvs_mtu(module, dv_switch, mtu)

    if (changed != True):
        module.fail_json(msg='Fail to change mtu to %s on switch %s' % (mtu, dv_switch.name))
    
    module.exit_json(changed=changed, result=result)

def main():
    run_module()

if __name__ == '__main__':
    main()
