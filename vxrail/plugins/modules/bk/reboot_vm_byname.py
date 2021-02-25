#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: reboot_vm_byname
short_description: Reboot ESXi/VC VM by Name
requirements: [pyvmomi module]
description:
    -  Reboot VM on ESXi Host or vCenter, if tools not install force reboot
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
    - name: Reboot VM
        reboot_vm_byname:
            vc_fqdn: "xx.xx.xx.xx"
            vc_user: "xxxxxx"
            vc_pwd: "xxxxxxxx"
            vc_vm_name: "xxxxxxx"
'''

RETURN = '''
msg:
    description: The status of the resource
'''
try:
    from ansible.module_utils.basic import AnsibleModule
    from pyVmomi import vim
    from pyVim.connect import SmartConnect, Disconnect
    import ssl, atexit

    HAS_PYVMOMI = True
except ImportError:
   HAS_PYVMOMI = False

def connect_to_vcenter(module, disconnect_atexit=True):
    """
    Connect to ESXi/vCenter 
    """
    hostname = module.params['vc_fqdn']
    username = module.params['vc_user'] 
    password = module.params['vc_pwd']
    port     = module.params['vc_port']
    
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

def _get_obj(module, content, vimtype, name):
    """
    Get the vsphere object associated with a given text name
    """
    obj = None
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        if c.name == name:
            obj = c
            break
    return obj

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            vc_fqdn         = dict(type='str', required=True),
            vc_user         = dict(type='str', required=True),
            vc_pwd          = dict(type='str', required=True, no_log=True),
            vc_port         = dict(type='int', required=False, default=443),
            vc_vm_name      = dict(type='str', required=True)
        ),
        supports_check_mode = False
    )

    if not HAS_PYVMOMI:
        module.fail_json(msg='pyvmomi is required for this module')
    
    vmname = module.params['vc_vm_name']
    content = connect_to_vcenter(module)
    vm = _get_obj(module, content, [vim.VirtualMachine], vmname)

    if vm == None:
        module.fail_json(msg=('No vm found by name %s' % vmname))

    # does the actual vm reboot
    try:
        vm.RebootGuest()
    except:
        # forceably shutoff/on if vmware guestadditions isn't running
        vm.ResetVM_Task()

    module.exit_json(changed=True, msg=("VM '%s' reboot initiated" % vmname))

def main():
    run_module()

if __name__ == '__main__':
    main()
