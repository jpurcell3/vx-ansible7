#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by':  'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: update_vxm_ip
short_description: Update default IP of VXRail Manager VM
requirements: [pyvmomi module]
description:
    - Update default IP of VXRail Manager VM from inside OS
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''

'''

RETURN = '''
msg:
    description: The change status of the resource
'''
try:
   from ansible.module_utils.basic import AnsibleModule
   import ssl, atexit, time
   from pyVmomi import vim, pbm, VmomiSupport
   from pyVim.connect import SmartConnect, Disconnect

   HAS_PYVMOMI = True
except ImportError:
   HAS_PYVMOMI = False

def connect_to_host(module, disconnect_atexit=True):
    hostname = module.params['esx_fqdn']
    username = module.params['esx_user']
    password = module.params['esx_pwd']
    port     = module.params['esx_port']

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


def run_command(module, content, cmd_path, cmd_arguments, vm, creds):
    try:
        cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(arguments=cmd_arguments, programPath=cmd_path)
        cmdpid = content.guestOperationsManager.processManager.StartProgramInGuest(vm=vm, auth=creds, spec=cmdspec)

        return cmdpid

    except:
	error = {}
	error['vm'] = vm.name
	error['cmd'] = cmd_path
	error['arguments'] = cmd_arguments
	errors['error'] = sys.exc_info()[0]
        module.fail_json(msg=errors)

def get_process(module, content, vm, creds, pid):
    try:
        processes = content.guestOperationsManager.processManager.ListProcessesInGuest(vm=vm, auth=creds,  pids=[pid])
        return processes

    except:
        module.fail_json(msg='Error> %s' % sys.exc_info()[0])

def get_vxm_vm(module, content, vmname):
    vm = None
    try:
        # Get a view ref to all VirtualMachines
        view_ref = content.viewManager.CreateContainerView(container=content.rootFolder, type=[vim.VirtualMachine], recursive=True)

        for childvm in  view_ref.view:
            if childvm.name == vmname:
                vm = childvm
                break
        if vm == None:
            module.fail_json(msg='No VM found with name %s on ESXi Host' % vmname)
    except:
        module.fail_json(msg='get_vxm_vm Error: %s' % sys.exc_info()[0])

    return vm

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            esx_fqdn      = dict(type='str', required=True),
            esx_user      = dict(type='str', required=True),
            esx_pwd       = dict(type='str', required=True, no_log=True),
	        esx_port      = dict(type='int', required=False, default=443),
            vmusername    = dict(type='str', required=True),
            vmpassword    = dict(type='str', required=True, no_log=True),
            vmip          = dict(type='str', required=True),
            vmsubnet      = dict(type='str', required=True),
            vmgateway     = dict(type='str', required=True)
        ),
        supports_check_mode = False
    )

    if not HAS_PYVMOMI:
        module.fail_json(msg='pyvmomi is required for this module')

    creds = vim.vm.guest.NamePasswordAuthentication(username=module.params['vmusername'], password=module.params['vmpassword'])

    # Connect to ESXi
    content = connect_to_host(module)
    # Get VXM VM
    vm = get_vxm_vm(module, content, 'VxRail Manager')

    # Stop Services, Update IP, Restart Service
    pid = run_command(module, content, '/usr/bin/systemctl', 'stop vmware-marvin', vm, creds)
    time.sleep(5)
    pid = run_command(module, content, '/opt/vmware/share/vami/vami_set_network', ('eth0 STATICV4 %s %s %s' % (module.params['vmip'], module.params['vmsubnet'], module.params['vmgateway'])), vm, creds)
    pid = run_command(module, content, '/usr/bin/systemctl', 'start vmware-marvin', vm, creds)
    time.sleep(5)
    pid = run_command(module, content, '/usr/bin/systemctl', 'restart vmware-loudmouth', vm, creds)

    module.exit_json(changed=True, msg="IP Updated on VM")


def main():
    run_module()

if __name__ == '__main__':
    main()
