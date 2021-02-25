#!/usr/bin/python
import logging
import ssl
import atexit
import uuid
import time
import requests


ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: update_vxm_ip
short_description: Change Portgroup type to ephemeral
requirements: [pyvmomi module]
description:
    - Change a distributed port group type to ephemeral,
      move any host vnic to temp protgroup then move back after change
author:
supported_by:
    
'''

EXAMPLES = '''
---
- name: Change vxRail VC management portgroup to ephemeral
vxrail_mgmt_portgroup_change:
    vc_fqdn: {{  vc_fqdn }}
    vc_user: {{ vc_user }}
    vc_pwd: {{ vc_pwd }}
    vmk_device: 'vmk0'
    mgmt_portgroup_name: 'Management'
register: results
'''

RETURN = '''
    results:
        description: Change results
'''

try:
    from pyVmomi import vim, vmodl
    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import (vmware_argument_spec, wait_for_task)
from pyVim.connect import SmartConnect, Disconnect


class CustomLogFormatter(logging.Formatter):
    ''' Class for generating log output of this module'''
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



# Configurations
LOG_FILE_NAME = "/tmp/vx-change_pg.log"
TMP_RETRY_FILE = "tmp_retry_id" # TBD
LOG_FORMAT = CustomLogFormatter()

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# file output
FILEHANDLER = logging.FileHandler(LOG_FILE_NAME)
FILEHANDLER.setLevel(logging.DEBUG)
FILEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILEHANDLER)

def connect_to_vcenter(module, disconnect_atexit=True):
    hostname = module.params['vc_fqdn']
    username = module.params['vc_user']
    password = module.params['vc_pwd']
    port = module.params['vc_port']

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

def find_dvpg_by_name(dv_switch, portgroup_name):
    portgroups = dv_switch.portgroup
    for pg in portgroups:
        if portgroup_name in pg.name:
            return pg

    return None

def create_host_vnic_config(dv_switch_uuid, portgroup_key, device):
    host_vnic_config = vim.host.VirtualNic.Config()
    host_vnic_config.spec = vim.host.VirtualNic.Specification()

    host_vnic_config.changeOperation = "edit"
    host_vnic_config.device = device
    host_vnic_config.portgroup = ""
    host_vnic_config.spec.distributedVirtualPort = vim.dvs.PortConnection()
    host_vnic_config.spec.distributedVirtualPort.switchUuid = dv_switch_uuid
    host_vnic_config.spec.distributedVirtualPort.portgroupKey = portgroup_key

    return host_vnic_config

def create_vds_portgroup(dv_switch, pg_name, vlanId):
    config = vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
    config.defaultPortConfig = vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy()
    config.defaultPortConfig.vlan = vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec()
    config.name = pg_name
    config.type = vim.dvs.DistributedVirtualPortgroup.PortgroupType.ephemeral
    config.defaultPortConfig.vlan.vlanId = vlanId
    task = dv_switch.AddDVPortgroup_Task([config])
    changed, result = wait_for_task(task)
    portgroup = find_dvpg_by_name(dv_switch, pg_name)

    return portgroup

def check_vmk_current_state(content, host_system, device, portgroup_key):
    for vnic in host_system.configManager.networkSystem.networkInfo.vnic:
        if vnic.device == device:
            if vnic.spec.distributedVirtualPort.portgroupKey == portgroup_key:
                return True

    return False

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            vc_fqdn=dict(required=True),
            vc_user=dict(required=True),
            vc_pwd=dict(required=True, no_log=True),
            vc_port=dict(required=False, default='443'),
            vmk_device=dict(required=True),
            mgmt_portgroup_name=dict(required=False, default='Management'),
            dv_switch_name=dict(required=False, default=None)
        ),
        supports_check_mode=False
    )

    if not HAS_PYVMOMI:
        module.fail_json(msg='pyvmomi is required for this module')

    temp_uuid = str(uuid.uuid4())
    temp_portgroup_name = 'MGMT-' + temp_uuid
    mgmt_portgroup = None
    temp_portgroup = None
    results = ''
    move_errors = None
    changed = False
    dv_switch_name = module.params['dv_switch_name']
    mgmt_portgroup_name = module.params['mgmt_portgroup_name']
    device = module.params['vmk_device']

    # Get DV Switch Switches
    content = connect_to_vcenter(module)
    dv_switches = get_all_objects(content, [vim.dvs.VmwareDistributedVirtualSwitch])

    if len(dv_switches) == 0:
        module.fail_json(msg='No DV Switch found')
    elif len(dv_switches) > 1:
        if dv_switch_name == None:
            module.fail_json(msg='More than 1 switch found and no switch name provided')
        else:
            for vds in dv_switches:
                if vds.name == dv_switch_name:
                    dv_switch = vds
                    break

                if dv_switch == None:
                    module.fail_json(msg=('No switch found with name %s ' %  dv_switch_name))
    else:
        dv_switch = dv_switches[0]

    # Find MGMT portgroup
    mgmt_portgroup = find_dvpg_by_name(dv_switch, mgmt_portgroup_name)

    if mgmt_portgroup == None:
        module.fail_json(msg=('Managemt Portgroup by name %s not found' % mgmt_portgroup_name))
    elif mgmt_portgroup.config.type == 'ephemeral':
        results += ('Portgroup %s is already ephemeral, ' % mgmt_portgroup.name)

    # Get all hosts
    esxi_hosts = get_all_objects(content, [vim.HostSystem])

    # Verify port group is not set ephemeral
    if mgmt_portgroup.config.type != 'ephemeral':
        # Create temp Portgroup
        temp_portgroup = create_vds_portgroup(dv_switch, temp_portgroup_name,
                                              mgmt_portgroup.config.defaultPortConfig.vlan.vlanId)

        if temp_portgroup == None:
            module.fail_json(msg=('Fail to create temp portgroup %s ' % temp_portgroup_name))

        config = vim.host.NetworkConfig()
        config.vnic = [create_host_vnic_config(dv_switch.uuid, temp_portgroup.key, device)]

        for esxi_host in esxi_hosts:
            # Check if vmk is on mgmt portgroup and need move
            vnic_need_move = check_vmk_current_state(content, esxi_host, device, mgmt_portgroup.key)
            LOGGER.info(vnic_need_move)
            if vnic_need_move == True:
                # Move the vmk to temp portgroup
                try:
                    host_network_system = esxi_host.configManager.networkSystem
                    host_network_system.UpdateNetworkConfig(config, "modify")
                    results += ("Host %s vNIC moved, " % esxi_host.name)
                    time.sleep(5)
                except:
                    module.fail_json(msg=("Host %s vNIC failed to move" % esxi_host.name))


        # Change Mgmt port type to ephemeral
        spec = vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
        spec.configVersion = mgmt_portgroup.config.configVersion
        spec.type = vim.dvs.DistributedVirtualPortgroup.PortgroupType.ephemeral
        task = mgmt_portgroup.ReconfigureDVPortgroup_Task(spec)
        changed, result = wait_for_task(task)
        time.sleep(5)
        if changed == True:
            results += ("%s Portgroup changed to ephemeral, " % mgmt_portgroup.name)
        else:
            module.fail_json(msg='Fail to change portgroup type to ephemeral')

    # Move all ports back to MGMT portgroup
    config = vim.host.NetworkConfig()
    config.vnic = [create_host_vnic_config(dv_switch.uuid, mgmt_portgroup.key, device)]

    for esxi_host in esxi_hosts:
        # Check if vmk need to move back
        vnic_on_mgmt = check_vmk_current_state(content, esxi_host, device, mgmt_portgroup.key)
        if  vnic_on_mgmt == False:
            try:
                host_network_system = esxi_host.configManager.networkSystem
                host_network_system.UpdateNetworkConfig(config, "modify")
                results += ("Host %s vNIC moved back, " % esxi_host.name)
                time.sleep(5)
            except:
                # verify vNIC moved
                move_errors += ("Host %s vNIC failed to move back, " % esxi_host.name)

    if move_errors != None:
        module.fail_json(msg=move_errors)

    # Delete temp port group
    if temp_portgroup != None:
        task = temp_portgroup.Destroy_Task()
        changed, result = wait_for_task(task)
        if changed == True:
            results += ("Temp portgeoup %s deleted, " % temp_portgroup_name)
        else:
            results += ("Fail to delete temp portgroup %s, please delete from gui" % temp_portgroup_name)

    module.exit_json(changed=changed, result=results)

def main():
    run_module()

if __name__ == '__main__':
    main()
