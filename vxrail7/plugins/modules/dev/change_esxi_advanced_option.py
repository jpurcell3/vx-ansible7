#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: change_esxi_option
short_description: Change primary node option value.
description: This module is for change primary node esxi advamce option value.
requirements:
    - python >= 2.6
    - PyVmomi
    - Executed on VxRail Manager. After all nodes discovered. Run script as root.
'''

EXAMPLES = '''
---

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
import sys
import os
import json
import requests
from requests.exceptions import HTTPError
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
import chardet
import subprocess
from datetime import datetime

sys.path.append('/usr/lib/vmware-marvin/marvind/webapps/ROOT/WEB-INF/classes/scripts/lib/python2.7/site-packages')

from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect

LOG_PATH = '/tmp/' + os.path.splitext(os.path.basename(__file__))[0] + '.log'
LOG_MESSAGE = ''
SSHPASS_BIN = '/usr/bin/sshpass'
LOUDMOUTH_QUERY = '/usr/lib/vmware-loudmouth/bin/loudmouthc query'
VXM_IPV6_INTERFACE = 'eth1'
SSH_SERVICE = 'TSM-SSH'
DEFAULT_USERNAME = 'root'
DEFAULT_PASSWORD = ''


class ExpansionUrls():
    ''' Class performs mapping of VxRail APIs and class methods called within the module '''
    nodes_tpl = 'https://{}/rest/vxm/private/system/initialize/nodes'

    def __init__(self, vxm_ip):
        '''init method'''
        self.vxm_ip = vxmIP

    def getall_nodes(self):
        '''return the current vcenter configuration settings'''
        return ExpansionUrls.nodes_tpl.format(self.vxm_ip)

def byte_to_json(body):
    ''' method to convert http content to json  '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))

def info(message):
    global LOG_MESSAGE
    _message = str(datetime.now()) + "[INFO\t] " + message
    LOG_MESSAGE = LOG_MESSAGE + _message + ", "
    with open(LOG_PATH, 'a') as f:
        f.write(_message + "\n")

def error(message):
    global LOG_MESSAGE
    _message = str(datetime.now()) + "[ERROR\t] " + message
    LOG_MESSAGE = LOG_MESSAGE + _message + ", "
    with open(LOG_PATH, 'a') as f:
        f.write(_message + "\n")

def warn(message):
    global LOG_MESSAGE
    _message = str(datetime.now()) + "[WARN\t] " + message
    LOG_MESSAGE = LOG_MESSAGE + _message + ", "
    with open(LOG_PATH, 'a') as f:
        f.write(_message + "\n")

def _exit(message, rc):
    global LOG_MESSAGE
    _message = str(datetime.now()) + "[EXIT\t] " + "rc: " + str(rc) + " exit message: " + message
    LOG_MESSAGE = LOG_MESSAGE + _message + ", "
    with open(LOG_PATH, 'a') as f:
        f.write(_message + "\n")

def retrieve_host_service_instance(module, host, username, password):
    try:
        service_instance = SmartConnect(host=host, user=username, pwd=password)
    except:
        error("Retrieve host {} service instance failed".format(host))
        module.fail_json(msg="Retrieve host {} service instance failed".format(host))

    return service_instance

def _change_advanced_option(module, host, optionKey, optionValue, password):
    service_instance = retrieve_host_service_instance(module, host, DEFAULT_USERNAME, password)
    service_content = service_instance.RetrieveContent()
    if service_content == None:
        error("Failed to retrieve service content of host {}".format(host))
        module.fail_json(msg="Failed to retrieve service content of host {}".format(host))
    change_advanced_option(module, service_content, optionKey, optionValue)
    Disconnect(service_instance)


def execute_local_command(command):
    info("Execute command locally: {cmd}".format(cmd=command))

    sub_popen = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = sub_popen.communicate()
    if sub_popen.returncode > 0:
        error("Error encountered when execute command locally - Command:{command}".format(command=command))
        error("Code {0} - {1}".format(sub_popen.returncode, err))
        output = err
    return sub_popen.returncode, output


def execute_remote_command(command, host, username, password):
    print(password)
    remote_exec_command = "{sshpass} -p {password} ssh {username}@{host} -t \'{command}\'".format(SSHPASS_BIN, password, username, host, command)
    rc, output = execute_local_command(remote_exec_command)
    return rc, output


""" Before first run """
def retrieve_host_ipv6_addr(vxmIP):
    ipv6_addr_list = []
    node_tpl = 'https://{}/rest/vxm/private/system/initialize/nodes'
    node_url = nodes_tpl.format(vxmIP)
    info(node_url)
    try:
        response = requests.get(url=node_url,
                                  verify=False,
                                  )
        response.raise_for_status()
    except HTTPError as http_err:
        error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
        return 'error'
    except Exception as api_exception:
        error(' %s Cannot connect to VxRail Manager %s', api_exception, self.vxm_ip)
        return 'error'

    if response.status_code == 200:
        data = byte_to_json(response.content)
    if not data:
        _exit("Failed to retrieve host ips from VxRail manager database", 3)
        module.fail_json(msg="Failed to retrieve host ips from VxRail manager database, exit code 3")
    for i, t in enumerate(data):
        ipv6_address = data[i].get('primary_ip')
        ipv6_address_list.append(ipv6_address)

    return ipv6_addr_list

def retrieve_primary_host_ipv6_addr(vxmIP):
    nodes_tpl = 'https://{}/rest/vxm/private/system/initialize/nodes'
    node_url = nodes_tpl.format(vxmIP)
    info(node_url)
    primary_host_ip = ""
    appliance_id = ""
    try:
        response = requests.get(url=node_url,
                                  verify=False,
                                  )
        response.raise_for_status()

    except Exception as api_exception:
        error('Cannot connect to VxRail Manager')
        return 'error'
    if response.status_code == 200:
        data = byte_to_json(response.content)
        for i, t in enumerate(data):
            if data[i].get('primary') == True:
                primary_host_ip = data[i].get('primary_ip')
                appliance_obj = data[i].get('id')
                appliance_id = appliance_obj.get('appliance_id')

    return appliance_id, primary_host_ip


""" After first run """
def retrieve_host_ipv4_addr(vxmIP):
    nodes_tpl = 'https://{}/rest/vxm/private/system/initialize/nodes'
    node_url = nodes_tpl.format(vxmIP)
    info(node_url)
    ipv4_addr_list = []
    try:
        response = requests.get(url=node_url,
                                  verify=False,
                                  )
        response.raise_for_status()

    except Exception as api_exception:
        error('Cannot connect to VxRail Manager')
        return 'error'
    if response.status_code == 200:
        data = byte_to_json(response.content)
        for i, t in enumerate(data):
            ip4v_addr = data[i].get('ip')
            ipv4_addr_list.append(ipv4.addr)
        return ip4v_addr_list

def change_advanced_option(module, content, optionKey, optionValue):
    try:
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        host = container.view[0]
        optionManager = host.configManager.advancedOption
        option = vim.option.OptionValue(key = optionKey, value = optionValue)
        info("Updating {} on ESXi host {} with value of {}".format(optionKey, host.name, optionValue))
        optionManager.UpdateOptions(changedValue=[option])
        optionValueAfterChange = optionManager.QueryOptions(optionKey)[0].value
        if optionValueAfterChange != optionValue:
            error("Update option {} to {} failed on ESXi host {}".format(optionKey, optionValue, host.name))
            module.fail_json(msg="Update option {} to {} failed on ESXi host {}".format(optionKey, optionValue, host.name))
        info("Update option {} to {} completed on ESXi host {}".format(optionKey, optionValue, host.name))
    except Exception as e:
        error("Failed to update advanced option. Error message: {}".format(str(e)))
        module.fail_json(msg="Failed to update advanced option. Error message: {}".format(str(e)))

# not used
def ipv6_change_advanced_option(appliance_id, ipv6_addr, optionKey, optionValue):
    info("Start change ESXi host {}[{}] advanced option {} to {}".format(appliance_id, ipv6_addr, optionKey, optionValue))
    ssh_ipv6_addr = ipv6_addr + "%" + VXM_IPV6_INTERFACE
    _change_advanced_option(ssh_ipv6_addr, optionKey, optionValue)

def ipv4_change_advanced_option(module, ipv4_addr, optionKey, optionValue, password):
    info("Start change ESXi host {} advanced option {} to {}".format(ipv4_addr, optionKey, optionValue))
    _change_advanced_option(module, ipv4_addr, optionKey, optionValue, password)

# not used
def batch_change_advanced_option_bf(optionKey, optionValue, vxmIP):
    host_ipv6_address_list = retrieve_host_ipv6_addr(vxmIP)
    for host_ipv6_address in host_ipv6_address_list:
        ipv6_change_advanced_option(host_ipv6_address.keys()[0], host_ipv6_address.values()[0], optionKey, optionValue)

# not used
def batch_change_advanced_option_af(optionKey, optionValue, password):
    host_ipv4_address_list = retrieve_host_ipv4_addr()
    for host_ipv4_address in host_ipv4_address_list:
        ipv4_change_advanced_option(host_ipv4_address, optionKey, optionValue, password)

def change_primary_node_advanced_option(module, optionKey, optionValue, password, vxmIP):
    appliance_id, primary_node_ip = retrieve_primary_host_ipv6_addr(vxmIP)
    info(appliance_id)
    info(primary_node_ip)
    info("Start change primary node {}[{}] advanced option".format(appliance_id, primary_node_ip))
    ipv4_change_advanced_option(module, primary_node_ip, optionKey, optionValue, password)

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            optionKey=dict(type='str', required=False, default='Config.HostAgent.vmacore.soap.sessionTimeout'),
            optionValue=dict(required=True),
            optionValueType=dict(type='str', required=False, default = 'int'),
            esxi_password=dict(type='str', required=True, no_log=True),
            vxmIP=dict(type=str, required=True)
        ),
        supports_check_mode = False
    )

    optionKey = module.params['optionKey']
    optionValueType = module.params['optionValueType']
    if optionValueType == 'int':
        optionValue = int(module.params['optionValue'])
    elif optionValueType == 'string':
        optionValue = module.params['optionValue']
    esxi_password = module.params['esxi_password']
    vxmIP = module.params['vxmIP']

    info("*" * 20 + " Start change ESXi host advanced option {} to {} ".format(optionKey, optionValue) + "*" * 20)
    change_primary_node_advanced_option(module, optionKey, optionValue, esxi_password, vxmIP)

    module.exit_json(changed=True, msg=LOG_MESSAGE)

def main():
    run_module()

if __name__ == '__main__':
    main()
