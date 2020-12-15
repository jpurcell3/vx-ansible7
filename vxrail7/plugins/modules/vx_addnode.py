#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
author: Dell EMC Ansible Team (@jpurcell3) <jeff.purcell@dell.com>
description:
  - "Add a node to an existing VxRail Cluster"

module: vx_addnode

options:

  name:
    description:
      Name of the playbook task
    required: false

  ip:
    description:
      The IP address of the VxRail Manager System
    required: true

  vcadmin:
    description:
      Administrative account of the vCenter Server the VxRail Manager is registeried to
    required: true

  vcpasswd:
    description:
      The password for the administror account provided in vcadmin
    required: true

  esxhost:
    description:
      The ESXi Hostname of the host you wish to remove from the cluster
    required: true

  vxadmin:
    description:
      The ESX Administrative user.
    required: true

  vxpasswd:
    description:
      The vxadmin user password.
    required: true

  mgt_ip:
    description:
      The management address for the ESX Host.
    required: true

  mgt_gw:
    description:
      The management gateway address for the ESX Host.
    required: true

  vsan_ip:
    description:
      The vsan IP address for the ESX Host.
    required: true

  vmotion_ip:
    description:
      The vmotion IP address for the ESX Host.
    required: true

  wirness_ip:
    description:
      The witness IP address for the ESX Host.
    required: true

  Timeout:
    description:
      Time out value for the HTTP session to connect to the REST API
    required: false

short_description: VxRail Node Removal
version_added: "2.9"


'''
EXAMPLES = """
    - name: Add Node to existing VxRail Cluster
      vx-addnode:
        vcadmin: "{{ vcadmin }}"
        vcpasswd: "{{ vcpasswd}}"
        ip: "{{ vxm_ip }}"
        esxhost: "{{ esxhost }}"
        vxadmin: "{{ vxuser }}"
        vxpasswd: "{{ vxpasswd }}"
        mgt:_ip: "{{ mgt_ip }}"
        mgt:_gw: "{{ mgt_gw }}"
        vsan_ip: "{{ vsan_ip }}"
        vmotion_ip: "{{ vmotion_ip }}"
        root_passwd: "{{ root_passwd }}"
    register: output

   - debug:
     msg: "{{ output }}"
"""

RETURN = """
"""



import time
import json
import logging
import requests
import chardet
import urllib3
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

def byte_to_json(body):
    ''' method to convert http content to json  '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


# Configurations
LOG_FILE_NAME = "/tmp/vx-addnode.log"
TMP_RETRY_FILE = "tmp_retry_id" # TBD
LOG_FORMAT = CustomLogFormatter()


# Disable package info
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)

# file output
FILEHANDLER = logging.FileHandler(LOG_FILE_NAME)
FILEHANDLER.setLevel(logging.DEBUG)
FILEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILEHANDLER)

class ExpansionUrls():
    ''' Class performs mapping of VxRail APIs and class methods called within the module '''
    available_hosts_url_tpl = 'https://{}/rest/vxm/v1/system/available-hosts'
    expansion_progress_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'
    precheck_url_tpl = 'https://{}/rest/vxm/private/cluster/expansion/precheck'
    start_expansion_url_tpl = 'https://{}/rest/vxm/private/cluster/add-host'
    validate_progress_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'
    validate_node_url_tpl = 'https://{}/rest/vxm/private/cluster/expansion/validate'
    ipaddress_url_tpl = 'https://{}/rest/vxm/private/system/network-info'

    def __init__(self, vxm_ip):
        '''init method'''
        self.vxm_ip = vxm_ip

    def get_url_available_hosts(self):
        '''map to VxRail list available hosts api'''
        return ExpansionUrls.available_hosts_url_tpl.format(self.vxm_ip)

    def post_url_validate_node(self):
        '''map to VxRail validate compatable hosts API'''
        return ExpansionUrls.validate_node_url_tpl.format(self.vxm_ip)

    def get_url_validation_progress(self, job_id):
        '''Maps to VxRail API: validation task progress'''
        return ExpansionUrls.validate_progress_url_tpl.format(self.vxm_ip, job_id)

    def post_expansion_url(self):
        '''Map to VxRail Node Expansion api'''
        return ExpansionUrls.start_expansion_url_tpl.format(self.vxm_ip)

    def get_url_expansion_progress(self, task_id):
        '''Map to VxRail Node Expansion api'''
        return ExpansionUrls.expansion_progress_url_tpl.format(self.vxm_ip, task_id)

    def get_url_precheck(self):
        '''Map to VxRail node pre-check api'''
        return ExpansionUrls.precheck_url_tpl.format(self.vxm_ip)

    def get_url_management_ips(self):
        '''Map to VxRail node pre-check api'''
        return ExpansionUrls.ipaddress_url_tpl.format(self.vxm_ip)



class VxRail():
    ''' Root Class for all mathods '''
    def __init__(self):
        self.esxip = module.params.get('mgt_ip')
        self.mgtgw = module.params.get('mgt_gw')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)
        self.vxm_ip = module.params.get('ip')
        self.vmotionip = module.params.get('vmotion_ip')
        self.vsanip = module.params.get('vsan_ip')
        self.witness = module.params.get('witness_ip')
        self.timeout = module.params.get('timeout')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)


    def precheck_node_compatibility(self, node_ids):
        ''' check for candidate nodes '''

        def format_node_info(node_info):
            node_version = node_info['system_version']
            node_version = None if 'version' not in node_version or 'build' not in node_version\
                           else '-'.join([node_version['version'], node_version['build']])
            message = node_info['compatible_messages']
            message = None if not message else message[0]

        node_id = []
        payload = {'nodes' : node_ids}

        try:
            response = requests.post(url=self.expansion_urls.get_url_precheck(),
                                     verify=False,
                                     auth=self.auth,
                                     data=json.dumps(payload))
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', {self.vxm_ip})

        response_json = byte_to_json(response.content)
        compatible_nodes = []
        LOGGER.info(response_json)
        for result in response_json:
            node_id = result['id']
            if node_id not in node_ids:
                LOGGER.error("Node not found on VxRail Cluster")
                continue
            if result['compatible_status'] != 'INCOMPATIBLE':
                LOGGER.info('Node %s added to compatible nodes list.', result['id'])
                compatible_nodes.append(node_id)
                LOGGER.info(compatible_nodes)
                LOGGER.info(result)
        return compatible_nodes

    def get_nodes(self):
        ''' Return a list of available nodes '''
        response = {}
        try:
            response = requests.get(url=self.expansion_urls.get_url_available_hosts(),
                                    verify=False,
                                    auth=self.auth,
                                    timeout=self.timeout)
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)

        if response:
            data = byte_to_json(response.content)
            LOGGER.info(data)
            if not data:
                LOGGER.info('No available hosts')
                return "No available hosts"
            node_ids = [n['serial_number'] for n in data]
            LOGGER.info("completed get_nodes function")
            LOGGER.info("Checking Node compatibility...")
            nodes = self.precheck_node_compatibility(node_ids)
            if nodes:
                LOGGER.info("completed compatibility validation...")
                LOGGER.info(nodes)
                return nodes
        else:
            return "No compatable hosts"

    def check_iplist(self):
        ''' Return a list of available nodes '''
        response = {}
        try:
            response = requests.get(url=self.expansion_urls.get_url_management_ips(),
                                    verify=False,
                                    auth=self.auth,
                                    timeout=self.timeout)

        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)

        if response.status_code == 200:
            data = byte_to_json(response.content)
            LOGGER.info(data)
            mgt_iplist = data['management']['ip_list']
            vsan_iplist = data['vsan']['ip_list']
            vmotion_iplist = data['vmotion']['ip_list']
            LOGGER.info('Allocated Management addresses %s', mgt_iplist)
            LOGGER.info('Allocated VSAN addresses %s', vsan_iplist)
            LOGGER.info('Allocated Management addresses %s', vmotion_iplist)
            if self.esxip in mgt_iplist:
                module.fail_json(msg="The specified management address is already in use")
            if self.vsanip in vsan_iplist:
                module.fail_json(msg="The specified VSAN address is already in use")
            if self.vmotionip in vmotion_iplist:
                module.fail_json(msg="The specified VMotion address is already in use")

    def create_validation_json(self, nodes, uplinks):
        ''' validate list of nodes as expansion candidates '''
        validate_json = {}
        validate_json['hosts'] = []
        validate_json['hosts'].append(self._create_one_host_section(nodes))
        network_section = {}
        nic_mapping = []
        nic_mapping = self._create_network_section(nodes, uplinks)
        network_section['vds'] = {'nic_mappings': nic_mapping}

        vcenter_section = {}
        vcenter_section['username'] = module.params.get('vcadmin')
        vcenter_section['password'] = module.params.get('vxpasswd')
        validate_json['network'] = network_section
        validate_json['vcenter'] = vcenter_section

        return validate_json

    def create_expansion_json(self, nodes, uplinks):
        ''' configure json object from user inputs '''
        expansion_json = {}
        network_dict = {}
        vcenter_dict = {}

        nic_mapping = []

        expansion_json['host'] = self._create_expansion_host(nodes)
        nic_mapping = self._create_network_section(nodes, uplinks)
        network_dict['vds'] = {'nic_mappings': nic_mapping}
        vcenter_dict['username'] = module.params.get('vcadmin')
        vcenter_dict['password'] = module.params.get('vxpasswd')

        expansion_json['network'] = network_dict
        expansion_json['vcenter'] = vcenter_dict
        return expansion_json

    def _create_one_host_section(self, snid):
        host = {}
        host['sn'] = snid
        host['hostname'] = module.params.get('esxhost')
        host['management_account'] = {}
        host['management_account']['username'] = module.params.get('vxadmin')
        host['management_account']['password'] = module.params.get('vxpasswd')
        host['root_password'] = module.params.get('root_passwd')
        host['networks'] = {}
        host['networks']['management'] = {"ip" : self.esxip, "netmask" : "255.255.255.0", "gateway" : self.mgtgw}
        host['networks']['vsan'] = {"ip" : self.vsanip, "netmask" : "255.255.255.0"}
        host['networks']['vmotion'] = {"ip" : self.vmotionip, "netmask" : "255.255.255.0"}
        host['networks']['witness'] = {"ip" : self.witness, "netmask" : "255.255.255.0"}
        host['geo_location'] = {}
        host['geo_location'] = {"rack_name" : module.params.get('rack_name'), "order_number" : module.params.get('rack_number')}

        return host

    def _create_expansion_host(self, snid):
        host = {}
        host['sn'] = snid
        host['hostname'] = module.params.get('esxhost')
        host['management_account'] = {}
        host['management_account']['username'] = module.params.get('vxadmin')
        host['management_account']['password'] = module.params.get('vxpasswd')
        host['root_password'] = module.params.get('root_passwd')
        host["is_maintenance_mode"] = False
        host['networks'] = {}
        host['networks']['management'] = {"ip" : self.esxip, "netmask" : "255.255.255.0", "gateway" : self.mgtgw}
        host['networks']['vsan'] = {"ip": self.vsanip, "netmask": "255.255.255.0"}
        host['networks']['vmotion'] = {"ip" : self.vmotionip, "netmask" : "255.255.255.0"}
        host['networks']['witness'] = {"ip" : self.witness, "netmask" : "255.255.255.0"}
        host['geo_location'] = {}
#        host['geo_location'] = {"rack_name" : module.params.get('rack_name'), "order_number" : module.params.get('rack_number')}
        host['geo_location'] = {"rack_name" : "r1", "order_number" : "1"}

        return host

    def _create_network_section(self, nodes, uplinks):
        nic_mappings = []
        nodelist = []
        host_dict = {}
        if isinstance(nodes, list):
            for i in range(len(nodes)):
                nodelist.append(nodes[i])
        else:
            nodelist = [nodes]
        host_dict['host_serial_numbers'] = nodelist
        host_dict['uplinks'] = uplinks
        nic_mappings.append(host_dict)
        return nic_mappings


    def start_expansion(self, expansion_json):
        ''' orchestrate the expansion task '''
        request_id_pool = []
        if expansion_json:
            request_id = self.start_one_host_expansion(expansion_json)
            request_id_pool.append(request_id)
        return request_id


    def start_one_host_expansion(self, hexp_json):
        ''' initiate cluster expansion '''
        request_id = ''
        LOGGER.info("Starting One Host expansion...")
        addnode_url = self.expansion_urls.post_expansion_url()
        headers = {'Content-type': 'application/json'}
        try:
            response = requests.post(url=addnode_url,
                                     verify=False,
                                     auth=self.auth,
                                     headers=headers,
                                     data=(hexp_json)
                                     )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            LOGGER.error('HTTP Request error: %s', err)
            module.fail_json(msg="Resonse error from url %s within %s seconds (timeout)" % (addnode_url, self.timeout))

        data = byte_to_json(response.content)
        LOGGER.info('Data %s', data)
        request_id = data['request_id']
        return request_id

    def start_validation(self, exp_json):
        ''' validate the pre-check '''
        response_json = []
        try:
            response = requests.post(url=self.expansion_urls.post_url_validate_node(),
                                     verify=False,
                                     auth=self.auth,
                                     headers={'Content-type': 'application/json'},
                                     data=json.dumps(exp_json)
                                     )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error('HTTP error %s request to VxRail Manager %s.', http_err, self.vxm_ip)
            return 'error'
        except Exception as http_err:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s.', http_err, self.vxm_ip)
            return 'error'

        LOGGER.info('HTTP Response ID %s.', response.status_code)
        if response.status_code == 202:
            response_json = byte_to_json(response.content)
            task_id = (response_json['request_id'])
            LOGGER.info('Pre-validation task started with request id: %s.', task_id)
            if not task_id:
                raise Exception(response_json)
            return task_id


    def get_validation_status(self, job_id):
        ''' get task status '''
        response_json = []
        validation_status = 'unsucessful'
        session = requests.Session()
        try:
            response = session.get(url=self.expansion_urls.get_url_validation_progress(job_id),
                                   verify=False,
                                   auth=self.auth,
                                   )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)
            return 'error'


        if response:
            response_json = byte_to_json(response.content)
            validation_status = response_json.get('state')
            LOGGER.info('Current Status: %s', validation_status)
            if validation_status == 'COMPLETED':
                LOGGER.info("Node validation has completed")
            elif validation_status == 'FAILED':
                LOGGER.info('Validation Task %s has failed.', job_id)
                LOGGER.info(response_json['extension']['normalValidationFieldErrors'])
                LOGGER.info(response_json['extension']['thoroughValidationFieldErrors'])
            else:
                index = int(response_json['extension']['number_of_executed_steps'])
                LOGGER.info(response_json)
                index -= 1
                summary = response_json['extension']['steps'][index]['summary']
                LOGGER.info('Validation Task: %s', summary)
                time.sleep(10)
        return validation_status


    def track_expansion_status(self, task_id):
        ''' track the job status '''
        session = requests.Session()
        expansion_status = []
        try:
            response = session.get(url=self.expansion_urls.get_url_expansion_progress(task_id),
                                   verify=False,
                                   auth=self.auth,
                                   )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)

#        LOGGER.info(response.status_code)
        response_json = byte_to_json(response.content)
        total_steps = response_json['extension']['number_of_total_steps']
        current_step = response_json['extension']['number_of_executed_steps']
        percent = ((current_step/total_steps) * 100)
        LOGGER.info('Percent completed: %d', percent)
        expansion_status = response_json.get('state')
        LOGGER.info('Expansion Status: %s', expansion_status)
        if expansion_status == 'COMPLETED':
            LOGGER.info("The Cluster expansion has completed")
        elif expansion_status == 'FAILED':
            LOGGER.info('Expansion Task %s has failed.', task_id)
            if response_json['extension']['thoroughValidationFieldErrors']:
                LOGGER.info(response_json['extension']['thoroughValidationFieldErrors'])
            LOGGER.info(response_json['extension']['normalValidationFieldErrors'])
        else:
            LOGGER.info(response_json)
            current_step -= 1
            summary = response_json['extension']['steps'][current_step]['summary']
            LOGGER.info('Expansion Task: %s', summary)
            time.sleep(10)

        return expansion_status


def main():
    ''' Go! '''
    global module
    module = AnsibleModule(
        argument_spec=dict(name=dict(required=False),
                           vcadmin=dict(required=True),
                           vcpasswd=dict(required=True, no_log=True),
                           ip=dict(required=True),
                           esxhost=dict(required=True),
                           vxadmin=dict(required=True),
                           vxpasswd=dict(required=True, no_log=True),
                           mgt_ip=dict(required=True),
                           mgt_gw=dict(required=True),
                           vsan_ip=dict(required=True),
                           vmotion_ip=dict(required=True),
                           witness_ip=dict(required=True),
                           root_passwd=dict(required=True, no_log=True),
                           timeout=dict(type='int', default=10),
                           ),
        supports_check_mode=True,
    )

    # To Do: Enumerate the hosts to obtain the network  network profile
    uplinks = []
    for i in range(0, 2):
        link = {}
        link['name'] = "uplink" + str(i+1)
        link['physical_nic'] = "vmnic" + str(i)
        uplinks.append(link)

    result = VxRail().check_iplist()
    validation_status = 0
    node_list = []
    expansion_status = 0
    node_list = VxRail().get_nodes()
    if (not node_list) or (node_list == 'error'):
        module.fail_json(msg="Module failed to get a connect to VxRail Manager")
    LOGGER.info('VxRail Node inventory completed.')
    LOGGER.info('The following nodes are available for cluster expansion -->: %s.', node_list)
    if node_list in ('No available hosts', 'No compatable hosts'):
        LOGGER.error("node_check: There are no available nodes to add to this system!")
        module.fail_json(msg='There are no available nodes to add to this cluster!')
    else:
        node = node_list.pop()
        LOGGER.info('node_check: %s will be used for expansion', node)
        exp_json = VxRail().create_validation_json(node, uplinks)
        LOGGER.info('node_check: %s.', exp_json)
        jobid = VxRail().start_validation(exp_json)
        LOGGER.info('node_check: VxRail task id: %s.', jobid)
    LOGGER.info('Checking to see if we have what we need for the deployment...')
    while validation_status not in ('COMPLETED', 'FAILED'):
        validation_status = VxRail().get_validation_status(jobid)
        LOGGER.info("Validation Task: Sleeping 2 minutes...")
        time.sleep(118)
    if validation_status == 'COMPLETED':
        expansion_json = VxRail().create_expansion_json(node, uplinks)
        hexp_json = json.dumps(expansion_json)
        LOGGER.info(hexp_json)
        task_id = VxRail().start_expansion(hexp_json)
        LOGGER.info('Cluster_expansion: VxRail task_ID: %s.', task_id)
        while expansion_status not in ('COMPLETED', 'FAILED'):
            LOGGER.info("cluster_expansion: sleeping 60 seconds...")
            time.sleep(60)
            expansion_status = VxRail().track_expansion_status(task_id)
            LOGGER.info('cluster_expansion: track_expansion status: %s', expansion_status)
    else:
        module.fail_json(msg="The environment validaiton has failed. Please see the /tmp/vx-addnode.log for more details")

    vx_facts = {'validation_status' : expansion_status}
    vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
