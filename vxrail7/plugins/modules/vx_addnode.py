#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import time
import json
import ipaddress
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

# console ouput
CONSOLEHANDLER = logging.StreamHandler()
CONSOLEHANDLER.setLevel(logging.INFO)
CONSOLEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(CONSOLEHANDLER)

# file output
FILEHANDLER = logging.FileHandler(LOG_FILE_NAME)
FILEHANDLER.setLevel(logging.DEBUG)
FILEHANDLER.setFormatter(LOG_FORMAT)
LOGGER.addHandler(FILEHANDLER)

class ExpansionUrls():
    ''' Class performs mapping of VxRail APIs and class methods called within the module '''
    available_hosts_url_tpl = 'https://{}/rest/vxm/v1/system/available-hosts'
    precheck_url_tpd = 'https://{}/rest/vxm/private/cluster/expansion/precheck'
    network_pool_url_tpl = 'https://{}/rest/vxm/v2/cluster/network/pools'
    validate_progress_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'
    expansion_progress_url_tpl = 'https://{}/rest/vxm/v1/requests/{}'
    validate_start_url_tpl = 'https://{}/rest/vxm/private/cluster/expansion/validate'
    expansion_start_url_tpl = 'https://{}/rest/vxm/private/cluster/add-host'

    def __init__(self, vxm_ip):
        '''init method'''
        self.vxm_ip = vxm_ip

    def get_url_available_hosts(self):
        '''map to vxrail list available hosts api'''
        return ExpansionUrls.available_hosts_url_tpl.format(self.vxm_ip)

    def get_url_validation_start(self):
        '''map to vxrail validate compatable hosts API'''
        return ExpansionUrls.validate_start_url_tpl.format(self.vxm_ip)

    def get_url_validation_progress(self, job_id):
        '''Maps to VxRail API: validation task progress'''
        return ExpansionUrls.validate_progress_url_tpl.format(self.vxm_ip, job_id)

    def get_url_expansion_start(self):
        '''Map to VxRail Node Expansion api'''
        return ExpansionUrls.expansion_start_url_tpl.format(self.vxm_ip)

    def get_url_expansion_progress(self, task_id):
        '''Map to VxRail Node Expansion api'''
        return ExpansionUrls.expansion_progress_url_tpl.format(self.vxm_ip, task_id)

    def get_url_network_pool(self):
        '''Map to VxRail get network pools api'''
        return ExpansionUrls.network_pool_url_tpl.format(self.vxm_ip)

    def get_url_precheck(self):
        '''Map to VxRail node pre-check api'''
        return ExpansionUrls.precheck_url_tpd.format(self.vxm_ip)


class vxrail():
    ''' Root Class for all mathods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.esxip = module.params.get('mgt_ip')
        self.vmotion_ip = module.params.get('vmotion_ip')
        self.vsanip = module.params.get('vsan_ip')
        self.timeout = module.params.get('timeout')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.auth = (self.vcadmin, self.vcpasswd)
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
        try:
            response = requests.get(url=self.expansion_urls.get_url_available_hosts(),
                                    verify=False,
                                    auth=self.auth,
                                    timeout=self.timeout)
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)

        if response.content:
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
            return "No compatable hosts"

    def create_validation_json(self, nodes, uplinks):
        ''' validate list of nodes as expansion candidates '''
        validate_json = {}
        validate_json['hosts'] = []
        validate_json['hosts'].append(self._create_one_host_section(nodes))
        network_section = {}
        network_section['vds'] = self._create_network_section(nodes, uplinks)

        vcenter_section = {}
        vcenter_section['username'] = module.params.get('vcadmin')
        vcenter_section['password'] = module.params.get('vxpasswd')
        validate_json['network'] = network_section
        validate_json['vcenter'] = vcenter_section

        return validate_json

    def create_expansion_json(self, nodes):
        ''' configure json object from user inputs '''
        all_expansion_json = []
        vcenter_section = {}
        vcenter_section['username'] = module.params.get('vcadmin')
        vcenter_section['password'] = module.params.get('vcpasswd')
        expansion_json = {}
        expansion_json['host'] = self._create_one_host_section(nodes)
        expansion_json['vcenter'] = vcenter_section
        expansion_json['maintenance_mode'] = False
        all_expansion_json.append(expansion_json)
        return all_expansion_json

    def _create_one_host_section(self, snid):
        hosts = []
        host = {}
        host['sn'] = snid
        host['hostname'] = module.params.get('esxhost')
        host['management_account'] = {}
        host['management_account']['username'] = module.params.get('vxadmin')
        host['management_account']['password'] = module.params.get('vxpasswd')
        host['root_password'] = module.params.get('root_passwd')
        host['networks'] = {}
        host['networks']['management'] = {"ip" : module.params.get('mgt_ip'), "netmask" : "255.255.255.0", "gateway" : "172.17.0.1"}
        host['networks']['vsan'] = {"ip" : module.params.get('vsan_ip'), "netmask" : "255.255.255.0"}
        host['networks']['vmotion'] = {"ip" : module.params.get('vmotion_ip'), "netmask" : "255.255.255.0"}
        host['networks']['witness'] = {"ip" : module.params.get('witness_ip'), "netmask" : "255.255.255.0"}
        host['geo_location'] = {}
        host['geo_location'] = {"rack_name" : module.params.get('rack_name'), "order_number" : module.params.get('rack_number')}

        return host


    def _create_network_section(self, nodes, uplinks):
        nic_mappings = []
        serial_numbers = []
#        uplinks = module.params.get('uplinks')

        for i in nodes:
            serial_numbers.append(i)

#        for n in range(len(nics)):
#            uplinks[n].name = nics[n].name
#            uplinks[n].physical_nic = nics[n].pnic

        nic_mappings.append(serial_numbers)
        nic_mappings.append(uplinks)

        return nic_mappings


    def start_expansion(self, expansion_json):
        ''' orchestrate the expansion task '''
        request_id_pool = []
        for json in expansion_json:
            request_id = self.start_one_host_expansion(json)
            request_id_pool.append(request_id)
        return request_id


    def start_one_host_expansion(self, expansion_json):
        ''' initiate cluster expansion '''
        LOGGER.info("Starting One Host expansion...")
        processed_data = []
        headers = {'Content-type': 'application/json'}
        try:
            response = requests.post(url=self.expansion_urls.get_url_expansion_start(),
                                     verify=False,
                                     auth=self.auth,
                                     headers=headers,
                                     data=json.dumps(expansion_json)
                                     )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('%s Cannot connect to VxRail Manager %s .', response.url, self.vxm_ip)

        if response.content:
            data = byte_to_json(response.content)
            return data['request_id']

    def start_validation(self, exp_json):
        ''' validate the pre-check '''
        response_json = []
        headers = {'Content-type': 'application/json'}
        try:
            response = requests.post(url=self.expansion_urls.get_url_validation_start(),
                                     verify=False,
                                     auth=self.auth,
                                     headers=headers,
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

        LOGGER.info(response.status_code)
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
            LOGGER.info('Expansion Task %s has failed.', job_id)
            LOGGER.info(response_json['extension']['thoroughValidationFieldErrors'])
            LOGGER.info(response_json['extension']['normalValidationFieldErrors'])
        else:
            LOGGER.info('Inner track_expansion method: %s', expansion_status)
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
                           vsan_ip=dict(required=True),
                           vmotion_ip=dict(required=True),
                           root_passwd=dict(required=True, no_log=True),
                           timeout=dict(type='int', default=10),
                           ),
        supports_check_mode=True,
    )

    uplinks = []
    for i in range(0, 2):
        link = {}
        link['name'] = "uplink" + str(i+1)
        link['physical_nic'] = "vmnic" + str(i)
        uplinks.append(link)
  
    validation_status = 0
    node_list = []
    expansion_status = 0
    node_list = vxrail().get_nodes()
    if node_list == 'error':
        module.fail_json(msg="Module failed to connect to VxRail Manager")
    LOGGER.info('VxRail Node inventory completed.')
    LOGGER.info('The following nodes are available for cluster expansion -->: %s.', node_list)
    if node_list in ('No available hosts', 'No compatable hosts'):
        LOGGER.error("node_check: There are no available nodes to add to this system!")
        module.fail_json(msg='There are no available nodes to add to this cluster!')
    else:
        node = node_list.pop()
        LOGGER.info('node_check: %s will be used for expansion', node)
        exp_json = vxrail().create_validation_json(node, uplinks)
        LOGGER.info('node_check: %s.', exp_json)
        jobid = vxrail().start_validation(exp_json)
#        LOGGER.info('node_check: VxRail task id: %s.', jobid)
    LOGGER.info('Checking to see if we have what we need for the deployment...')
#    while validation_status not in ('COMPLETED', 'FAILED'):
#        validation_status = vxrail().get_validation_status(jobid)
#        LOGGER.info("expansion_validation: Sleeping 60 seconds before checking for status...")
#        time.sleep(60)
#    if validation_status == 'COMPLETED':
        expansion_json = vxrail().create_expansion_json(node)
#        task_id = vxrail().start_expansion(expansion_json)
#        LOGGER.info('expansion_validation: vxrail task_ID: %s.', task_id)
#        while expansion_status not in ('COMPLETED', 'FAILED'):
#            LOGGER.info("node_expansion: sleeping 60 seconds...")
#            time.sleep(60)
#            expansion_status = vxrail().track_expansion_status(task_id)
#            LOGGER.info('node_expansion: track_expansion status: %s', expansion_status)
#    else:
#        expansion_status = validation_status

    vx_facts = {'validation_status' : expansion_status}
    vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
