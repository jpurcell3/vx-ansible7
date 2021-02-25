#!/usr/bin/python3
# Copyright: (c) 2018, Jeff Purcell <jeff.purcell@dell.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


# add package path if script run on VxRail manager
import time
import json
import os
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
LOG_FILE_NAME = "/tmp/cluster-init.log"
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
    validate_json_url_tpl = 'https://{}/rest/vxm/v1/system/initialize?dryrun=true'
    validation_status_url_tpl = 'https://{}/rest/vxm/v1/system/initialize/status'
    initialize_url_tpl = 'https://{}/rest/vxm/v1/system/initialize'
    initialization_status_url_tpl = 'https://{}/rest/vxm/v1/system/initialize/status'

    def __init__(self, vxm_ip):
        '''init method'''
        self.vxm_ip = vxm_ip

    def post_url_validate_json(self):
        return ExpansionUrls.validate_json_url_tpl.format(self.vxm_ip)

    def get_validation_status(self):
        return ExpansionUrls.validation_status_url_tpl.format(self.vxm_ip)

    def post_url_initialize_cluster(self):
        return ExpansionUrls.initialize_url_tpl.format(self.vxm_ip)

    def get_initialization_task_status(self):
        return ExpansionUrls.initialization_status_url_tpl.format(self.vxm_ip)


class vxrail():
    ''' Root Class for all mathods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)


    def validate_json(self, config_json):
        headers = {'Content-type': 'application/json'}
        try:
            response = requests.post(url=self.expansion_urls.post_url_validate_json(),
                                     verify=False,
                                     headers=headers,
                                     data=json.dumps(config_json)
                                     )
            response.raise_for_status()

        except HTTPError as http_err:
            LOGGER.error('HTTP error %s request to VxRail Manager.', http_err)

        except Exception as e:
            LOGGER.error('Error: %s. Cannot connect to VxRail Manager %s.', e, self.vxm_ip)

        if response.content:
            data = byte_to_json(response.content)
            LOGGER.info(data)
            if data.get('message'):
                LOGGER.error(data['message'])
                return "Cluster has already been built"
            else:
                return data['request_id']
        else:
            LOGGER.info(response.status_code)

    def init_cluster(self, config_json):
        ''' Initiate Cluster deployment '''
        payload = config_json
        content = {'Content-type': 'application/json'}
        try:
            response = requests.post(
                url=self.expansion_urls.post_url_initialize_cluster(),
                verify=False,
                headers=content,
                data=json.dumps(config_json)
                )
            response.raise_for_status()
            return response.content
        except HTTPError as http_err:
            LOGGER.error('HTTP error %s request to VxRail Manager %s.', http_err, self.vxm_ip)
        except Exception as e:
            LOGGER.error('Module exception %s. Cannot connect to VxRail Manager %s.', e, self.vxm_ip)

    def get_task_status(self, task):
        ''' track the job status '''
        session = requests.Session()
        try:
            response = session.get(url=self.expansion_urls.get_validation_status(),
                                   verify=False,
                                   auth=None,
                                   )
        except Exception as http_err:
            LOGGER.error(http_err)
            LOGGER.error('Cannot connect to VxRail Manager %s.', self.vxm_ip)

#        LOGGER.info(response.status_code)
        if response.status_code in (200, 202):
            response_json = byte_to_json(response.content)
            step = response_json['step']
            percent = response_json['progress']
            state = response_json['state']
            LOGGER.info('%s Status: %s', task, state)
            LOGGER.info('Percent completed: %d', percent)
            if state == 'COMPLETED':
                LOGGER.info("The task has completed")
            elif state == 'FAILED':
                LOGGER.info('%s task has failed at step %s.', task, step)
                LOGGER.info(response_json['extension']['validation']['thorough']['errors'])
                LOGGER.info(response_json['extension']['validation']['thorough']['warnings'])
            else:
                LOGGER.info('Current Step: %s', step)
            LOGGER.info(' %s: Sleeping 30 seconds before re-checking for status..."', task)
            time.sleep(30)
        return state

def main():
    ''' Go! '''
    global module
    module = AnsibleModule(
        argument_spec=dict(name=dict(required=False),
                           ip=dict(required=True),
                           cfg=dict(required=True),
                           timeout=dict(type='int', default=10),
                           ),
        supports_check_mode=True,
    )


    validation_status = ''
    init_status = ''
    file = module.params.get('cfg')
    if os.path.isfile(file):
        LOGGER.info('VxRail Initializaion using JSON file %s', module.params.get('cfg'))
        with open(file) as f:
            config_json = json.load(f)
    else:
        LOGGER.error('File cannot not be opened or does not exit, please verify and try again')
        module.fail_json(msg="JSON file not found!")

    LOGGER.info("Validating the JSON input file...")
    jobid = vxrail().validate_json(config_json)
    if 'Cluster has already been built' in jobid:
        module.fail_json(msg='The VxRail Cluster has already been built')
    LOGGER.info('------------------------------------------------------------')
    LOGGER.info('Validate json configuration file: VxRail task id: %s.', jobid)
    LOGGER.info('------------------------------------------------------------')
    while validation_status not in ('COMPLETED', 'FAILED'):
        validation_status = vxrail().get_task_status('validation')

    if validation_status == 'COMPLETED':
        LOGGER.info('------------------------------------------------------------')
        LOGGER.info('Validation Completed. Initializing VxRail Cluster')
        LOGGER.info('------------------------------------------------------------')
        task_id = vxrail().init_cluster(config_json)
    else:
        module.fail_json(msg="Validation Task has failed. Check Log file /tmp/cluster-init.log for details")

    if task_id:
        LOGGER.info('------------------------------------------------------------')
        LOGGER.info('Cluster Initialization in progress: vxrail task_ID: %s.', task_id)
        LOGGER.info('------------------------------------------------------------')
        while init_status not in ('COMPLETED', 'FAILED'):
            init_status = vxrail().get_task_status('initialization')
            LOGGER.info('cluster_init: track_initialization status: %s', init_status)

    if init_status == 'COMPLETED':
        LOGGER.info('------------------------------------------------------------')
        LOGGER.info('Initialization Completed.')
        LOGGER.info('------------------------------------------------------------')
        vx_facts = {'initialization_status' : init_status}
        vx_facts_result = dict(changed=False, ansible_facts=vx_facts)
        module.exit_json(**vx_facts_result)
    else:
        module.fail_json(msg="The VxRail Initializaiton Task has failed to complete. Please see the /tmp/cluster-init.log file for additional detials")


if __name__ == '__main__':
    main()
