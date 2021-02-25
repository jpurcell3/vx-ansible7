#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: vxrail_update_json
short_description: Update vxRail first run JSON
requirements: 
description:
    -  Update vxRail first run JSON
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
---
'''

RETURN = '''
msg:
    description: The status of the resource
'''

from ansible.module_utils.basic import AnsibleModule
import json
import logging
import time
import requests
from requests.exceptions import HTTPError
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
import chardet

logs = None

class LoggingConfig(object):
    """Generate conversion logs to File"""

    def __init__(self, log_file):
        log_path = log_file
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_path, mode='a')
        fh.setLevel(logging.INFO)
        log_format = logging.Formatter('%(asctime)s-%(levelname)s:%(message)s')
        fh.setFormatter(log_format)
        self.logger.addHandler(fh)

    def get_log(self):
        return self.logger


def byte_to_json(body):
    ''' method to convert http content to json  '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            vxmIP=dict(type='str', required=True),
            build_logfile=dict(required=False, type="str"),
            use_proxy=dict(required=False, type="bool", default=False),
            validate_certs=dict(required=False, type="bool", default=False)
        ),
        supports_check_mode=False
    )

    vxmIP = module.params['vxmIP']
    if module.params['build_logfile']:
        build_logfile = module.params['build_logfile']
    else:
        build_logfile = '/tmp/build_output_' + vxmIP.replace(".", "-") + ".log"

    logs = LoggingConfig(build_logfile)
    use_proxy = module.params['use_proxy']
    status_tpl = 'https://{}/rest/vxm/v1/system/initialize/status'
    status_url = status_tpl.format(vxmIP)
    configureLog = None

    while True:
        try:
            response = requests.get(url=status_url,
                                    verify=False,
                                    )
            response.raise_for_status()
        except HTTPError as http_err:
            return 'error'
        except Exception as api_exception:
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            status = data['state']
            steps = data['extension']['steps']

            if status == "FAILED":
                for step in steps:
                    if step.state == "FAILED":
                        logs.get_log().debug("Configuration Failed %s" % step['message'])
                        module.fail_json(changed=False, msg="Failed  %s" % step['message'], progress="FAILED")
            elif status == "COMPLETED":
                logs.get_log().debug("Configuration Succeeded!")
                module.exit_json(changed=True, msg="Configuration Succeeded!", progress="COMPLETED")

            step_detail = ""
            for step in steps:
                if step.get('state') == "STARTING":
                    step_detail = step['name']
                    logs.get_log().info(step_detail)
                    break
                if step.get('state') == "STARTED":
                    step_detail = step['name']
                    time.sleep(5)
                    break

            if step_detail != "":
                newLog = step_detail

                if configureLog != newLog:
                    logs.get_log().debug("Applying configurations: %s" % newLog)
                    configureLog = newLog
            else:
                time.sleep(2)
#                logs.get_log().debug("Waiting for Configuration")
        else:
            logs.get_log().debug("Failed to execute the API request: %s" % api_exception) 
            module.fail_json(msg="Failed to execute the API request: %s" % api_exception)

        time.sleep(1)

def main():
    run_module()

if __name__ == '__main__':
    main()
