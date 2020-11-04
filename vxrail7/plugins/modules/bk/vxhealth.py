#!/usr/bin/python3

import json
import logging
import requests
import chardet
from requests.exceptions import HTTPError
from ansible.module_utils.basic import AnsibleModule

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

class CustomLogFormatter(logging.Formatter):
    ''' class to provide logging functions to module '''
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
    ''' method primarily used to convert http content '''
    info_fmt = "%(asctime)s [%(levelname)s]\t%(message)s"
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


# Configurations
LOG_FILE_NAME = "/tmp/vx-health.log"
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
    ''' mapping class for vxrail apis '''
    system_url_tpl = 'https://{}/rest/vxm/v1/system'
    hosts_url_tpl = 'https://{}/rest/vxm/v1/hosts'
    node_url_tpl = 'https://{}/rest/vxm/v1/hosts/{}'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_system(self):
        ''' map to get system properties '''
        return ExpansionUrls.system_url_tpl.format(self.vxm_ip)

class VxRail():
    ''' primary class for module functions or methods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.vcadmin = module.params.get('vcadmin')
        self.vcpasswd = module.params.get('vcpasswd')
        self.auth = self.vcadmin, self.vcpasswd
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def syshealth(self):
        ''' query for host details '''
        vxm = {}
        session = requests.Session()

        try:
            response = session.get(url=self.expansion_urls.get_system(),
                                   verify=False,
                                   auth=self.auth
                                   )
            response.raise_for_status()
        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            vxm['state'] = data['health']
        return vxm

def main():
    ''' entry point into module exeution '''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            vcadmin=dict(required=True),
            vcpasswd=dict(required=True, no_log=True),
            ip=dict(required=True),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    result = VxRail().syshealth()
    LOGGER.info(result)

    if result == 'error':
        module.fail_json(msg="VxRail Manager is unreachable")


    vx_facts_result = dict(changed=False, ansible_facts=result)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
