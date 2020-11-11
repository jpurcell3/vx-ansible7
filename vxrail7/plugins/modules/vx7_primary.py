#!/usr/bin/python3
import json
import datetime
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
LOG_FILE_NAME = datetime.datetime.now().strftime('/tmp/vx7-primary.log')
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
    nodes_tpl = 'https://{}/rest/vxm/private/system/initialize/nodes'

    def __init__(self, vxm_ip):
        self.vxm_ip = vxm_ip

    def get_nodes(self):
        ''' map to get system properties '''
        return ExpansionUrls.nodes_tpl.format(self.vxm_ip)

class VxRail():
    ''' primary class for module functions or methods '''
    def __init__(self):
        self.vxm_ip = module.params.get('ip')
        self.timeout = module.params.get('timeout')
        self.expansion_urls = ExpansionUrls(self.vxm_ip)

    def cluster_nodes(self):
        ''' query for host details '''
        ipv6_addr_list = []
        primary_host_ip = ""
        appliance_id = ""
        response = requests

        try:
            response = requests.get(url=self.expansion_urls.get_nodes(),
                                    verify=False,
                                    )
            response.raise_for_status()

        except HTTPError as http_err:
            LOGGER.error("HTTP error %s request to VxRail Manager %s", http_err, self.vxm_ip)
            return 'error'
        except Exception as api_exception:
            LOGGER.error(' %s Cannot connect to VxRail Manager %s', api_exception, self.vxm_ip)
            return 'error'

        if response.status_code == 200:
            data = byte_to_json(response.content)
            for i in range(len(data)):
                if data[i].get('primary') == True:
                    primary_host_ip = data[i].get('primary_ip')
                    appid_dict = data[i].get('id')
                    appliance_id = appid_dict.get('appliance_id')
        return appliance_id, primary_host_ip

def main():
    ''' entry point into module exeution '''
    global module
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=False),
            ip=dict(required=True),
            timeout=dict(type='int', default=10),
            ),
        supports_check_mode=True,
    )

    result = VxRail().cluster_nodes()
    LOGGER.info(result)

    if result == 'error':
        module.fail_json(msg="VxRail Manager returned an error. It is either unreachable or it has already been deployed")


    vx_facts_result = dict(changed=False, ansible_facts=result)
    module.exit_json(**vx_facts_result)

if __name__ == '__main__':
    main()
