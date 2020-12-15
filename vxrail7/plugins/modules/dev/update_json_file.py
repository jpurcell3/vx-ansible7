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
import requests
from requests.exceptions import HTTPError
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
import chardet
from collections import OrderedDict

# Define Variables: MarvinKeys
NORMAL_ERROR = "normalValidationFieldErrors"
THOROUGH_ERROR = "thoroughValidationFieldErrors"
VALIDATION_PROGRESS = "validatorProgresses"


def byte_to_json(body):
    ''' method to convert http content to json  '''
    return json.loads(body.decode(chardet.detect(body)["encoding"]))


def load_json_object(module, filePath):
    try:
        with open(filePath, 'r') as f:
            jsonData = json.load(f, object_pairs_hook=OrderedDict)
            return jsonData
    except:
        module.fail_json(changed=False, msg="fail to load file %s" % filePath)

def write_json_object(module, filePath, jsonData):
    try:
        with open(filePath, 'w') as f:
            json.dump(jsonData, f, indent=4, sort_keys=False)
    except:
        module.fail_json(changed=False, msg="fail to write to file %s" % filePath)

def add_missed_host(module, jsonObj, tmpJsonFile, expectedNodeCount):
    nodeCount = len(jsonObj['hosts'])
    nodeNumOffset = expectedNodeCount - nodeCount

    if nodeNumOffset < 0:
        module.fail_json(changed=False, msg=("Json file defines %s number of hosts. Input NodeCount value is %s. Please update the Json file" % (nodeCount, expectedNodeCount)))

    while nodeNumOffset:
        tmpObj = jsonObj['hosts'][0]
        jsonObj['hosts'].append(tmpObj)
        nodeNumOffset -= 1

    write_json_object(module, tmpJsonFile, jsonObj)

    return jsonObj

def update_host_name(module, jsonObj, tmpJsonFile, expectNodeCount, prefix):
    for i in range(expectNodeCount):
        jsonObj['hosts'][i]['hostname'] = (generate_host_name(jsonObj, i, prefix))
    write_json_object(module, tmpJsonFile, jsonObj)

    return jsonObj

def generate_host_name(jsonObj, nodeIndex, prefix):
    host = ""
    offset = ""
    separator = ""
    host = jsonObj['hosts'][0]['hostname']
    offset = host.split(prefix)[-1]
    for char in offset:
        if char[0:1] == "-":
            separator = "-"
            offset = offset[1:]
    topLevelDomain = jsonObj['global']['top_level_domain'].strip()
    network = jsonObj['hosts'][0]['network'][0]['ip']

    if offset == "":
        offset = 1   # Default input of offset is empty, the correspoding value is 1
    else:
        offset_length = len(offset)
        offset = int(offset)

    offset = offset + nodeIndex
    if offset_length == 2:
        numericPart = ("%02d" % (offset,))
    elif offset_length == 3:
        numericPart = ("%03d" % (offset,))
    elif offset_length == 4:
        numericPart = ("%04d" % (offset,))
    else:
        numericPart = str(offset)

    hostname = prefix + separator + numericPart
    return hostname

def add_node(module, jsonObj, tmpJsonFile, expectedNodeCount, vxmIP):
    use_proxy = module.params['use_proxy']
    nodes_tpl = 'https://{}/rest/vxm/private/system/initialize/nodes'
    node_url = nodes_tpl.format(vxmIP)

    try:
        response = requests.get(url=node_url,
                                verify=False,
                                )
        response.raise_for_status()
    except HTTPError as http_err:
        return 'error'
    except Exception as api_exception:
        return 'error'

    if response.status_code == 200:
        data = byte_to_json(response.content)
    if not data:
        module.fail_json(msg="Node data could not be retrieved from vxRail Manager")

    foundNodeCount = len(data)
    if expectedNodeCount != foundNodeCount:
        module.fail_json(msg="Expect %s nodes, but only found %s nodes" % (expectedNodeCount, foundNodeCount))

    write_json_object(module, tmpJsonFile, jsonObj)

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            vxmIP=dict(type='str', required=True),
            expectedNodeCount=dict(type='int', required=True),
            initJsonFile=dict(type='str', required=True),
            tmpJsonFile=dict(type='str', required=True),
            prefix=dict(type=str, required=True),
            use_proxy=dict(required=False, type="bool", default=False),
            validate_certs=dict(required=False, type="bool", default=False)
        ),
        supports_check_mode=False
    )

    vxmIP = module.params['vxmIP']
    initJsonFile = module.params['initJsonFile']
    initJsonObj = load_json_object(module, initJsonFile)
    tmpJsonFile = module.params['tmpJsonFile']
    expectedNodeCount = module.params['expectedNodeCount']
    use_proxy = module.params['use_proxy']
    prefix = module.params['prefix']

    tmpJsonObj = add_missed_host(module, initJsonObj, tmpJsonFile, expectedNodeCount)
    tmpJsonObj = update_host_name(module, tmpJsonObj, tmpJsonFile, expectedNodeCount, prefix)
    add_node(module, tmpJsonObj, tmpJsonFile, expectedNodeCount, vxmIP)

    module.exit_json(changed=True, msg="Temp JSON file created %s" % module.params['tmpJsonFile'])

def main():
    run_module()

if __name__ == '__main__':
    main()
