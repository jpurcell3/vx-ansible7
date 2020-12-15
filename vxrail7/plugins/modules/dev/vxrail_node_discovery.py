#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: vxrail_node_discovery
short_description: Disover VXRail unconfigured nodes
requirements: 
description:
    -  Disover vxRail unconfigured nodes
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''

'''

RETURN = '''
msg:
    description: The status of the resource
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec
import  json, os, time

NODE_DISCOVERY = "/rest/vxm/private/system/initialize/nodes"

def discover_nodes(module, vxmIP, expectedNodeCount, use_proxy):
    response = os.system("ping -c 5 %s" % vxmIP)
    node = {}
    nodeTags = []
    nodeType = []
    results = {}
    if response == 0:
        method = 'GET'
        url = "https://" + vxmIP + NODE_DISCOVERY
        headers = {'content-type': 'application/json'}
        response, info = fetch_url(module,
                                   url,
                                   data={},
                                   headers=headers,
                                   use_proxy=use_proxy,
                                   method=method)

        if info['status'] == 200:
            response_content = response.read()
            data = json.loads(response_content)
            if not data:
                return "No available hosts"
            for i, t in enumerate(data):
                node['assetTag'] = data[i].get('asset_tag')
                node['model'] = data[i].get('model')
                nodeTags.append(node['assetTag'])
                nodeType.append(node['model'])

            results['nodeTags'] = nodeTags
            results['nodeType'] = nodeType

            foundNodeCount = len(data)
            if foundNodeCount == expectedNodeCount:
                results['msg'] = ("Found all %s nodes" % expectedNodeCount)
                results['foundNodeCount'] = foundNodeCount
                return results
            else:
                results['msg'] = ("Expect %s nodes, but only found %s" % (expectedNodeCount, foundNodeCount))
                module.fail_json(**results)
        else:
            module.fail_json(msg="Failed to discover nodes. Can not proceed to build the cluster, Response %s " % info['msg'])
    else:
        module.fail_json(msg="Cannot reach VxRail Manager. Can not proceed to build the cluster, Ping Response %s." % response)

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            vxmIP=dict(type='str', required=True),
            expectedNodeCount=dict(type='int', required=True),
            use_proxy=dict(required=False, type="bool", default=False),
            validate_certs=dict(required=False, type="bool", default=False)
        ),
        supports_check_mode=False
    )

    results = discover_nodes(module, module.params['vxmIP'], module.params['expectedNodeCount'], module.params['use_proxy']) 

    vx_facts = dict(results)
    module.exit_json(**vx_facts)

def main():
    run_module()

if __name__ == '__main__':
    main()
