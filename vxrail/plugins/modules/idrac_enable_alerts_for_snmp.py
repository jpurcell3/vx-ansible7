#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'globalclouddev@emc.com'
}

DOCUMENTATION = '''
---
module: idrac_set_snmp_community_string
short_description: Set Community name string on SNMP alert settings under System Settings > SNMP Settings
author: shahid.imran@dell.com
supported_by: globalclouddev@emc.com
'''

EXAMPLES = '''
---
- name: get os network info from iDRAC
  idrac_set_snmp_community_string:
    idrac_ip:   "{{ idrac_ip }}"
    idrac_user: "{{ idrac_user }}"
    idrac_password: "{{ idrac_password }}"
    alerts_json: "{{ alerts_json }}"
  register: result
'''

RETURN = '''
msg:
    description: The status of the resource
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.idrac_session import idrac_login, idrac_logout
from urllib3.exceptions import InsecureRequestWarning
import json, requests

SOCKET_TIMEOUT = 30

def set_snmp_string(module, idrac_cookie, idrac_token):
    body =  {
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#AMP_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "AMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#AMP_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "AMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#AMP_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "AMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#ASR_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "ASR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#BAT_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "BAT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#BAT_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "BAT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#BAT_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "BAT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#BAT_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "BAT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#BAT_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "BAT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#BAT_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "BAT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CBL_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "CBL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CMC_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "CMC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CMC_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "CMC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CMC_4_1": {
      "filter_actions": 9,
      "category": 4,
      "severity": 1,
      "subcategory": "CMC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CMC_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "CMC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CMC_4_3": {
      "filter_actions": 9,
      "category": 4,
      "severity": 3,
      "subcategory": "CMC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CPUA_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "CPUA"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CPU_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "CPU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CPU_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "CPU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CPU_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "CPU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CTL_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "CTL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CTL_2_2": {
      "filter_actions": 11,
      "category": 2,
      "severity": 2,
      "subcategory": "CTL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#CTL_2_3": {
      "filter_actions": 11,
      "category": 2,
      "severity": 3,
      "subcategory": "CTL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#DIS_5_3": {
      "filter_actions": 9,
      "category": 5,
      "severity": 3,
      "subcategory": "DIS"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#ENC_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "ENC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#ENC_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "ENC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#ENC_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "ENC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FAN_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "FAN"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FAN_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "FAN"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FAN_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "FAN"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FAN_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "FAN"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FAN_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "FAN"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FC_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "FC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FC_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "FC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FSD_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "FSD"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#FSD_4_3": {
      "filter_actions": 9,
      "category": 4,
      "severity": 3,
      "subcategory": "FSD"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#HWC_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "HWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#HWC_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "HWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#HWC_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "HWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#IOID_5_2": {
      "filter_actions": 9,
      "category": 5,
      "severity": 2,
      "subcategory": "IOID"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#IOID_5_3": {
      "filter_actions": 9,
      "category": 5,
      "severity": 3,
      "subcategory": "IOID"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#IOV_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "IOV"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#IPA_5_3": {
      "filter_actions": 9,
      "category": 5,
      "severity": 3,
      "subcategory": "IPA"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#JCP_5_3": {
      "filter_actions": 9,
      "category": 5,
      "severity": 3,
      "subcategory": "JCP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#LIC_4_1": {
      "filter_actions": 9,
      "category": 4,
      "severity": 1,
      "subcategory": "LIC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#LIC_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "LIC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#LIC_4_3": {
      "filter_actions": 9,
      "category": 4,
      "severity": 3,
      "subcategory": "LIC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#LNK_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "LNK"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#LNK_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "LNK"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#LNK_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "LNK"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#MEM_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "MEM"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#MEM_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "MEM"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#MEM_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "MEM"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#NIC_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "NIC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#NIC_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "NIC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#OSE_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "OSE"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PCI_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "PCI"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PCI_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "PCI"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PCI_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "PCI"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PCI_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "PCI"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PCI_5_3": {
      "filter_actions": 9,
      "category": 5,
      "severity": 3,
      "subcategory": "PCI"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PDR_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "PDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PDR_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "PDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PDR_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "PDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PDR_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "PDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PDR_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "PDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PDR_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "PDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PFM_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "PFM"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PST_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "PST"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSUA_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "PSUA"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_4_1": {
      "filter_actions": 9,
      "category": 4,
      "severity": 1,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PSU_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "PSU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PWR_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "PWR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PWR_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "PWR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PWR_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "PWR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PWR_4_1": {
      "filter_actions": 9,
      "category": 4,
      "severity": 1,
      "subcategory": "PWR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PWR_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "PWR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#PWR_4_3": {
      "filter_actions": 9,
      "category": 4,
      "severity": 3,
      "subcategory": "PWR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RAC_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "RAC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RDU_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "RDU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RDU_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "RDU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RDU_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "RDU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RED_3_3": {
      "filter_actions": 9,
      "category": 3,
      "severity": 3,
      "subcategory": "RED"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RFLA_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "RFLA"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RFL_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "RFL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RFL_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "RFL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RFL_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "RFL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RRDU_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "RRDU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RRDU_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "RRDU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#RRDU_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "RRDU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEC_5_2": {
      "filter_actions": 9,
      "category": 5,
      "severity": 2,
      "subcategory": "SEC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEL_1_1": {
      "filter_actions": 11,
      "category": 1,
      "severity": 1,
      "subcategory": "SEL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEL_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "SEL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SEL_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "SEL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SSD_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "SSD"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#STOR_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "STOR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#STOR_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "STOR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#STOR_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "STOR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWC_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "SWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWC_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "SWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWC_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "SWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWC_5_1": {
      "filter_actions": 9,
      "category": 5,
      "severity": 1,
      "subcategory": "SWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWC_5_2": {
      "filter_actions": 9,
      "category": 5,
      "severity": 2,
      "subcategory": "SWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWC_5_3": {
      "filter_actions": 9,
      "category": 5,
      "severity": 3,
      "subcategory": "SWC"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SWU_3_2": {
      "filter_actions": 9,
      "category": 3,
      "severity": 2,
      "subcategory": "SWU"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SYS_1_1": {
      "filter_actions": 11,
      "category": 1,
      "severity": 1,
      "subcategory": "SYS"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#SYS_4_3": {
      "filter_actions": 9,
      "category": 4,
      "severity": 3,
      "subcategory": "SYS"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMPS_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "TMPS"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMPS_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "TMPS"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_4_1": {
      "filter_actions": 9,
      "category": 4,
      "severity": 1,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#TMP_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "TMP"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#UEFI_1_1": {
      "filter_actions": 1,
      "category": 1,
      "severity": 1,
      "subcategory": "UEFI"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#USR_4_2": {
      "filter_actions": 9,
      "category": 4,
      "severity": 2,
      "subcategory": "USR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VDR_2_1": {
      "filter_actions": 9,
      "category": 2,
      "severity": 1,
      "subcategory": "VDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VDR_2_2": {
      "filter_actions": 9,
      "category": 2,
      "severity": 2,
      "subcategory": "VDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VDR_2_3": {
      "filter_actions": 9,
      "category": 2,
      "severity": 3,
      "subcategory": "VDR"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VFLA_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "VFLA"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VFL_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "VFL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VFL_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "VFL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VFL_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "VFL"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VLT_1_1": {
      "filter_actions": 9,
      "category": 1,
      "severity": 1,
      "subcategory": "VLT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VLT_1_2": {
      "filter_actions": 9,
      "category": 1,
      "severity": 2,
      "subcategory": "VLT"
    },
    "iDRAC.Embedded.1#RACEvtFilterCfgRoot#VLT_1_3": {
      "filter_actions": 9,
      "category": 1,
      "severity": 3,
      "subcategory": "VLT"
    }
  }
  
    method = 'PUT'
    endpoint = module.params['idrac_ip']
    url = 'https://' + endpoint + '/sysmgmt/2012/server/eventpolicy'
    headers = {
        'Content-Type':'application/json',
        'Accept':'application/json',
        'XSRF-TOKEN': idrac_token,
        'Cookie': idrac_cookie
    }

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    response = requests.put(url, data=json.dumps(body), headers=headers, verify=False)

    if response.status_code != 200:
        idrac_logout(module, idrac_cookie, idrac_token)
        module.fail_json(msg="Failed to enable SNMP event alerts", info=response.text)
    
    return response

def run_module():
    module = AnsibleModule(
        argument_spec = dict(
            idrac_ip             = dict(required=True),
            idrac_user           = dict(required=True),
            idrac_password       = dict(required=True, no_log=True),
            validate_certs       = dict(required=False, type="bool", default=False)
        ),
        supports_check_mode = False
    )
    
    result = {}
    
    # Get iDRAC token
    login_info = idrac_login(module)

    if login_info['status'] != 201:
        module.fail_json(msg="Failed to get iDRAC token", info=login_info)

    idrac_cookie = login_info['set-cookie']
    idrac_token = login_info['xsrf-token']

    response = set_snmp_string(module, idrac_cookie, idrac_token)
    result['status_code'] = response.status_code
    result['changed'] = True
    result['status'] = "All Events Enable For SNMP Alerts"

    # logout iDRAC Session
    idrac_logout(module, idrac_cookie, idrac_token)
    
    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()

