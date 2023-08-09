#!/usr/bin/python
#
# Copyright (c) 2020-2022 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Allen Robel"

DOCUMENTATION = """
---
module: dcnm_easy_fabric
short_description: Create VXLAN/EVPN Fabrics.
version_added: "0.9.0"
description:
    - "Create VXLAN/EVPN Fabrics."
author: Allen Robel
options:
  state:
    description:
    - The state of DCNM after module completion.
    - I(merged) and I(query) are the only states supported.
    type: str
    choices:
      - merged
      - query
    default: merged
  config:
    description:
    - A dictionary of fabric configurations
    type: list
    elements: dict
    suboptions:
      aaa_remote_ip_enabled:
        description:
        - Enable (True) or disable (False) AAA remote IP
        type: bool
        required: false
        default: False
      bgp_as:
        description:
        - The fabric BGP Autonomous System number
        type: str
        required: true
      fabric_name:
        description:
        - The name of the fabric
        type: str
        required: true
      pm_enable:
        description:
        - Enable (True) or disable (False) fabric performance monitoring
        type: bool
        required: false
        default: False
      replication_mode:
        description:
        - Replication Mode for BUM Traffic
        type: str
        required: False
        choices: ["Ingress", "Multicast"]
        default: "Multicast"
"""

EXAMPLES = """
# This module supports the following states:
#
# Merged:
#   Fabric defined in the playbook will be created.
#
# Query:
#   Returns the current DCNM state for the fabric.


# The following will create fabric my-fabric
- name: Create fabric
  cisco.dcnm.dcnm_fabric:
    state: merged
    config:
    -   fabric_name: my-fabric
        bgp_as: 100

"""

import copy
import json
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send,
    validate_list_of_dicts,
    dcnm_version_supported,
    get_fabric_details,
    get_fabric_inventory_details,
)


class DcnmFabric:
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.fabric = 'my_fabric'
        self.fd = None
        self.config = module.params.get("config")
        if not isinstance(self.config, list):
            msg = f"expected list type for self.config. got {type(self.config).__name__}"
            self.module.fail_json(msg=msg)

        self.log_msg(f"__init__ self.config {self.config}")
        self.check_mode = False
        self.validated = []
        self.have_create = []
        self.want_create = []
        self.diff_create = []
        self.diff_save = {}
        self.query = []
        self.nd_prefix = "/appcenter/cisco/ndfc/api/v1/lan-fabric"

        self.result = dict(changed=False, diff=[], response=[])

        self.controller_version = dcnm_version_supported(self.module)
        self.fabric_details = {}
        self.inventory_data = {}
        self.mandatory_keys = {"fabric_name", "bgp_as"}
        for item in self.config:
            if not self.mandatory_keys.issubset(item):
                msg = f"missing mandatory keys in {item}. "
                msg += f"expected {self.mandatory_keys}"
                self.module.fail_json(msg=msg)
            fabric = item["fabric_name"]
            self.fabric_details[fabric] = get_fabric_details(self.module, fabric)
            self.inventory_data[fabric] = get_fabric_inventory_details(
                self.module, fabric
            )
        self.log_msg(f"fabric_details: {self.fabric_details}")
        self.log_msg(f"inventory_data: {self.inventory_data}")
        self.nd = True if self.controller_version >= 12 else False

    def update_create_params(self, inv):
        return inv

    def get_have(self):
        self.log_msg(msg=f'get_have(): entered. self.fabric_details {self.fabric_details}')

        method = "GET"
        for fabric in self.fabric_details:
            path = f"/rest/control/fabrics/{fabric}"
            if self.nd:
                path = self.nd_prefix + path
            fabric_info = dcnm_send(self.module, method, path)
            self.log_msg(f'get_have(): fabric_info {fabric_info}')
            missing_fabric, not_ok = self.handle_response(fabric_info, "query_dcnm")

            if missing_fabric is False and not_ok is True:
                msg = f"get_have(): returning: missing_fabric {missing_fabric}, not_ok {not_ok}"
                self.log_msg(msg=msg)
                return
            msg = f"get_have(): Fabric {fabric} already present on DCNM"
            self.module.fail_json(msg=msg)

    def get_want(self):
        self.log_msg(msg=f'get_want(): entered. self.validated {self.validated}')
        want_create = []

        # if not self.config:
        #     return

        for inv in self.validated:
            self.log_msg(msg=f'inv {inv}')
            want_create.append(self.update_create_params(inv))
        self.log_msg(msg=f'get_want(): want_create {want_create}')

        if not want_create:
            return

        self.want_create = want_create


    def get_diff_merge(self):
        self.log_msg(msg=f'get_diff_merge(): entered. self.want_create {self.want_create}')

        diff_create = []

        for want_c in self.want_create:
            found = False
            for have_c in self.have_create:
                if want_c["fabric_name"] == have_c["fabric_name"]:
                    found = True
            if not found:
                diff_create.append(want_c)

        self.diff_create = diff_create
        self.log_msg(msg=f'get_diff_merge(): self.diff_create {self.diff_create}')

    def validate_input(self):
        """Parse the playbook values, validate to param specs."""

        state = self.params["state"]

        if state != "merged":
            msg = f"We only support merged state. Got state {state}"
            self.module.fail_json(msg=msg)

        if state == "merged":
            inv_spec = dict(
                aaa_remote_ip_enabled=dict(required=False, type="bool", default=False),
                fabric_name=dict(required=True, type="str"),
                bgp_as=dict(required=True, type="str"),
                pm_enable=dict(required=False, type="bool", default=False),
                replication_mode=dict(
                    required=False,
                    type="str",
                    default="Multicast",
                    choices=["Ingress", "Multicast"],
                ),
            )

            msg = None
            if self.config:
                self.log_msg(f"validate_input(): self.config {self.config}")
                for inv in self.config:
                    if "fabric_name" not in inv:
                        msg = "fabric_name is mandatory"
                        break
                    if "bgp_as" not in inv:
                        msg = "bgp_as is mandatory"
                        break
                    # if msg:
                    #     self.module.fail_json(msg=msg)
            else:
                if state == "merged":
                    msg = f"config: element is mandatory for state {state}"
            if msg:
                self.module.fail_json(msg=msg)

            valid_inv, invalid_params = validate_list_of_dicts(
                self.config, inv_spec, self.module
            )
            for inv in valid_inv:
                self.validated.append(inv)

            if invalid_params:
                inv_params = "\n".join(invalid_params)
                msg = f"Invalid parameters in playbook: {inv_params}"
                self.module.fail_json(msg=msg)

    def log_msg(self, msg):

        if self.fd is None:
            self.fd = open("/tmp/dcnm_easy_fabric.log", "a+")
        if self.fd is not None:
            self.fd.write(msg)
            self.fd.write("\n")
            self.fd.flush()

    def build_fabric_fabric_nv_pairs_default(self):
        self._fabric_nv_pairs_default = {}
        self._fabric_nv_pairs_default["AAA_REMOTE_IP_ENABLED"] = False
        self._fabric_nv_pairs_default["AAA_SERVER_CONF"] = ""
        self._fabric_nv_pairs_default["ACTIVE_MIGRATION"] = False
        self._fabric_nv_pairs_default["ADVERTISE_PIP_BGP"] = False
        self._fabric_nv_pairs_default["AGENT_INTF"] = "eth0"
        self._fabric_nv_pairs_default["ANYCAST_BGW_ADVERTISE_PIP"] = False
        self._fabric_nv_pairs_default["ANYCAST_GW_MAC"] = "2020.0000.00aa"
        self._fabric_nv_pairs_default["ANYCAST_LB_ID"] = ""
        self._fabric_nv_pairs_default["ANYCAST_RP_IP_RANGE"] = "10.254.254.0/24"
        self._fabric_nv_pairs_default["ANYCAST_RP_IP_RANGE_INTERNAL"] = ""
        self._fabric_nv_pairs_default["AUTO_SYMMETRIC_DEFAULT_VRF"] = False
        self._fabric_nv_pairs_default["AUTO_SYMMETRIC_VRF_LITE"] = False
        self._fabric_nv_pairs_default["AUTO_VRFLITE_IFC_DEFAULT_VRF"] = False
        self._fabric_nv_pairs_default["BFD_AUTH_ENABLE"] = False
        self._fabric_nv_pairs_default["BFD_AUTH_KEY"] = ""
        self._fabric_nv_pairs_default["BFD_AUTH_KEY_ID"] = ""
        self._fabric_nv_pairs_default["BFD_ENABLE"] = False
        self._fabric_nv_pairs_default["BFD_IBGP_ENABLE"] = False
        self._fabric_nv_pairs_default["BFD_ISIS_ENABLE"] = False
        self._fabric_nv_pairs_default["BFD_OSPF_ENABLE"] = False
        self._fabric_nv_pairs_default["BFD_PIM_ENABLE"] = False
        self._fabric_nv_pairs_default["BGP_AS"] = "1"
        self._fabric_nv_pairs_default["BGP_AS_PREV"] = ""
        self._fabric_nv_pairs_default["BGP_AUTH_ENABLE"] = False
        self._fabric_nv_pairs_default["BGP_AUTH_KEY"] = ""
        self._fabric_nv_pairs_default["BGP_AUTH_KEY_TYPE"] = ""
        self._fabric_nv_pairs_default["BGP_LB_ID"] = "0"
        self._fabric_nv_pairs_default["BOOTSTRAP_CONF"] = ""
        self._fabric_nv_pairs_default["BOOTSTRAP_ENABLE"] = False
        self._fabric_nv_pairs_default["BOOTSTRAP_ENABLE_PREV"] = False
        self._fabric_nv_pairs_default["BOOTSTRAP_MULTISUBNET"] = ""
        self._fabric_nv_pairs_default["BOOTSTRAP_MULTISUBNET_INTERNAL"] = ""
        self._fabric_nv_pairs_default["BRFIELD_DEBUG_FLAG"] = "Disable"
        self._fabric_nv_pairs_default[
            "BROWNFIELD_NETWORK_NAME_FORMAT"
        ] = "Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$"
        key = "BROWNFIELD_SKIP_OVERLAY_NETWORK_ATTACHMENTS"
        self._fabric_nv_pairs_default[key] = False
        self._fabric_nv_pairs_default["CDP_ENABLE"] = False
        self._fabric_nv_pairs_default["COPP_POLICY"] = "strict"
        self._fabric_nv_pairs_default["DCI_SUBNET_RANGE"] = "10.33.0.0/16"
        self._fabric_nv_pairs_default["DCI_SUBNET_TARGET_MASK"] = "30"
        self._fabric_nv_pairs_default["DEAFULT_QUEUING_POLICY_CLOUDSCALE"] = ""
        self._fabric_nv_pairs_default["DEAFULT_QUEUING_POLICY_OTHER"] = ""
        self._fabric_nv_pairs_default["DEAFULT_QUEUING_POLICY_R_SERIES"] = ""
        self._fabric_nv_pairs_default["DEFAULT_VRF_REDIS_BGP_RMAP"] = ""
        self._fabric_nv_pairs_default["DEPLOYMENT_FREEZE"] = False
        self._fabric_nv_pairs_default["DHCP_ENABLE"] = False
        self._fabric_nv_pairs_default["DHCP_END"] = ""
        self._fabric_nv_pairs_default["DHCP_END_INTERNAL"] = ""
        self._fabric_nv_pairs_default["DHCP_IPV6_ENABLE"] = ""
        self._fabric_nv_pairs_default["DHCP_IPV6_ENABLE_INTERNAL"] = ""
        self._fabric_nv_pairs_default["DHCP_START"] = ""
        self._fabric_nv_pairs_default["DHCP_START_INTERNAL"] = ""
        self._fabric_nv_pairs_default["DNS_SERVER_IP_LIST"] = ""
        self._fabric_nv_pairs_default["DNS_SERVER_VRF"] = ""
        self._fabric_nv_pairs_default["ENABLE_AAA"] = False
        self._fabric_nv_pairs_default["ENABLE_AGENT"] = False
        self._fabric_nv_pairs_default["ENABLE_DEFAULT_QUEUING_POLICY"] = False
        self._fabric_nv_pairs_default["ENABLE_EVPN"] = True
        self._fabric_nv_pairs_default["ENABLE_FABRIC_VPC_DOMAIN_ID"] = False
        self._fabric_nv_pairs_default["ENABLE_FABRIC_VPC_DOMAIN_ID_PREV"] = ""
        self._fabric_nv_pairs_default["ENABLE_MACSEC"] = False
        self._fabric_nv_pairs_default["ENABLE_NETFLOW"] = False
        self._fabric_nv_pairs_default["ENABLE_NETFLOW_PREV"] = ""
        self._fabric_nv_pairs_default["ENABLE_NGOAM"] = True
        self._fabric_nv_pairs_default["ENABLE_NXAPI"] = True
        self._fabric_nv_pairs_default["ENABLE_NXAPI_HTTP"] = True
        self._fabric_nv_pairs_default["ENABLE_PBR"] = False
        self._fabric_nv_pairs_default["ENABLE_PVLAN"] = False
        self._fabric_nv_pairs_default["ENABLE_PVLAN_PREV"] = ""
        self._fabric_nv_pairs_default["ENABLE_TENANT_DHCP"] = True
        self._fabric_nv_pairs_default["ENABLE_TRM"] = False
        self._fabric_nv_pairs_default["ENABLE_VPC_PEER_LINK_NATIVE_VLAN"] = False
        self._fabric_nv_pairs_default["EXTRA_CONF_INTRA_LINKS"] = ""
        self._fabric_nv_pairs_default["EXTRA_CONF_LEAF"] = ""
        self._fabric_nv_pairs_default["EXTRA_CONF_SPINE"] = ""
        self._fabric_nv_pairs_default["EXTRA_CONF_TOR"] = ""
        self._fabric_nv_pairs_default["FABRIC_INTERFACE_TYPE"] = "p2p"
        self._fabric_nv_pairs_default["FABRIC_MTU"] = "9216"
        self._fabric_nv_pairs_default["FABRIC_MTU_PREV"] = "9216"
        self._fabric_nv_pairs_default["FABRIC_NAME"] = "easy-fabric"
        self._fabric_nv_pairs_default["FABRIC_TYPE"] = "Switch_Fabric"
        self._fabric_nv_pairs_default["FABRIC_VPC_DOMAIN_ID"] = ""
        self._fabric_nv_pairs_default["FABRIC_VPC_DOMAIN_ID_PREV"] = ""
        self._fabric_nv_pairs_default["FABRIC_VPC_QOS"] = False
        self._fabric_nv_pairs_default["FABRIC_VPC_QOS_POLICY_NAME"] = ""
        self._fabric_nv_pairs_default["FEATURE_PTP"] = False
        self._fabric_nv_pairs_default["FEATURE_PTP_INTERNAL"] = False
        self._fabric_nv_pairs_default["FF"] = "Easy_Fabric"
        self._fabric_nv_pairs_default["GRFIELD_DEBUG_FLAG"] = "Disable"
        self._fabric_nv_pairs_default["HD_TIME"] = "180"
        self._fabric_nv_pairs_default["HOST_INTF_ADMIN_STATE"] = True
        self._fabric_nv_pairs_default["IBGP_PEER_TEMPLATE"] = ""
        self._fabric_nv_pairs_default["IBGP_PEER_TEMPLATE_LEAF"] = ""
        self._fabric_nv_pairs_default["INBAND_DHCP_SERVERS"] = ""
        self._fabric_nv_pairs_default["INBAND_MGMT"] = False
        self._fabric_nv_pairs_default["INBAND_MGMT_PREV"] = False
        self._fabric_nv_pairs_default["ISIS_AUTH_ENABLE"] = False
        self._fabric_nv_pairs_default["ISIS_AUTH_KEY"] = ""
        self._fabric_nv_pairs_default["ISIS_AUTH_KEYCHAIN_KEY_ID"] = ""
        self._fabric_nv_pairs_default["ISIS_AUTH_KEYCHAIN_NAME"] = ""
        self._fabric_nv_pairs_default["ISIS_LEVEL"] = ""
        self._fabric_nv_pairs_default["ISIS_OVERLOAD_ELAPSE_TIME"] = ""
        self._fabric_nv_pairs_default["ISIS_OVERLOAD_ENABLE"] = False
        self._fabric_nv_pairs_default["ISIS_P2P_ENABLE"] = False
        self._fabric_nv_pairs_default["L2_HOST_INTF_MTU"] = "9216"
        self._fabric_nv_pairs_default["L2_HOST_INTF_MTU_PREV"] = "9216"
        self._fabric_nv_pairs_default["L2_SEGMENT_ID_RANGE"] = "30000-49000"
        self._fabric_nv_pairs_default["L3VNI_MCAST_GROUP"] = ""
        self._fabric_nv_pairs_default["L3_PARTITION_ID_RANGE"] = "50000-59000"
        self._fabric_nv_pairs_default["LINK_STATE_ROUTING"] = "ospf"
        self._fabric_nv_pairs_default["LINK_STATE_ROUTING_TAG"] = "UNDERLAY"
        self._fabric_nv_pairs_default["LINK_STATE_ROUTING_TAG_PREV"] = ""
        self._fabric_nv_pairs_default["LOOPBACK0_IPV6_RANGE"] = ""
        self._fabric_nv_pairs_default["LOOPBACK0_IP_RANGE"] = "10.2.0.0/22"
        self._fabric_nv_pairs_default["LOOPBACK1_IPV6_RANGE"] = ""
        self._fabric_nv_pairs_default["LOOPBACK1_IP_RANGE"] = "10.3.0.0/22"
        self._fabric_nv_pairs_default["MACSEC_ALGORITHM"] = ""
        self._fabric_nv_pairs_default["MACSEC_CIPHER_SUITE"] = ""
        self._fabric_nv_pairs_default["MACSEC_FALLBACK_ALGORITHM"] = ""
        self._fabric_nv_pairs_default["MACSEC_FALLBACK_KEY_STRING"] = ""
        self._fabric_nv_pairs_default["MACSEC_KEY_STRING"] = ""
        self._fabric_nv_pairs_default["MACSEC_REPORT_TIMER"] = ""
        self._fabric_nv_pairs_default["MGMT_GW"] = ""
        self._fabric_nv_pairs_default["MGMT_GW_INTERNAL"] = ""
        self._fabric_nv_pairs_default["MGMT_PREFIX"] = ""
        self._fabric_nv_pairs_default["MGMT_PREFIX_INTERNAL"] = ""
        self._fabric_nv_pairs_default["MGMT_V6PREFIX"] = "64"
        self._fabric_nv_pairs_default["MGMT_V6PREFIX_INTERNAL"] = ""
        self._fabric_nv_pairs_default["MPLS_HANDOFF"] = False
        self._fabric_nv_pairs_default["MPLS_LB_ID"] = ""
        self._fabric_nv_pairs_default["MPLS_LOOPBACK_IP_RANGE"] = ""
        self._fabric_nv_pairs_default["MSO_CONNECTIVITY_DEPLOYED"] = ""
        self._fabric_nv_pairs_default["MSO_CONTROLER_ID"] = ""
        self._fabric_nv_pairs_default["MSO_SITE_GROUP_NAME"] = ""
        self._fabric_nv_pairs_default["MSO_SITE_ID"] = ""
        self._fabric_nv_pairs_default["MST_INSTANCE_RANGE"] = ""
        self._fabric_nv_pairs_default["MULTICAST_GROUP_SUBNET"] = "239.1.1.0/25"
        self._fabric_nv_pairs_default["NETFLOW_EXPORTER_LIST"] = ""
        self._fabric_nv_pairs_default["NETFLOW_MONITOR_LIST"] = ""
        self._fabric_nv_pairs_default["NETFLOW_RECORD_LIST"] = ""
        self._fabric_nv_pairs_default["NETWORK_VLAN_RANGE"] = "2300-2999"
        self._fabric_nv_pairs_default["NTP_SERVER_IP_LIST"] = ""
        self._fabric_nv_pairs_default["NTP_SERVER_VRF"] = ""
        self._fabric_nv_pairs_default["NVE_LB_ID"] = "1"
        self._fabric_nv_pairs_default["OSPF_AREA_ID"] = "0.0.0.0"
        self._fabric_nv_pairs_default["OSPF_AUTH_ENABLE"] = False
        self._fabric_nv_pairs_default["OSPF_AUTH_KEY"] = ""
        self._fabric_nv_pairs_default["OSPF_AUTH_KEY_ID"] = ""
        self._fabric_nv_pairs_default["OVERLAY_MODE"] = "config-profile"
        self._fabric_nv_pairs_default["OVERLAY_MODE_PREV"] = ""
        self._fabric_nv_pairs_default["PHANTOM_RP_LB_ID1"] = ""
        self._fabric_nv_pairs_default["PHANTOM_RP_LB_ID2"] = ""
        self._fabric_nv_pairs_default["PHANTOM_RP_LB_ID3"] = ""
        self._fabric_nv_pairs_default["PHANTOM_RP_LB_ID4"] = ""
        self._fabric_nv_pairs_default["PIM_HELLO_AUTH_ENABLE"] = False
        self._fabric_nv_pairs_default["PIM_HELLO_AUTH_KEY"] = ""
        self._fabric_nv_pairs_default["PM_ENABLE"] = False
        self._fabric_nv_pairs_default["PM_ENABLE_PREV"] = False
        self._fabric_nv_pairs_default["POWER_REDUNDANCY_MODE"] = "ps-redundant"
        self._fabric_nv_pairs_default["PREMSO_PARENT_FABRIC"] = ""
        self._fabric_nv_pairs_default["PTP_DOMAIN_ID"] = ""
        self._fabric_nv_pairs_default["PTP_LB_ID"] = ""
        self._fabric_nv_pairs_default["REPLICATION_MODE"] = "Multicast"
        self._fabric_nv_pairs_default["ROUTER_ID_RANGE"] = ""
        self._fabric_nv_pairs_default["ROUTE_MAP_SEQUENCE_NUMBER_RANGE"] = "1-65534"
        self._fabric_nv_pairs_default["RP_COUNT"] = "2"
        self._fabric_nv_pairs_default["RP_LB_ID"] = "254"
        self._fabric_nv_pairs_default["RP_MODE"] = "asm"
        self._fabric_nv_pairs_default["RR_COUNT"] = "2"
        self._fabric_nv_pairs_default["SEED_SWITCH_CORE_INTERFACES"] = ""
        self._fabric_nv_pairs_default["SERVICE_NETWORK_VLAN_RANGE"] = "3000-3199"
        self._fabric_nv_pairs_default["SITE_ID"] = ""
        self._fabric_nv_pairs_default["SNMP_SERVER_HOST_TRAP"] = True
        self._fabric_nv_pairs_default["SPINE_COUNT"] = "0"
        self._fabric_nv_pairs_default["SPINE_SWITCH_CORE_INTERFACES"] = ""
        self._fabric_nv_pairs_default["SSPINE_ADD_DEL_DEBUG_FLAG"] = "Disable"
        self._fabric_nv_pairs_default["SSPINE_COUNT"] = "0"
        self._fabric_nv_pairs_default["STATIC_UNDERLAY_IP_ALLOC"] = False
        self._fabric_nv_pairs_default["STP_BRIDGE_PRIORITY"] = ""
        self._fabric_nv_pairs_default["STP_ROOT_OPTION"] = "unmanaged"
        self._fabric_nv_pairs_default["STP_VLAN_RANGE"] = ""
        self._fabric_nv_pairs_default["STRICT_CC_MODE"] = False
        self._fabric_nv_pairs_default["SUBINTERFACE_RANGE"] = "2-511"
        self._fabric_nv_pairs_default["SUBNET_RANGE"] = "10.4.0.0/16"
        self._fabric_nv_pairs_default["SUBNET_TARGET_MASK"] = "30"
        self._fabric_nv_pairs_default["SYSLOG_SERVER_IP_LIST"] = ""
        self._fabric_nv_pairs_default["SYSLOG_SERVER_VRF"] = ""
        self._fabric_nv_pairs_default["SYSLOG_SEV"] = ""
        self._fabric_nv_pairs_default["TCAM_ALLOCATION"] = True
        self._fabric_nv_pairs_default["UNDERLAY_IS_V6"] = False
        self._fabric_nv_pairs_default["UNNUM_BOOTSTRAP_LB_ID"] = ""
        self._fabric_nv_pairs_default["UNNUM_DHCP_END"] = ""
        self._fabric_nv_pairs_default["UNNUM_DHCP_END_INTERNAL"] = ""
        self._fabric_nv_pairs_default["UNNUM_DHCP_START"] = ""
        self._fabric_nv_pairs_default["UNNUM_DHCP_START_INTERNAL"] = ""
        self._fabric_nv_pairs_default["USE_LINK_LOCAL"] = False
        self._fabric_nv_pairs_default["V6_SUBNET_RANGE"] = ""
        self._fabric_nv_pairs_default["V6_SUBNET_TARGET_MASK"] = ""
        self._fabric_nv_pairs_default["VPC_AUTO_RECOVERY_TIME"] = "360"
        self._fabric_nv_pairs_default["VPC_DELAY_RESTORE"] = "150"
        self._fabric_nv_pairs_default["VPC_DELAY_RESTORE_TIME"] = "60"
        self._fabric_nv_pairs_default["VPC_DOMAIN_ID_RANGE"] = "1-1000"
        self._fabric_nv_pairs_default["VPC_ENABLE_IPv6_ND_SYNC"] = True
        self._fabric_nv_pairs_default["VPC_PEER_KEEP_ALIVE_OPTION"] = "management"
        self._fabric_nv_pairs_default["VPC_PEER_LINK_PO"] = "500"
        self._fabric_nv_pairs_default["VPC_PEER_LINK_VLAN"] = "3600"
        self._fabric_nv_pairs_default["VRF_LITE_AUTOCONFIG"] = "Manual"
        self._fabric_nv_pairs_default["VRF_VLAN_RANGE"] = "2000-2299"
        self._fabric_nv_pairs_default["abstract_anycast_rp"] = "anycast_rp"
        self._fabric_nv_pairs_default["abstract_bgp"] = "base_bgp"
        value = "evpn_bgp_rr_neighbor"
        self._fabric_nv_pairs_default["abstract_bgp_neighbor"] = value
        self._fabric_nv_pairs_default["abstract_bgp_rr"] = "evpn_bgp_rr"
        self._fabric_nv_pairs_default["abstract_dhcp"] = "base_dhcp"
        self._fabric_nv_pairs_default[
            "abstract_extra_config_bootstrap"
        ] = "extra_config_bootstrap_11_1"
        value = "extra_config_leaf"
        self._fabric_nv_pairs_default["abstract_extra_config_leaf"] = value
        value = "extra_config_spine"
        self._fabric_nv_pairs_default["abstract_extra_config_spine"] = value
        value = "extra_config_tor"
        self._fabric_nv_pairs_default["abstract_extra_config_tor"] = value
        value = "base_feature_leaf_upg"
        self._fabric_nv_pairs_default["abstract_feature_leaf"] = value
        value = "base_feature_spine_upg"
        self._fabric_nv_pairs_default["abstract_feature_spine"] = value
        self._fabric_nv_pairs_default["abstract_isis"] = "base_isis_level2"
        self._fabric_nv_pairs_default["abstract_isis_interface"] = "isis_interface"
        self._fabric_nv_pairs_default[
            "abstract_loopback_interface"
        ] = "int_fabric_loopback_11_1"
        self._fabric_nv_pairs_default["abstract_multicast"] = "base_multicast_11_1"
        self._fabric_nv_pairs_default["abstract_ospf"] = "base_ospf"
        value = "ospf_interface_11_1"
        self._fabric_nv_pairs_default["abstract_ospf_interface"] = value
        self._fabric_nv_pairs_default["abstract_pim_interface"] = "pim_interface"
        self._fabric_nv_pairs_default["abstract_route_map"] = "route_map"
        self._fabric_nv_pairs_default["abstract_routed_host"] = "int_routed_host"
        self._fabric_nv_pairs_default["abstract_trunk_host"] = "int_trunk_host"
        value = "int_fabric_vlan_11_1"
        self._fabric_nv_pairs_default["abstract_vlan_interface"] = value
        self._fabric_nv_pairs_default["abstract_vpc_domain"] = "base_vpc_domain_11_1"
        value = "Default_Network_Universal"
        self._fabric_nv_pairs_default["default_network"] = value
        self._fabric_nv_pairs_default["default_pvlan_sec_network"] = ""
        self._fabric_nv_pairs_default["default_vrf"] = "Default_VRF_Universal"
        self._fabric_nv_pairs_default["enableRealTimeBackup"] = ""
        self._fabric_nv_pairs_default["enableScheduledBackup"] = ""
        self._fabric_nv_pairs_default[
            "network_extension_template"
        ] = "Default_Network_Extension_Universal"
        self._fabric_nv_pairs_default["scheduledTime"] = ""
        self._fabric_nv_pairs_default["temp_anycast_gateway"] = "anycast_gateway"
        self._fabric_nv_pairs_default["temp_vpc_domain_mgmt"] = "vpc_domain_mgmt"
        self._fabric_nv_pairs_default["temp_vpc_peer_link"] = "int_vpc_peer_link_po"
        self._fabric_nv_pairs_default[
            "vrf_extension_template"
        ] = "Default_VRF_Extension_Universal"

    def build_fabric_params_default(self):
        """
        Initialize default NDFC top-level parameters
        See also: _init_nv_pairs*
        """
        self._fabric_params_default = {}
        self._fabric_params_default["deviceType"] = "n9k"
        self._fabric_params_default["fabricTechnology"] = "VXLANFabric"
        self._fabric_params_default["fabricTechnologyFriendly"] = "VXLAN Fabric"
        self._fabric_params_default["fabricType"] = "Switch_Fabric"
        self._fabric_params_default["fabricTypeFriendly"] = "Switch Fabric"
        self._fabric_params_default[
            "networkExtensionTemplate"
        ] = "Default_Network_Extension_Universal"
        value = "Default_Network_Universal"
        self._fabric_params_default["networkTemplate"] = value
        self._fabric_params_default["provisionMode"] = "DCNMTopDown"
        self._fabric_params_default["replicationMode"] = "Multicast"
        self._fabric_params_default["siteId"] = ""
        self._fabric_params_default["templateName"] = "Easy_Fabric"
        self._fabric_params_default[
            "vrfExtensionTemplate"
        ] = "Default_VRF_Extension_Universal"
        self._fabric_params_default["vrfTemplate"] = "Default_VRF_Universal"

    def build_translatable_nv_pairs(self):
        """
        All parameters in the playbook are lowercase dunder, while
        NDFC nvPairs contains a mish-mash of styles, for example:
        - enableScheduledBackup
        - default_vrf
        - REPLICATION_MODE

        This method handles the most common case (uppercase dunder e.g. 
        REPLICATION_MODE) to build a set of playbook parameters that can
        be safely converted to uppercase dunder style.

        So far, all playbook-supported parameters are covered with this
        method. We can add methods to translate the other cases if/when
        they are needed.
        """
        self.translatable_nv_pairs = set()
        self.translatable_nv_pairs.add("aaa_remote_ip_enabled")
        self.translatable_nv_pairs.add("bgp_as")
        self.translatable_nv_pairs.add("fabric_name")
        self.translatable_nv_pairs.add("pm_enable")
        self.translatable_nv_pairs.add("replication_mode")

    def translate_to_ndfc_nv_pairs(self, params):
        """
        translate keys in params dict into what NDFC
        expects in nvPairs and return the translated
        params as a dict.
        """
        self.log_msg(f"translate_to_ndfc_nv_pairs params {params}")
        self.translated_nv_pairs = {}
        for param in self.translatable_nv_pairs:
            if param in params:
                self.translated_nv_pairs[param.upper()] = params[param]
        self.log_msg(f"translate_to_ndfc_nv_pairs {self.translated_nv_pairs}")

    def create_fabrics(self):


        method = "POST"
        path = f"/rest/control/fabrics"
        if self.nd:
            path = self.nd_prefix + path

        self.log_msg(f"create_fabrics() self.want_create {self.want_create}")
        for item in self.want_create:
            fabric = item["fabric_name"]
            bgp_as = item["bgp_as"]

            self.build_fabric_params_default()
            self.build_fabric_fabric_nv_pairs_default()
            self.build_translatable_nv_pairs()
            payload = self._fabric_params_default
            payload["fabricName"] = fabric
            payload["asn"] = bgp_as
            payload["nvPairs"] = self._fabric_nv_pairs_default
            self.translate_to_ndfc_nv_pairs(item)
            for key,value in self.translated_nv_pairs.items():
                self.log_msg(f"create_fabrics(): key {key}, value {value}")
                payload["nvPairs"][key] = value

            self.log_msg(f"create_fabrics() dcnm_send() path {path}")
            self.log_msg(f"create_fabrics() dcnm_send() data {json.dumps(payload)}")
            response = dcnm_send(self.module, method, path, data=json.dumps(payload))
            self.log_msg(f"create_fabrics() response {response}")
            fail, self.result["changed"] = self.handle_response(response, "create")
            self.log_msg(f"create_fabrics() fail {fail}, result {self.result['changed']}")

            if fail:
                self.log_msg(f"create_fabrics() calling self.failure with response {response}")
                self.failure(response)

    def handle_response(self, res, op):

        fail = False
        changed = True

        if op == "query_dcnm":
            # This if blocks handles responses to the query APIs against DCNM.
            # Basically all GET operations.
            if res.get("ERROR") == "Not Found" and res["RETURN_CODE"] == 404:
                return True, False
            if res["RETURN_CODE"] != 200 or res["MESSAGE"] != "OK":
                return False, True
            return False, False

        # Responses to all other operations POST and PUT are handled here.
        if res.get("MESSAGE") != "OK":
            fail = True
            changed = False
            return fail, changed
        if res.get("ERROR"):
            fail = True
            changed = False

        return fail, changed

    def failure(self, resp):

        res = copy.deepcopy(resp)

        if not resp.get("DATA"):
            data = copy.deepcopy(resp.get("DATA"))
            if data.get("stackTrace"):
                data.update(
                    {"stackTrace": "Stack trace is hidden, use '-vvvvv' to print it"}
                )
                res.update({"DATA": data})

        self.module.fail_json(msg=res)


def main():
    """main entry point for module execution"""

    element_spec = dict(
        config=dict(required=False, type="list", elements="dict"),
        state=dict(default="merged", choices=["merged"]),
    )

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)
    dcnm_fabric = DcnmFabric(module)
    dcnm_fabric.validate_input()
    dcnm_fabric.get_have()
    dcnm_fabric.get_want()

    if module.params["state"] == "merged":
        dcnm_fabric.get_diff_merge()

    if dcnm_fabric.diff_create:
        dcnm_fabric.result["changed"] = True
    else:
        module.exit_json(**dcnm_fabric.result)

    if module.check_mode:
        dcnm_fabric.result["changed"] = False
        module.exit_json(**dcnm_fabric.result)

    if dcnm_fabric.diff_create:
        dcnm_fabric.create_fabrics()


    module.exit_json(**dcnm_fabric.result)


if __name__ == "__main__":
    main()
