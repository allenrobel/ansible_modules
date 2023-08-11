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
      advertise_pip_bgp:
        description:
        - Enable (True) or disable (False) usage of Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes
        type: bool
        required: false
        default: False
      anycast_bgw_advertise_pip:
        description:
        - Enable (True) or disable (False) advertising Anycast Border Gateway PIP as VTEP. Effective after Recalculate Config on parent MSD fabric
        type: bool
        required: false
        default: False
      anycast_gw_mac:
        description:
        - Shared MAC address for all leafs (xx:xx:xx:xx:xx:xx, xxxx.xxxx.xxxx, etc)
        type: str
        required: false
        default: "2020.0000.00aa"
      anycast_lb_id:
        description:
        - Underlay Anycast Loopback Id
        type: int
        required: false
        default: ""
      anycast_rp_ip_range:
        description:
        - Anycast or Phantom RP IP Address Range
        type: str
        required: false
        default: 10.254.254.0/24
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
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send,
    validate_list_of_dicts,
    dcnm_version_supported,
    get_fabric_details,
    get_fabric_inventory_details,
)

def translate_mac_address(mac_addr):
    """
    Accept mac address with any (or no) punctuation
    and convert it into the dotted format that NDFC
    expects.

    Return mac address formatted for NDFC on success
    Return False on failure.
    """
    mac_addr = re.sub(r'[\W\s_]',"",mac_addr)
    if not re.search("^[A-Fa-f0-9]{12}$", mac_addr):
        return False
    return ''.join(
        (
            mac_addr[:4],
            ".",
            mac_addr[4:8],
            ".",
            mac_addr[8:]
        )
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

    @staticmethod
    def build_params_spec_for_merged_state():
            params_spec = {}
            params_spec.update(
                aaa_remote_ip_enabled=dict(
                    required=False,
                    type="bool",
                    default=False
                )
            )
            # TODO:6 active_migration
            # active_migration doesn't seem to be represented in
            # the NDFC EasyFabric GUI.  Add this param if we figure out
            # what it's used for and where in the GUI it's represented
            params_spec.update(
                advertise_pip_bgp=dict(
                    required=False,
                    type="bool",
                    default=False
                )
            )
            # TODO:6 agent_intf (add if needed)
            params_spec.update(
                anycast_bgw_advertise_pip=dict(
                    required=False,
                    type="bool",
                    default=False
                )
            )
            params_spec.update(
                anycast_gw_mac=dict(
                    required=False,
                    type="str",
                    default="2020.0000.00aa"
                )
            )
            params_spec.update(
                anycast_lb_id=dict(
                    required=False,
                    type="int",
                    range_min=0,
                    range_max=1023,
                    default=""
                )
            )
            params_spec.update(
                anycast_rp_ip_range=dict(
                    required=False,
                    type="ipv4_subnet",
                    default="10.254.254.0/24"
                )
            )
            params_spec.update(
                bgp_as=dict(
                    required=True,
                    type="str"
                )
            )
            params_spec.update(
                fabric_name=dict(
                    required=True,
                    type="str"
                )
            )
            params_spec.update(
                pm_enable=dict(
                    required=False,
                    type="bool",
                    default=False
                )
            )
            params_spec.update(
                replication_mode=dict(
                    required=False,
                    type="str",
                    default="Multicast",
                    choices=["Ingress", "Multicast"],
                )
            )
            return params_spec

    def verify_cfg_for_merged_state(self, cfg):
        """
        Verify the user's playbook parameters for an individual fabric
        configuration.  Whenever possible, throw the user a bone by
        converting values to NDFC's expectations. For example, NDFC's 
        REST API accepts mac addresses in any format (does not return
        an error), since the NDFC GUI validates that it is in the expected
        format, but the fabric will be in an errored state if the mac address
        sent via REST is any format other than dotted-quad format
        (xxxx.xxxx.xxxx). So, we convert all mac address formats to
        dotted-quad before passing them to NDFC.

        Fail if anything is not valid that we couldn't fix
        Return the validated cfg otherwise
        """
        self.log_msg(msg=f"validate_input_for_merged_state: cfg {cfg}")
        if "fabric_name" not in cfg:
            msg = "fabric_name is mandatory"
            self.module.fail_json(msg=msg)
        if "bgp_as" not in cfg:
            msg = "bgp_as is mandatory"
            self.module.fail_json(msg=msg)
        if "anycast_gw_mac" in cfg:
            result = translate_mac_address(cfg["anycast_gw_mac"])
            if result is False:
                msg = f"invalid anycast_gw_mac {cfg['anycast_gw_mac']}"
                self.module.fail_json(msg=msg)
            cfg["anycast_gw_mac"] = result
        return cfg

    def validate_input_for_merged_state(self):
        """
        Valid self.config contains appropriate values for merged state
        """
        params_spec = self.build_params_spec_for_merged_state()
        msg = None
        if not self.config:
            msg = "config: element is mandatory for state merged"
            self.module.fail_json(msg=msg)

        cfg_index = 0
        for cfg in self.config:
            self.config[cfg_index] = self.verify_cfg_for_merged_state(cfg)
            cfg_index += 1
        if msg:
            self.module.fail_json(msg=msg)

        valid_params, invalid_params = validate_list_of_dicts(
            self.config, params_spec, self.module
        )
        for param in valid_params:
            self.validated.append(param)

        if invalid_params:
            msg = f"Invalid parameters in playbook: "
            msg += f"{','.join(invalid_params)}"
            self.module.fail_json(msg=msg)

    def validate_input(self):
        """Parse the playbook values, validate the param specs."""

        state = self.params["state"]

        # TODO:2 remove this when we implement query state
        if state != "merged":
            msg = f"Only merged state is supported. Got state {state}"
            self.module.fail_json(msg=msg)

        if state == "merged":
            self.validate_input_for_merged_state()

    def log_msg(self, msg):
        if self.fd is None:
            self.fd = open("/tmp/dcnm_easy_fabric.log", "a+")
        if self.fd is not None:
            self.fd.write(msg)
            self.fd.write("\n")
            self.fd.flush()

    def build_default_nv_pairs(self):
        self._default_nv_pairs = {}
        self._default_nv_pairs["AAA_REMOTE_IP_ENABLED"] = False
        self._default_nv_pairs["AAA_SERVER_CONF"] = ""
        self._default_nv_pairs["ACTIVE_MIGRATION"] = False
        self._default_nv_pairs["ADVERTISE_PIP_BGP"] = False
        self._default_nv_pairs["AGENT_INTF"] = "eth0"
        self._default_nv_pairs["ANYCAST_BGW_ADVERTISE_PIP"] = False
        self._default_nv_pairs["ANYCAST_GW_MAC"] = "2020.0000.00aa"
        self._default_nv_pairs["ANYCAST_LB_ID"] = ""
        self._default_nv_pairs["ANYCAST_RP_IP_RANGE"] = "10.254.254.0/24"
        self._default_nv_pairs["ANYCAST_RP_IP_RANGE_INTERNAL"] = ""
        self._default_nv_pairs["AUTO_SYMMETRIC_DEFAULT_VRF"] = False
        self._default_nv_pairs["AUTO_SYMMETRIC_VRF_LITE"] = False
        self._default_nv_pairs["AUTO_VRFLITE_IFC_DEFAULT_VRF"] = False
        self._default_nv_pairs["BFD_AUTH_ENABLE"] = False
        self._default_nv_pairs["BFD_AUTH_KEY"] = ""
        self._default_nv_pairs["BFD_AUTH_KEY_ID"] = ""
        self._default_nv_pairs["BFD_ENABLE"] = False
        self._default_nv_pairs["BFD_IBGP_ENABLE"] = False
        self._default_nv_pairs["BFD_ISIS_ENABLE"] = False
        self._default_nv_pairs["BFD_OSPF_ENABLE"] = False
        self._default_nv_pairs["BFD_PIM_ENABLE"] = False
        self._default_nv_pairs["BGP_AS"] = "1"
        self._default_nv_pairs["BGP_AS_PREV"] = ""
        self._default_nv_pairs["BGP_AUTH_ENABLE"] = False
        self._default_nv_pairs["BGP_AUTH_KEY"] = ""
        self._default_nv_pairs["BGP_AUTH_KEY_TYPE"] = ""
        self._default_nv_pairs["BGP_LB_ID"] = "0"
        self._default_nv_pairs["BOOTSTRAP_CONF"] = ""
        self._default_nv_pairs["BOOTSTRAP_ENABLE"] = False
        self._default_nv_pairs["BOOTSTRAP_ENABLE_PREV"] = False
        self._default_nv_pairs["BOOTSTRAP_MULTISUBNET"] = ""
        self._default_nv_pairs["BOOTSTRAP_MULTISUBNET_INTERNAL"] = ""
        self._default_nv_pairs["BRFIELD_DEBUG_FLAG"] = "Disable"
        self._default_nv_pairs[
            "BROWNFIELD_NETWORK_NAME_FORMAT"
        ] = "Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$"
        key = "BROWNFIELD_SKIP_OVERLAY_NETWORK_ATTACHMENTS"
        self._default_nv_pairs[key] = False
        self._default_nv_pairs["CDP_ENABLE"] = False
        self._default_nv_pairs["COPP_POLICY"] = "strict"
        self._default_nv_pairs["DCI_SUBNET_RANGE"] = "10.33.0.0/16"
        self._default_nv_pairs["DCI_SUBNET_TARGET_MASK"] = "30"
        self._default_nv_pairs["DEAFULT_QUEUING_POLICY_CLOUDSCALE"] = ""
        self._default_nv_pairs["DEAFULT_QUEUING_POLICY_OTHER"] = ""
        self._default_nv_pairs["DEAFULT_QUEUING_POLICY_R_SERIES"] = ""
        self._default_nv_pairs["DEFAULT_VRF_REDIS_BGP_RMAP"] = ""
        self._default_nv_pairs["DEPLOYMENT_FREEZE"] = False
        self._default_nv_pairs["DHCP_ENABLE"] = False
        self._default_nv_pairs["DHCP_END"] = ""
        self._default_nv_pairs["DHCP_END_INTERNAL"] = ""
        self._default_nv_pairs["DHCP_IPV6_ENABLE"] = ""
        self._default_nv_pairs["DHCP_IPV6_ENABLE_INTERNAL"] = ""
        self._default_nv_pairs["DHCP_START"] = ""
        self._default_nv_pairs["DHCP_START_INTERNAL"] = ""
        self._default_nv_pairs["DNS_SERVER_IP_LIST"] = ""
        self._default_nv_pairs["DNS_SERVER_VRF"] = ""
        self._default_nv_pairs["ENABLE_AAA"] = False
        self._default_nv_pairs["ENABLE_AGENT"] = False
        self._default_nv_pairs["ENABLE_DEFAULT_QUEUING_POLICY"] = False
        self._default_nv_pairs["ENABLE_EVPN"] = True
        self._default_nv_pairs["ENABLE_FABRIC_VPC_DOMAIN_ID"] = False
        self._default_nv_pairs["ENABLE_FABRIC_VPC_DOMAIN_ID_PREV"] = ""
        self._default_nv_pairs["ENABLE_MACSEC"] = False
        self._default_nv_pairs["ENABLE_NETFLOW"] = False
        self._default_nv_pairs["ENABLE_NETFLOW_PREV"] = ""
        self._default_nv_pairs["ENABLE_NGOAM"] = True
        self._default_nv_pairs["ENABLE_NXAPI"] = True
        self._default_nv_pairs["ENABLE_NXAPI_HTTP"] = True
        self._default_nv_pairs["ENABLE_PBR"] = False
        self._default_nv_pairs["ENABLE_PVLAN"] = False
        self._default_nv_pairs["ENABLE_PVLAN_PREV"] = ""
        self._default_nv_pairs["ENABLE_TENANT_DHCP"] = True
        self._default_nv_pairs["ENABLE_TRM"] = False
        self._default_nv_pairs["ENABLE_VPC_PEER_LINK_NATIVE_VLAN"] = False
        self._default_nv_pairs["EXTRA_CONF_INTRA_LINKS"] = ""
        self._default_nv_pairs["EXTRA_CONF_LEAF"] = ""
        self._default_nv_pairs["EXTRA_CONF_SPINE"] = ""
        self._default_nv_pairs["EXTRA_CONF_TOR"] = ""
        self._default_nv_pairs["FABRIC_INTERFACE_TYPE"] = "p2p"
        self._default_nv_pairs["FABRIC_MTU"] = "9216"
        self._default_nv_pairs["FABRIC_MTU_PREV"] = "9216"
        self._default_nv_pairs["FABRIC_NAME"] = "easy-fabric"
        self._default_nv_pairs["FABRIC_TYPE"] = "Switch_Fabric"
        self._default_nv_pairs["FABRIC_VPC_DOMAIN_ID"] = ""
        self._default_nv_pairs["FABRIC_VPC_DOMAIN_ID_PREV"] = ""
        self._default_nv_pairs["FABRIC_VPC_QOS"] = False
        self._default_nv_pairs["FABRIC_VPC_QOS_POLICY_NAME"] = ""
        self._default_nv_pairs["FEATURE_PTP"] = False
        self._default_nv_pairs["FEATURE_PTP_INTERNAL"] = False
        self._default_nv_pairs["FF"] = "Easy_Fabric"
        self._default_nv_pairs["GRFIELD_DEBUG_FLAG"] = "Disable"
        self._default_nv_pairs["HD_TIME"] = "180"
        self._default_nv_pairs["HOST_INTF_ADMIN_STATE"] = True
        self._default_nv_pairs["IBGP_PEER_TEMPLATE"] = ""
        self._default_nv_pairs["IBGP_PEER_TEMPLATE_LEAF"] = ""
        self._default_nv_pairs["INBAND_DHCP_SERVERS"] = ""
        self._default_nv_pairs["INBAND_MGMT"] = False
        self._default_nv_pairs["INBAND_MGMT_PREV"] = False
        self._default_nv_pairs["ISIS_AUTH_ENABLE"] = False
        self._default_nv_pairs["ISIS_AUTH_KEY"] = ""
        self._default_nv_pairs["ISIS_AUTH_KEYCHAIN_KEY_ID"] = ""
        self._default_nv_pairs["ISIS_AUTH_KEYCHAIN_NAME"] = ""
        self._default_nv_pairs["ISIS_LEVEL"] = ""
        self._default_nv_pairs["ISIS_OVERLOAD_ELAPSE_TIME"] = ""
        self._default_nv_pairs["ISIS_OVERLOAD_ENABLE"] = False
        self._default_nv_pairs["ISIS_P2P_ENABLE"] = False
        self._default_nv_pairs["L2_HOST_INTF_MTU"] = "9216"
        self._default_nv_pairs["L2_HOST_INTF_MTU_PREV"] = "9216"
        self._default_nv_pairs["L2_SEGMENT_ID_RANGE"] = "30000-49000"
        self._default_nv_pairs["L3VNI_MCAST_GROUP"] = ""
        self._default_nv_pairs["L3_PARTITION_ID_RANGE"] = "50000-59000"
        self._default_nv_pairs["LINK_STATE_ROUTING"] = "ospf"
        self._default_nv_pairs["LINK_STATE_ROUTING_TAG"] = "UNDERLAY"
        self._default_nv_pairs["LINK_STATE_ROUTING_TAG_PREV"] = ""
        self._default_nv_pairs["LOOPBACK0_IPV6_RANGE"] = ""
        self._default_nv_pairs["LOOPBACK0_IP_RANGE"] = "10.2.0.0/22"
        self._default_nv_pairs["LOOPBACK1_IPV6_RANGE"] = ""
        self._default_nv_pairs["LOOPBACK1_IP_RANGE"] = "10.3.0.0/22"
        self._default_nv_pairs["MACSEC_ALGORITHM"] = ""
        self._default_nv_pairs["MACSEC_CIPHER_SUITE"] = ""
        self._default_nv_pairs["MACSEC_FALLBACK_ALGORITHM"] = ""
        self._default_nv_pairs["MACSEC_FALLBACK_KEY_STRING"] = ""
        self._default_nv_pairs["MACSEC_KEY_STRING"] = ""
        self._default_nv_pairs["MACSEC_REPORT_TIMER"] = ""
        self._default_nv_pairs["MGMT_GW"] = ""
        self._default_nv_pairs["MGMT_GW_INTERNAL"] = ""
        self._default_nv_pairs["MGMT_PREFIX"] = ""
        self._default_nv_pairs["MGMT_PREFIX_INTERNAL"] = ""
        self._default_nv_pairs["MGMT_V6PREFIX"] = "64"
        self._default_nv_pairs["MGMT_V6PREFIX_INTERNAL"] = ""
        self._default_nv_pairs["MPLS_HANDOFF"] = False
        self._default_nv_pairs["MPLS_LB_ID"] = ""
        self._default_nv_pairs["MPLS_LOOPBACK_IP_RANGE"] = ""
        self._default_nv_pairs["MSO_CONNECTIVITY_DEPLOYED"] = ""
        self._default_nv_pairs["MSO_CONTROLER_ID"] = ""
        self._default_nv_pairs["MSO_SITE_GROUP_NAME"] = ""
        self._default_nv_pairs["MSO_SITE_ID"] = ""
        self._default_nv_pairs["MST_INSTANCE_RANGE"] = ""
        self._default_nv_pairs["MULTICAST_GROUP_SUBNET"] = "239.1.1.0/25"
        self._default_nv_pairs["NETFLOW_EXPORTER_LIST"] = ""
        self._default_nv_pairs["NETFLOW_MONITOR_LIST"] = ""
        self._default_nv_pairs["NETFLOW_RECORD_LIST"] = ""
        self._default_nv_pairs["NETWORK_VLAN_RANGE"] = "2300-2999"
        self._default_nv_pairs["NTP_SERVER_IP_LIST"] = ""
        self._default_nv_pairs["NTP_SERVER_VRF"] = ""
        self._default_nv_pairs["NVE_LB_ID"] = "1"
        self._default_nv_pairs["OSPF_AREA_ID"] = "0.0.0.0"
        self._default_nv_pairs["OSPF_AUTH_ENABLE"] = False
        self._default_nv_pairs["OSPF_AUTH_KEY"] = ""
        self._default_nv_pairs["OSPF_AUTH_KEY_ID"] = ""
        self._default_nv_pairs["OVERLAY_MODE"] = "config-profile"
        self._default_nv_pairs["OVERLAY_MODE_PREV"] = ""
        self._default_nv_pairs["PHANTOM_RP_LB_ID1"] = ""
        self._default_nv_pairs["PHANTOM_RP_LB_ID2"] = ""
        self._default_nv_pairs["PHANTOM_RP_LB_ID3"] = ""
        self._default_nv_pairs["PHANTOM_RP_LB_ID4"] = ""
        self._default_nv_pairs["PIM_HELLO_AUTH_ENABLE"] = False
        self._default_nv_pairs["PIM_HELLO_AUTH_KEY"] = ""
        self._default_nv_pairs["PM_ENABLE"] = False
        self._default_nv_pairs["PM_ENABLE_PREV"] = False
        self._default_nv_pairs["POWER_REDUNDANCY_MODE"] = "ps-redundant"
        self._default_nv_pairs["PREMSO_PARENT_FABRIC"] = ""
        self._default_nv_pairs["PTP_DOMAIN_ID"] = ""
        self._default_nv_pairs["PTP_LB_ID"] = ""
        self._default_nv_pairs["REPLICATION_MODE"] = "Multicast"
        self._default_nv_pairs["ROUTER_ID_RANGE"] = ""
        self._default_nv_pairs["ROUTE_MAP_SEQUENCE_NUMBER_RANGE"] = "1-65534"
        self._default_nv_pairs["RP_COUNT"] = "2"
        self._default_nv_pairs["RP_LB_ID"] = "254"
        self._default_nv_pairs["RP_MODE"] = "asm"
        self._default_nv_pairs["RR_COUNT"] = "2"
        self._default_nv_pairs["SEED_SWITCH_CORE_INTERFACES"] = ""
        self._default_nv_pairs["SERVICE_NETWORK_VLAN_RANGE"] = "3000-3199"
        self._default_nv_pairs["SITE_ID"] = ""
        self._default_nv_pairs["SNMP_SERVER_HOST_TRAP"] = True
        self._default_nv_pairs["SPINE_COUNT"] = "0"
        self._default_nv_pairs["SPINE_SWITCH_CORE_INTERFACES"] = ""
        self._default_nv_pairs["SSPINE_ADD_DEL_DEBUG_FLAG"] = "Disable"
        self._default_nv_pairs["SSPINE_COUNT"] = "0"
        self._default_nv_pairs["STATIC_UNDERLAY_IP_ALLOC"] = False
        self._default_nv_pairs["STP_BRIDGE_PRIORITY"] = ""
        self._default_nv_pairs["STP_ROOT_OPTION"] = "unmanaged"
        self._default_nv_pairs["STP_VLAN_RANGE"] = ""
        self._default_nv_pairs["STRICT_CC_MODE"] = False
        self._default_nv_pairs["SUBINTERFACE_RANGE"] = "2-511"
        self._default_nv_pairs["SUBNET_RANGE"] = "10.4.0.0/16"
        self._default_nv_pairs["SUBNET_TARGET_MASK"] = "30"
        self._default_nv_pairs["SYSLOG_SERVER_IP_LIST"] = ""
        self._default_nv_pairs["SYSLOG_SERVER_VRF"] = ""
        self._default_nv_pairs["SYSLOG_SEV"] = ""
        self._default_nv_pairs["TCAM_ALLOCATION"] = True
        self._default_nv_pairs["UNDERLAY_IS_V6"] = False
        self._default_nv_pairs["UNNUM_BOOTSTRAP_LB_ID"] = ""
        self._default_nv_pairs["UNNUM_DHCP_END"] = ""
        self._default_nv_pairs["UNNUM_DHCP_END_INTERNAL"] = ""
        self._default_nv_pairs["UNNUM_DHCP_START"] = ""
        self._default_nv_pairs["UNNUM_DHCP_START_INTERNAL"] = ""
        self._default_nv_pairs["USE_LINK_LOCAL"] = False
        self._default_nv_pairs["V6_SUBNET_RANGE"] = ""
        self._default_nv_pairs["V6_SUBNET_TARGET_MASK"] = ""
        self._default_nv_pairs["VPC_AUTO_RECOVERY_TIME"] = "360"
        self._default_nv_pairs["VPC_DELAY_RESTORE"] = "150"
        self._default_nv_pairs["VPC_DELAY_RESTORE_TIME"] = "60"
        self._default_nv_pairs["VPC_DOMAIN_ID_RANGE"] = "1-1000"
        self._default_nv_pairs["VPC_ENABLE_IPv6_ND_SYNC"] = True
        self._default_nv_pairs["VPC_PEER_KEEP_ALIVE_OPTION"] = "management"
        self._default_nv_pairs["VPC_PEER_LINK_PO"] = "500"
        self._default_nv_pairs["VPC_PEER_LINK_VLAN"] = "3600"
        self._default_nv_pairs["VRF_LITE_AUTOCONFIG"] = "Manual"
        self._default_nv_pairs["VRF_VLAN_RANGE"] = "2000-2299"
        self._default_nv_pairs["abstract_anycast_rp"] = "anycast_rp"
        self._default_nv_pairs["abstract_bgp"] = "base_bgp"
        value = "evpn_bgp_rr_neighbor"
        self._default_nv_pairs["abstract_bgp_neighbor"] = value
        self._default_nv_pairs["abstract_bgp_rr"] = "evpn_bgp_rr"
        self._default_nv_pairs["abstract_dhcp"] = "base_dhcp"
        self._default_nv_pairs[
            "abstract_extra_config_bootstrap"
        ] = "extra_config_bootstrap_11_1"
        value = "extra_config_leaf"
        self._default_nv_pairs["abstract_extra_config_leaf"] = value
        value = "extra_config_spine"
        self._default_nv_pairs["abstract_extra_config_spine"] = value
        value = "extra_config_tor"
        self._default_nv_pairs["abstract_extra_config_tor"] = value
        value = "base_feature_leaf_upg"
        self._default_nv_pairs["abstract_feature_leaf"] = value
        value = "base_feature_spine_upg"
        self._default_nv_pairs["abstract_feature_spine"] = value
        self._default_nv_pairs["abstract_isis"] = "base_isis_level2"
        self._default_nv_pairs["abstract_isis_interface"] = "isis_interface"
        self._default_nv_pairs[
            "abstract_loopback_interface"
        ] = "int_fabric_loopback_11_1"
        self._default_nv_pairs["abstract_multicast"] = "base_multicast_11_1"
        self._default_nv_pairs["abstract_ospf"] = "base_ospf"
        value = "ospf_interface_11_1"
        self._default_nv_pairs["abstract_ospf_interface"] = value
        self._default_nv_pairs["abstract_pim_interface"] = "pim_interface"
        self._default_nv_pairs["abstract_route_map"] = "route_map"
        self._default_nv_pairs["abstract_routed_host"] = "int_routed_host"
        self._default_nv_pairs["abstract_trunk_host"] = "int_trunk_host"
        value = "int_fabric_vlan_11_1"
        self._default_nv_pairs["abstract_vlan_interface"] = value
        self._default_nv_pairs["abstract_vpc_domain"] = "base_vpc_domain_11_1"
        value = "Default_Network_Universal"
        self._default_nv_pairs["default_network"] = value
        self._default_nv_pairs["default_pvlan_sec_network"] = ""
        self._default_nv_pairs["default_vrf"] = "Default_VRF_Universal"
        self._default_nv_pairs["enableRealTimeBackup"] = ""
        self._default_nv_pairs["enableScheduledBackup"] = ""
        self._default_nv_pairs[
            "network_extension_template"
        ] = "Default_Network_Extension_Universal"
        self._default_nv_pairs["scheduledTime"] = ""
        self._default_nv_pairs["temp_anycast_gateway"] = "anycast_gateway"
        self._default_nv_pairs["temp_vpc_domain_mgmt"] = "vpc_domain_mgmt"
        self._default_nv_pairs["temp_vpc_peer_link"] = "int_vpc_peer_link_po"
        self._default_nv_pairs[
            "vrf_extension_template"
        ] = "Default_VRF_Extension_Universal"

    def build_fabric_params_default(self):
        """
        Initialize default NDFC top-level parameters
        See also: _init_nv_pairs*
        """
        # TODO:3 We may need translation methods for these as well. See the
        #   method for nvPair transation: translate_to_ndfc_nv_pairs
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

        This method builds a set of playbook parameters that conform to the
        most common case (uppercase dunder e.g. REPLICATION_MODE) and so
        can safely be translated to uppercase dunder style that NDFC expects
        in the payload.

        See also: self.translate_to_ndfc_nv_pairs, where the actual
        translation happens.
        """
        # self._default_nv_pairs is already built via create_fabric()
        # Given we have a specific controlled input, we can use a more
        # relaxed regex here.  We just want to exclude camelCase e.g.
        # "thisThing", lowercase dunder e.g. "this_thing", and lowercase
        # e.g. "thisthing".
        re_uppercase_dunder = "^[A-Z0-9_]+$"
        self.translatable_nv_pairs = set()
        for param in self._default_nv_pairs:
            if re.search(re_uppercase_dunder, param):
                self.translatable_nv_pairs.add(param.lower())

    def translate_to_ndfc_nv_pairs(self, params):
        """
        translate keys in params dict into what NDFC
        expects in nvPairs and populate dict 
        self.translated_nv_pairs

        """
        self.build_translatable_nv_pairs()
        # TODO:4 We currently don't handle non-dunder uppercase and lowercase,
        #   e.g. THIS or that.  But (knock on wood), so far there are no
        #   cases like this (or THAT).
        self.log_msg(f"translate_to_ndfc_nv_pairs params {params}")
        self.translated_nv_pairs = {}
        # upper-case dunder keys
        for param in self.translatable_nv_pairs:
            if param not in params:
                continue
            self.translated_nv_pairs[param.upper()] = params[param]
        # special cases
        # dunder keys, these need no modification
        dunder_keys = {
            "default_network",
            "default_vrf",
            "network_extension_template",
            "vrf_extension_template"
        }
        for key in dunder_keys:
            if key not in params:
                continue
            self.translated_nv_pairs[key] = params[key]
        # camelCase keys
        # These are currently manually mapped with a dictionary.
        #
        # TODO:2 Use a regex so we don't have to manually translate these
        # The regex below sort of works, but doesn't handle camelCase
        # with multiple upper-case letters e.g. myCoolAI would fail and
        # become my_cool_a_i.  This single case could be fixed with e.g.
        # r"(?<!^)(?=[A-Z]{2})" but would fail for myCoolAIBOT.
        # Same for {3}, {4}...
        #
        # Tentative code for this, once we improve the regex:
        #
        # pattern = r"(?<!^)(?=[A-Z])"
        # for camel_key in camel_keys:
        #     dunder_key = re.sub(pattern, "_", param).lower()
        #     if dunder_key not in params:
        #         continue
        # self.translated_nv_pairs[camel_key] = params[dunder_key]
        # 
        camel_keys = {
            "enableRealTimeBackup": "enable_real_time_backup",
            "enableScheduledBackup": "enable_scheduled_backup",
            "scheduledTime": "scheduled_time"
        }
        for ndfc_key,user_key in camel_keys.items():
            if user_key not in params:
                continue
            self.translated_nv_pairs[ndfc_key] = params[user_key]

        self.log_msg(f"translate_to_ndfc_nv_pairs {self.translated_nv_pairs}")


    def build_mandatory_params(self):
        """
        build a map of mandatory parameters.

        Certain parameters become mandatory only if another parameter is
        set, or only if it's set to a specific value.  For example, if
        underlay_is_v6 is set to True, the following parameters become
        mandatory:
        -   anycast_lb_id
        -   loopback0_ipv6_range
        -   loopback1_ipv6_range
        -   router_id_range
        -   v6_subnet_range
        -   v6_subnet_target_mask

        self.mandatory_params is a dictionary, keyed on parameter.
        The value is a dictionary with the following keys:

        value:  The parameter value that makes the dependent parameters
                mandatory.  Using underlay_is_v6 as an example, it must
                have a value of True, for the six dependent parameters to
                be considered mandatory.
        mandatory: a python set() containing mandatory parameters.

        NOTE: Individual mandatory parameter values are validated elsewhere

        Hence, we have the following structure for the 
        self.mandatory_params dictionary, to handle the case where
        underlay_is_v6 is set to True:

        self.mandatory_params = {
            "underlay_is_v6": {
                "value": True,
                "mandatory": {
                    "anycast_lb_id",
                    "loopback0_ipv6_range",
                    "loopback1_ipv6_range",
                    "router_id_range",
                    "v6_subnet_range",
                    "v6_subnet_target_mask"
                }
            }
        }

        Above, we validate that all mandatory parameters are set, only
        if the value of underlay_is_v6 is True.

        Set "value:" above to "any" if the dependent parameters are mandatory
        regardless of the parameter's value.  For example, if we wanted to
        verify that underlay_is_v6 is set in the case that anycast_lb_id is
        set (which can be a value between 1-1023) we don't care what the
        value of anycast_lb_id is.  We only care that underlay_is_v6 is
        set.  In this case, we could add the following:

        self.mandatory_params.update = {
            "anycast_lb_id": {
                "value": "any",
                "mandatory": {
                    "underlay_is_v6"
                }
            }
        }

        """
        self.mandatory_params = {}
        self.mandatory_params.update(
            {
                "anycast_lb_id": {
                    "value": "any",
                    "mandatory": {
                        "underlay_is_v6"
                    }
                }
            }
        )
        self.mandatory_params.update(
            {
                "underlay_is_v6": {
                    "value": True,
                    "mandatory": {
                        "anycast_lb_id",
                        "loopback0_ipv6_range",
                        "loopback1_ipv6_range",
                        "router_id_range",
                        "v6_subnet_range",
                        "v6_subnet_target_mask"
                    }
                }
            }
        )


    def validate_dependencies(self, params):
        self.build_mandatory_params()
        for param in params:
            # param doesn't have any dependent parameters
            if param not in self.mandatory_params:
                continue
            needs_validation = False
            if self.mandatory_params[param]["value"] == "any":
                needs_validation = True
            if params[param] == self.mandatory_params[param]["value"]:
                needs_validation = True
            if not needs_validation:
                continue
            for mandatory_param in self.mandatory_params[param]["mandatory"]:
                failed_dependencies = set()
                if mandatory_param not in params:
                    # The user hasn't set this mandatory parameter, but if it
                    # has a non-null default value, it's OK and we can skip it
                    param_up = mandatory_param.upper()
                    if param_up in self._default_nv_pairs:
                        if self._default_nv_pairs[param_up] != "":
                            continue
                    failed_dependencies.add(mandatory_param)
                    continue
                if params[mandatory_param] is None:
                    failed_dependencies.add(mandatory_param)
                    continue
                if params[mandatory_param] == "":
                    failed_dependencies.add(mandatory_param)
                    continue
            if failed_dependencies:
                msg = f"When {param} is set to "
                msg += f"{self.mandatory_params[param]['value']}, the "
                msg += "following are mandatory "
                msg += f"{','.join(sorted(failed_dependencies))}"
                self.module.fail_json(msg=msg)

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
            self.build_default_nv_pairs()
            self.validate_dependencies(item)
            payload = self._fabric_params_default
            payload["fabricName"] = fabric
            payload["asn"] = bgp_as
            payload["nvPairs"] = self._default_nv_pairs
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
