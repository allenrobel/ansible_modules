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
"""
Classes and methods for Ansible support of NDFC Data Center VXLAN EVPN Fabric.

Ansible states "merged", "deleted", and "query" are implemented.
"""
from __future__ import absolute_import, division, print_function

import copy
import json
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send, dcnm_version_supported, get_fabric_details,
    get_fabric_inventory_details, validate_list_of_dicts)

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
        - NDFC GUI label, Enable AAA IP Authorization
        - NDFC GUI tab, Advanced
        type: bool
        required: false
        default: False
      advertise_pip_bgp:
        description:
        - Enable (True) or disable (False) usage of Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes
        - NDFC GUI label, vPC advertise-pip
        - NDFC GUI tab, VPC
        type: bool
        required: false
        default: False
      anycast_bgw_advertise_pip:
        description:
        - Enable (True) or disable (False) advertising Anycast Border Gateway PIP as VTEP.
        - Effective after Recalculate Config on parent MSD fabric.
        - NDFC GUI label, Anycast Border Gateway advertise-pip
        - NDFC GUI tab, Advanced
        type: bool
        required: false
        default: False
      anycast_gw_mac:
        description:
        - Shared MAC address for all leafs (xx:xx:xx:xx:xx:xx, xxxx.xxxx.xxxx, etc)
        - NDFC GUI label, Anycast Gateway MAC
        - NDFC GUI tab, General Parameters
        type: str
        required: false
        default: "2020.0000.00aa"
      anycast_lb_id:
        description:
        - Underlay Anycast Loopback Id
        - NDFC GUI label, Underlay Anycast Loopback Id
        - NDFC GUI tab, Protocols
        type: int
        required: false
        default: ""
      anycast_rp_ip_range:
        description:
        - Anycast or Phantom RP IP Address Range
        - NDFC GUI label, Underlay RP Loopback IP Range
        - NDFC GUI tab, Resources
        type: str
        required: false
        default: 10.254.254.0/24
      auto_symmetric_default_vrf:
        description:
        - Enable (True) or disable (False) auto generation of Default VRF interface and BGP peering configuration on managed neighbor devices.
        - If True, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF for Peer' enabled.
        - vrf_lite_autoconfig must be set to 1
        - auto_symmetric_vrf_lite must be set to True
        - auto_vrflite_ifc_default_vrf must be set to True
        - NDFC GUI label: Auto Deploy Default VRF for Peer
        - NDFC GUI tab: Resources
        type: bool
        required: false
        default: False
      auto_symmetric_vrf_lite:
        description:
        - Enable (True) or disable (False) auto generation of Whether to auto generate VRF LITE sub-interface and BGP peering configuration on managed neighbor devices.
        - If True, auto created VRF Lite IFC links will have 'Auto Deploy for Peer' enabled.
        - NDFC GUI label, Auto Deploy for Peer
        - NDFC GUI tab, Resources
        - vrf_lite_autoconfig must be set to 1
        type: bool
        required: false
        default: False
      auto_vrflite_ifc_default_vrf:
        description:
        - Enable (True) or disable (False) auto generation of Default VRF interface and BGP peering configuration on VRF LITE IFC auto deployment.
        - If True, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF' enabled.
        - NDFC GUI label, Auto Deploy Default VRF
        - NDFC GUI tab, Resources
        - vrf_lite_autoconfig must be set to 1
        type: bool
        required: false
        default: False
      bgp_as:
        description:
        - The fabric BGP Autonomous System number
        - NDFC GUI label, BGP ASN
        - NDFC GUI tab, General Parameters
        type: str
        required: true
      default_vrf_redis_bgp_rmap:
        description:
        - Route Map used to redistribute BGP routes to IGP in default vrf in auto created VRF Lite IFC links
        - NDFC GUI label, Redistribute BGP Route-map Name
        - NDFC GUI tab, Resources
        type: str
        required: false, unless auto_vrflite_ifc_default_vrf is set to True
      fabric_name:
        description:
        - The name of the fabric
        type: str
        required: true
      pm_enable:
        description:
        - Enable (True) or disable (False) fabric performance monitoring
        - NDFC GUI label, Enable Performance Monitoring
        - NDFC GUI tab, General Parameters
        type: bool
        required: false
        default: False
      replication_mode:
        description:
        - Replication Mode for BUM Traffic
        - NDFC GUI label, Replication Mode
        - NDFC GUI tab, Replication
        type: str
        required: False
        choices:
        - Ingress
        - Multicast
        default: Multicast
      vrf_lite_autoconfig:
        description:
        - VRF Lite Inter-Fabric Connection Deployment Options.
        - If (0), VRF Lite configuration is Manual.
        - If (1), VRF Lite IFCs are auto created between border devices of two Easy Fabrics
        - If (1), VRF Lite IFCs are auto created between border devices in Easy Fabric and edge routers in External Fabric.
        - The IP address is taken from the 'VRF Lite Subnet IP Range' pool.
        - NDFC GUI label, VRF Lite Deployment
        - NDFC GUI tab, Resources
        type: int
        required: false
        default: 0
        choices:
        - 0
        - 1

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



def translate_mac_address(mac_addr):
    """
    Accept mac address with any (or no) punctuation
    and convert it into the dotted format that NDFC
    expects.

    Return mac address formatted for NDFC on success
    Return False on failure.
    """
    mac_addr = re.sub(r"[\W\s_]", "", mac_addr)
    if not re.search("^[A-Fa-f0-9]{12}$", mac_addr):
        return False
    return "".join((mac_addr[:4], ".", mac_addr[4:8], ".", mac_addr[8:]))


def translate_vrf_lite_autoconfig(value):
    """
    Translate playbook values to those expected by NDFC
    """
    try:
        value = int(value)
    except ValueError:
        return False
    if value == 0:
        return "Manual"
    if value == 1:
        return "Back2Back&ToExternal"
    return False


class DcnmFabric:
    """
    Ansible support for Data Center VXLAN EVPN (Easy_Fabric)
    """
    def __init__(self, module):
        self.module = module
        self.params = module.params
        # TODO:1 set self.debug to False to disable self.log_msg()
        self.debug = True
        # Used for self.log_msg()
        self.fd = None
        # File self.log_msg() logs to
        self.logfile = "/tmp/dcnm_easy_fabric.log"

        self.config = module.params.get("config")
        if not isinstance(self.config, list):
            msg = "expected list type for self.config. "
            msg = f"got {type(self.config).__name__}"
            self.module.fail_json(msg=msg)

        self.check_mode = False
        self.validated = []
        self.have_create = []
        self.want_create = []
        self.diff_create = []
        self.diff_save = {}
        self.query = []
        self.result = dict(changed=False, diff=[], response=[])
        self._default_fabric_params = {}
        self._default_nv_pairs = {}
        # See self.build_mandatory_params()
        self._mandatory_params = {}
        # nvPairs that are safe to translate from lowercase dunder
        # (as used in the playbook) to uppercase dunder (as used
        # in the NDFC payload).
        self._translatable_nv_pairs = set()
        # A dictionary that holds the set of nvPairs that have been
        # translated for use in the NDFC payload.  These include only
        # parameters that the user has changed.  Keyed on the NDFC-expected
        # parameter name, value is the user's setting for the parameter.
        # Populated in:
        #  self._translate_to_ndfc_nv_pairs()
        #  self._build_translatable_nv_pairs()
        self._translated_nv_pairs = {}

        self.nd_prefix = "/appcenter/cisco/ndfc/api/v1/lan-fabric"
        self.controller_version = dcnm_version_supported(self.module)
        self.nd = self.controller_version >= 12

        self.mandatory_keys = {"fabric_name", "bgp_as"}
        self.fabric_details = {}
        self.inventory_data = {}
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

    # def update_create_params(self, inv):
    #     return inv

    def get_have(self):
        """
        determine current fabric state on NDFC for all existing fabrics
        """
        method = "GET"
        for fabric in self.fabric_details:
            path = f"/rest/control/fabrics/{fabric}"
            if self.nd:
                path = self.nd_prefix + path
            fabric_info = dcnm_send(self.module, method, path)
            missing_fabric, not_ok = self.handle_response(fabric_info, "query_dcnm")

            if missing_fabric is False and not_ok is True:
                return
            msg = f"get_have(): Fabric {fabric} already present on NDFC"
            self.module.fail_json(msg=msg)

    def get_want(self):
        """
        Update self.want_create for all fabrics defined in the playbook
        """
        want_create = []

        # we don't want to use self.validated here since
        # validate_list_of_dicts() adds items the user
        # did not set to self.validated
        # If we got this far, then the items in self.config
        # have been validated to conform to their param spec.
        for fabric_config in self.config:
            want_create.append(fabric_config)
        if not want_create:
            return
        self.want_create = want_create

    def get_diff_merge(self):
        """
        Populates self.diff_create list() with items from our want list
        that are not in our have list.  These items will be sent to NDFC.

        Called from main().
        """
        diff_create = []

        for want_c in self.want_create:
            found = False
            for have_c in self.have_create:
                if want_c["fabric_name"] == have_c["fabric_name"]:
                    found = True
            if not found:
                diff_create.append(want_c)
        self.diff_create = diff_create

    @staticmethod
    def build_params_spec_for_merged_state():
        """
        Build the specs for the parameters expected when state == merged.

        Called from: validate_input_for_merged_state()
        Return: params_spec, a dictionary containing the set of
                parameter specifications.
        """
        params_spec = {}
        params_spec.update(
            aaa_remote_ip_enabled=dict(required=False, type="bool", default=False)
        )
        # TODO:6 active_migration
        # active_migration doesn't seem to be represented in
        # the NDFC EasyFabric GUI.  Add this param if we figure out
        # what it's used for and where in the GUI it's represented
        params_spec.update(
            advertise_pip_bgp=dict(required=False, type="bool", default=False)
        )
        # TODO:6 agent_intf (add if needed)
        params_spec.update(
            anycast_bgw_advertise_pip=dict(required=False, type="bool", default=False)
        )
        params_spec.update(
            anycast_gw_mac=dict(required=False, type="str", default="2020.0000.00aa")
        )
        params_spec.update(
            anycast_lb_id=dict(
                required=False, type="int", range_min=0, range_max=1023, default=""
            )
        )
        params_spec.update(
            anycast_rp_ip_range=dict(
                required=False, type="ipv4_subnet", default="10.254.254.0/24"
            )
        )
        params_spec.update(
            auto_symmetric_default_vrf=dict(
                required=False,
                type="bool",
                default=False
            )
        )
        params_spec.update(
            auto_symmetric_vrf_lite=dict(
                required=False,
                type="bool",
                default=False
            )
        )
        params_spec.update(
            auto_vrflite_ifc_default_vrf=dict(
                required=False,
                type="bool",
                default=False
            )
        )
        params_spec.update(bgp_as=dict(required=True, type="str"))
        params_spec.update(default_vrf_redis_bgp_rmap=dict(required=False, type="str", default=""))
        params_spec.update(fabric_name=dict(required=True, type="str"))
        params_spec.update(pm_enable=dict(required=False, type="bool", default=False))
        params_spec.update(
            replication_mode=dict(
                required=False,
                type="str",
                default="Multicast",
                choices=["Ingress", "Multicast"],
            )
        )
        params_spec.update(
            vrf_lite_autoconfig=dict(
                required=False,
                type="str",
                default="Manual",
                choices=["Back2Back&ToExternal", "Manual"],
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
        if "vrf_lite_autoconfig" in cfg:
            result = translate_vrf_lite_autoconfig(cfg["vrf_lite_autoconfig"])
            if result is False:
                msg = "invalid vrf_lite_autoconfig "
                msg += f"{cfg['vrf_lite_autoconfig']}. Expected one of 0,1"
                self.module.fail_json(msg=msg)
            cfg["vrf_lite_autoconfig"] = result
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

        valid_params, invalid_params = validate_list_of_dicts(
            self.config, params_spec, self.module
        )
        for param in valid_params:
            self.validated.append(param)

        if invalid_params:
            msg = "Invalid parameters in playbook: "
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
        """
        used for debugging. disable this when committing to main
        """
        if self.debug is False:
            return
        if self.fd is None:
            try:
                self.fd = open(f"{self.logfile}", "a+",
                               encoding="UTF-8"
                )
            except IOError as err:
                msg = f"error opening logfile {self.logfile}. "
                msg += f"detail: {err}"
                self.module.fail_json(msg=msg)

        self.fd.write(msg)
        self.fd.write("\n")
        self.fd.flush()

    def _build_default_nv_pairs(self):
        """
        Build a dict() of default fabric nvPairs that will be sent to NDFC.
        The values for these items are what NDFC currently (as of 12.1.2e)
        uses for defaults.  Items that are supported by this module may be
        modified by the user's playbook.
        """
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

    def _build_default_fabric_params(self):
        """
        Initialize default NDFC top-level parameters
        See also: self._build_default_nv_pairs()
        """
        # TODO:3 We may need translation methods for these as well. See the
        #   method for nvPair transation: _translate_to_ndfc_nv_pairs
        self._default_fabric_params = {}
        self._default_fabric_params["deviceType"] = "n9k"
        self._default_fabric_params["fabricTechnology"] = "VXLANFabric"
        self._default_fabric_params["fabricTechnologyFriendly"] = "VXLAN Fabric"
        self._default_fabric_params["fabricType"] = "Switch_Fabric"
        self._default_fabric_params["fabricTypeFriendly"] = "Switch Fabric"
        self._default_fabric_params[
            "networkExtensionTemplate"
        ] = "Default_Network_Extension_Universal"
        value = "Default_Network_Universal"
        self._default_fabric_params["networkTemplate"] = value
        self._default_fabric_params["provisionMode"] = "DCNMTopDown"
        self._default_fabric_params["replicationMode"] = "Multicast"
        self._default_fabric_params["siteId"] = ""
        self._default_fabric_params["templateName"] = "Easy_Fabric"
        self._default_fabric_params[
            "vrfExtensionTemplate"
        ] = "Default_VRF_Extension_Universal"
        self._default_fabric_params["vrfTemplate"] = "Default_VRF_Universal"

    def _build_translatable_nv_pairs(self):
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

        See also: self._translate_to_ndfc_nv_pairs, where the actual
        translation happens.
        """
        # self._default_nv_pairs is already built via create_fabric()
        # Given we have a specific controlled input, we can use a more
        # relaxed regex here.  We just want to exclude camelCase e.g.
        # "thisThing", lowercase dunder e.g. "this_thing", and lowercase
        # e.g. "thisthing".
        re_uppercase_dunder = "^[A-Z0-9_]+$"
        self._translatable_nv_pairs = set()
        for param in self._default_nv_pairs:
            if re.search(re_uppercase_dunder, param):
                self._translatable_nv_pairs.add(param.lower())

    def _translate_to_ndfc_nv_pairs(self, params):
        """
        translate keys in params dict into what NDFC
        expects in nvPairs and populate dict
        self._translated_nv_pairs

        """
        self._build_translatable_nv_pairs()
        # TODO:4 We currently don't handle non-dunder uppercase and lowercase,
        #   e.g. THIS or that.  But (knock on wood), so far there are no
        #   cases like this (or THAT).
        self._translated_nv_pairs = {}
        # upper-case dunder keys
        for param in self._translatable_nv_pairs:
            if param not in params:
                continue
            self._translated_nv_pairs[param.upper()] = params[param]
        # special cases
        # dunder keys, these need no modification
        dunder_keys = {
            "default_network",
            "default_vrf",
            "network_extension_template",
            "vrf_extension_template",
        }
        for key in dunder_keys:
            if key not in params:
                continue
            self._translated_nv_pairs[key] = params[key]
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
        # self._translated_nv_pairs[camel_key] = params[dunder_key]
        #
        camel_keys = {
            "enableRealTimeBackup": "enable_real_time_backup",
            "enableScheduledBackup": "enable_scheduled_backup",
            "scheduledTime": "scheduled_time",
        }
        for ndfc_key, user_key in camel_keys.items():
            if user_key not in params:
                continue
            self._translated_nv_pairs[ndfc_key] = params[user_key]

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

        self._mandatory_params is a dictionary, keyed on parameter.
        The value is a dictionary with the following keys:

        value:  The parameter value that makes the dependent parameters
                mandatory.  Using underlay_is_v6 as an example, it must
                have a value of True, for the six dependent parameters to
                be considered mandatory.
        mandatory:  a python dict() containing mandatory parameters and what
                    value (if any) they must have.  Indicate that the value
                    should not be considered by setting it to None.

        NOTE: Generalized parameter value validation is handled elsewhere

        Hence, we have the following structure for the
        self._mandatory_params dictionary, to handle the case where
        underlay_is_v6 is set to True.  Below, we don't case what the
        value for any of the mandatory parameters is.  We only care that
        they are set.

        self._mandatory_params = {
            "underlay_is_v6": {
                "value": True,
                "mandatory": {
                    "anycast_lb_id": None
                    "loopback0_ipv6_range": None
                    "loopback1_ipv6_range": None
                    "router_id_range": None
                    "v6_subnet_range": None
                    "v6_subnet_target_mask": None
                }
            }
        }

        Above, we validate that all mandatory parameters are set, only
        if the value of underlay_is_v6 is True.

        Set "value:" above to "any" if the dependent parameters are mandatory
        regardless of the parameter's value.  For example, if we wanted to
        verify that underlay_is_v6 is set to True in the case that
        anycast_lb_id is set (which can be a value between 1-1023) we
        don't care what the value of anycast_lb_id is.  We only care that
        underlay_is_v6 is set to True.  In this case, we could add the following:

        self._mandatory_params.update = {
            "anycast_lb_id": {
                "value": "any",
                "mandatory": {
                    "underlay_is_v6": True
                }
            }
        }

        """
        self._mandatory_params = {}
        self._mandatory_params.update(
            {
                "anycast_lb_id": {
                    "value": "any",
                    "mandatory": {
                        "underlay_is_v6": True
                    }
                }
            }
        )
        self._mandatory_params.update(
            {
                "underlay_is_v6": {
                    "value": True,
                    "mandatory": {
                        "anycast_lb_id": None,
                        "loopback0_ipv6_range": None,
                        "loopback1_ipv6_range": None,
                        "router_id_range": None,
                        "v6_subnet_range": None,
                        "v6_subnet_target_mask": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "auto_symmetric_default_vrf": {
                    "value": True,
                    "mandatory": {
                        "vrf_lite_autoconfig": "Back2Back&ToExternal",
                        "auto_vrflite_ifc_default_vrf": True
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "auto_symmetric_vrf_lite": {
                    "value": True,
                    "mandatory": {
                        "vrf_lite_autoconfig": "Back2Back&ToExternal"
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "auto_vrflite_ifc_default_vrf": {
                    "value": True,
                    "mandatory": {
                        "vrf_lite_autoconfig": "Back2Back&ToExternal",
                        "default_vrf_redis_bgp_rmap": None
                    },
                }
            }
        )

    def _validate_dependencies(self, user_params):
        """
        Validate cross-parameter dependencies.
        See docstring for self.build_mandatory_params()
        """
        self.build_mandatory_params()
        requires_validation = set()
        for user_param in user_params:
            # param doesn't have any dependent parameters
            if user_param not in self._mandatory_params:
                continue
            # need to run validation for any value of user_param
            if self._mandatory_params[user_param]["value"] == "any":
                requires_validation.add(user_param)
            # need to run validation because user_param is a specific value
            if user_params[user_param] == self._mandatory_params[user_param]["value"]:
                requires_validation.add(user_param)
        if not requires_validation:
            return

        failed_dependencies = dict()
        for user_param in requires_validation:
            # mandatory_params associated with user_param
            mandatory_params = self._mandatory_params[user_param]["mandatory"]
            for check_param in mandatory_params:
                check_value = mandatory_params[check_param]
                if check_param not in user_params and check_value is not None:
                    # The playbook doesn't contain this mandatory parameter.
                    # We care what the value is (since it's not None).
                    # If the mandatory parameter's default value is not equal
                    # to the required value, add it to the failed dependencies.
                    param_up = check_param.upper()
                    if param_up in self._default_nv_pairs:
                        if self._default_nv_pairs[param_up] != check_value:
                            failed_dependencies[check_param] = check_value
                            continue
                if user_params[check_param] != check_value and check_value is not None:
                    # The playbook does contain this mandatory parameter, but
                    # the value in the playbook does not match the required value
                    # and we care about what the required value is.
                    failed_dependencies[check_param] = check_value
                    continue
        if failed_dependencies:
            if self._mandatory_params[user_param]['value'] == "any":
                msg = f"When {user_param} is set to any value, "
            else:
                msg = f"When {user_param} is set to "
                msg += f"{self._mandatory_params[user_param]['value']}. "
            msg += "the following parameters are mandatory: "
            for item in failed_dependencies:
                msg += f"parameter {item} "
                if failed_dependencies[item] is None:
                    msg += "value <any value>"
                else:
                    msg += f"value {failed_dependencies[item]}"
            self.module.fail_json(msg=msg)

    def create_fabrics(self):
        """
        Build and send the payload to create the
        fabrics specified in the playbook.

        Called from main()
        """
        method = "POST"
        path = "/rest/control/fabrics"
        if self.nd:
            path = self.nd_prefix + path

        for item in self.want_create:

            fabric = item["fabric_name"]
            bgp_as = item["bgp_as"]

            self._build_default_fabric_params()
            self._build_default_nv_pairs()
            self._validate_dependencies(item)
            payload = self._default_fabric_params
            payload["fabricName"] = fabric
            payload["asn"] = bgp_as
            payload["nvPairs"] = self._default_nv_pairs
            self._translate_to_ndfc_nv_pairs(item)
            for key, value in self._translated_nv_pairs.items():
                payload["nvPairs"][key] = value

            response = dcnm_send(self.module, method, path, data=json.dumps(payload))
            fail, self.result["changed"] = self.handle_response(response, "create")

            if fail:
                self.log_msg(
                    f"create_fabrics() calling self.failure with response {response}"
                )
                self.failure(response)

    def handle_response(self, res, op):
        """
        Handle DELETE, GET, POST, PUT responses from NDFC.
        """
        fail = False
        changed = True

        if op == "query_dcnm":
            # This if block handles responses to the query APIs against DCNM.
            # Basically all GET operations.
            if res.get("ERROR") == "Not Found" and res["RETURN_CODE"] == 404:
                return True, False
            if res["RETURN_CODE"] != 200 or res["MESSAGE"] != "OK":
                return False, True
            return False, False

        # Responses to all other operations (DELETE, POST, PUT)
        # are handled here.
        if res.get("MESSAGE") != "OK":
            fail = True
            changed = False
            return fail, changed
        if res.get("ERROR"):
            fail = True
            changed = False

        return fail, changed

    def failure(self, resp):
        """
        This came from dcnm_inventory.py, but doesn't seem to be correct
        for the case where resp["DATA"] does not exist?

        If resp["DATA"] does not exist, the contents of the
        if block don't seem to actually do anything:
            - data will be None
            - Hence, data.get("stackTrace") will also be None
            - Hence, data.update() and res.update() are never executed

        So, the only two lines that will actually ever be executed are
        the happy path:

        res = copy.deepcopy(resp)
        self.module.fail_json(msg=res)
        """
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