#!/usr/bin/python
#
# Copyright (c) 2023-2023 Cisco and/or its affiliates.
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
Classes and methods to verify NDFC Data Center VXLAN EVPN Fabric parameters.
This should go in:
ansible_collections/cisco/dcnm/plugins/module_utils/fabric/fabric.py

Example Usage:
import sys
from ansible_collections.cisco.dcnm.plugins.module_utils.fabric.fabric import (
    VerifyFabricParams,
)

config = {}
config["fabric_name"] = "foo"
config["bgp_as"] = "65000.869"
# If auto_symmetric_vrf_lite == True, several other parameters
# become mandatory. The user has not explicitely set these other
# parameters.  Hence, verify.result would be False (i.e. an error)
# If auto_symmetric_vrf_lite ==  False, no other parameters are required
# and so verify.result would be True and verify.payload would contain
# a valid payload to send to NDFC
config["auto_symmetric_vrf_lite"] = False
verify = VerifyFabricParams()
verify.config = config
verify.state = "merged"
verify.validate_config()
if verify.result == False:
    print(f"result {verify.result}, {verify.msg}")
    sys.exit(1)
print(f"result {verify.result}, {verify.msg}, payload {verify.payload}")
"""
import copy
import json
import re
import ipaddress

def translate_mac_address(mac_addr):
    """
    Accept mac address with any (or no) punctuation and convert it
    into the dotted-quad format that NDFC expects.

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

def verify_ip_list(value):
    """
    Return True if value is a comma-separated list of ipv4/ipv6
    addresses.
    Return False otherwise
    """
    for ip in value.split(","):
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
    return True

class VerifyFabricParams:
    """
    Parameter validation for NDFC Easy_Fabric (Data Center VXLAN EVPN)
    """

    def __init__(self):
        self._initialize_properties()

        self.msg = None
        self.payload = {}
        self._default_fabric_params = {}
        self._default_nv_pairs = {}
        # See self._build_parameter_aliases
        self._parameter_aliases = {}
        # See self._build_mandatory_params()
        self._mandatory_params = {}
        # See self._validate_dependencies()
        self._requires_validation = set()
        # See self._build_failed_dependencies()
        self._failed_dependencies = {}
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
        self._valid_states = {"merged"}
        self._minimum_mandatory_keys = {"fabric_name", "bgp_as"}
        self._build_default_fabric_params()
        self._build_default_nv_pairs()
        self._add_default_nv_pairs_12_1_3b()
        self._build_parameter_aliases()

    def _initialize_properties(self):
        self.properties = {}
        self.properties["msg"] = None
        self.properties["result"] = True
        self.properties["state"] = None
        self.properties["config"] = {}

    def _append_msg(self, msg):
        if self.msg is None:
            self.msg = msg
        else:
            self.msg += f" {msg}"

    def _validate_config(self, config):
        """
        verify that self.config is a dict and that it contains
        the minimal set of mandatory keys.

        Caller: self.config (@property setter)

        On success:
            return True
        On failure:
            set self.result to False
            append an approprate error message to self.msg
            return False
        """
        if not isinstance(config, dict):
            msg = "error: config must be a dictionary"
            self.result = False
            self._append_msg(msg)
            return False
        if not self._minimum_mandatory_keys.issubset(config):
            missing_keys = self._minimum_mandatory_keys.difference(config.keys())
            msg = f"error: missing mandatory keys {','.join(sorted(missing_keys))}."
            self.result = False
            self._append_msg(msg)
            return False
        return True

    def validate_config(self):
        """
        Caller: public method, called by the user
        Validate the items in self.config are appropriate for self.state
        """
        if self.state is None:
            msg = "call instance.state before calling instance.validate_config"
            self._append_msg(msg)
            self.result = False
            return
        if self.state == "merged":
            self._validate_merged_state_config()

    def _verify_vrf_list_length(self, vrf_list_key, ip_list_key):
        """
        There are three parameters that need to be checked for
        correct list of VRFs vs list of IP addresses.  This method
        handles these parameters.

        vrf_list_key - the key name of the vrf list e.g. dns_server_vrf
        ip_list_key - the key name of the ip list e.g. dns_server_ip_list

        dns_server_vrf validated against dns_server_ip_list
        ntp_server_vrf validated against ntp_server_ip_list
        syslog_server_vrf validated against syslog_server_ip_list


        """
        if vrf_list_key in self.config:
            vrf_list_length = len(self.config[vrf_list_key].split(","))
            if vrf_list_length == 1:
                return
            ip_list_length = len(self.config[ip_list_key].split(","))
            if vrf_list_length != ip_list_length:
                msg = f"If {vrf_list_key} contains multiple entries, the "
                msg += "number of entries must match the number of entries "
                msg += f"in {ip_list_key}. "
                self._append_msg(msg)
                self.result = False
                return

    @staticmethod
    def _verify_list_of_dict(param):
        """
        raise TypeError if param is not a list() of dict()
        """
        if not isinstance(param, list):
            msg = f"expected list(), got {type(param).__name__}"
            raise TypeError(msg)
        if len(param) == 0:
            msg = f"expected list() with at least one dict(), "
            msg += f"got {type(param).__name__} with length 0"
            raise TypeError(msg)
        for elem in param:
            if not isinstance(elem, dict):
                msg = "expected list() of dict(), "
                msg = f" got {type(elem).__name__} for at least one "
                msg += "list element"
                raise TypeError(msg)

    @staticmethod
    def _verify_keys(args):
        """
        Verify that args["keys"] are present in args["dict"]

        args is a dict() with the following keys:
        - keys: a set() of keys that are expected in dict
        - dict: the dictionary to test

        raise TypeError if args is not a dict
        raise KeyError if args does not contain keys "keys" and "dict"
        raise TypeError if args["keys"] is not a set()
        raise TypeError if args["dict"] is not a dict()
        raise KeyError if args["dict"] does not contain all args["keys"]
        """
        if not isinstance(args, dict):
            msg = f"expected dict. got {args}"
            raise TypeError(msg)
        mandatory_keys = {"keys", "dict"}
        if not mandatory_keys.issubset(args):
            msg = "missing keys (internal error, please raise an issue). "
            msg += f"expected {mandatory_keys} "
            msg += f"got: {args.keys()}"
            raise KeyError(msg)
        if not isinstance(args["keys"], set):
            msg = "keys (bad type): expected python set(). "
            msg += f"got {type(args['keys']).__name__}"
            raise TypeError(msg)
        if not isinstance(args["dict"], dict):
            msg = "keys (bad type): expected python dict(). "
            msg += f"got {type(args['dict']).__name__}"
            raise TypeError(msg)
        if not args["keys"].issubset(args["dict"]):
            missing = ','.join(sorted(args["keys"].difference(args["dict"])))
            msg = f"missing keys {missing}. expected {','.join(sorted(args['keys']))}, "
            msg += f"got {','.join(sorted(args['dict'].keys()))}"
            raise KeyError(msg)

    def _validate_netflow_exporter_list(self, param):
        """
        Verify the following:
        1. param is a list of dict
        2. mandatory keys are present in every dict
        3. each key's value is appropriate
        """
        try:
            self._verify_list_of_dict(param)
        except TypeError as err:
            msg = "invalid netflow_exporter_list. "
            msg += f"expected list of dict. got {param}. "
            msg += f"error detail: {err}"
            self._append_msg(msg)
            self.result = False
            return
        keys = {"EXPORTER_NAME", "IP", "VRF", "SRC_IF_NAME", "UDP_PORT"}
        for item in param:
            args = {}
            args["keys"] = keys
            args["dict"] = item
            try:
                self._verify_keys(args)
            except (KeyError, TypeError) as err:
                msg = f"invalid netflow_exporter_list: {err}"
                self._append_msg(msg)
                self.result = False
                return

    def _validate_netflow_record_list(self, param):
        """
        Verify the following:
        1. param is a list of dict
        2. mandatory keys are present in every dict
        3. each key's value is appropriate
        """
        try:
            self._verify_list_of_dict(param)
        except TypeError as err:
            msg = "invalid netflow_record_list. "
            msg += f"expected list of dict. got {param}. "
            msg += f"error detail: {err}"
            self._append_msg(msg)
            self.result = False
            return
        keys = {"RECORD_NAME", "RECORD_TEMPLATE", "LAYER2_RECORD"}
        for item in param:
            args = {}
            args["keys"] = keys
            args["dict"] = item
            try:
                self._verify_keys(args)
            except (KeyError, TypeError) as err:
                msg = f"invalid netflow_record_list: {err}"
                self._append_msg(msg)
                self.result = False
                return

    def _translate_netflow_record_list(self, param):
        """
        Perform any conversions that are needed to satisfy NDFC

        Conversions:
        1. Convert LAYER2_RECORD from bool to lowercase str()

        NOTES:
        1.  param has already been validated so it's safe to forge ahead
        2.  LAYER2_RECORD MUST be lowercase, not title-case, so
            a simple conversion like str(bool) won't work.
        """
        new_param = []
        for item in param:
            new_item = copy.deepcopy(item)
            new_item["LAYER2_RECORD"] = str(new_item["LAYER2_RECORD"]).lower()
            new_param.append(new_item)
        return new_param

    def _validate_netflow_monitor_list(self, param):
        """
        Verify the following:
        1. param is a list of dict
        2. mandatory keys are present in every dict
        3. each key's value is appropriate
        """
        try:
            self._verify_list_of_dict(param)
        except TypeError as err:
            msg = "invalid netflow_monitor_list. "
            msg += f"expected list of dict. got {param}. "
            msg += f"error detail: {err}"
            self._append_msg(msg)
            self.result = False
            return
        keys = {"MONITOR_NAME", "RECORD_NAME", "EXPORTER1"}
        for item in param:
            args = {}
            args["keys"] = keys
            args["dict"] = item
            try:
                self._verify_keys(args)
            except (KeyError, TypeError) as err:
                msg = f"invalid netflow_monitor_list: {err}"
                self._append_msg(msg)
                self.result = False
                return

    def _validate_merged_state_config(self):
        """
        Caller: self.validate_config()

        Update self.config with a verified version of the users playbook
        parameters.


        Verify the user's playbook parameters for an individual fabric
        configuration.  Whenever possible, throw the user a bone by
        converting values to NDFC's expectations. For example, NDFC's
        REST API accepts mac addresses in any format (does not return
        an error), since the NDFC GUI validates that it is in the expected
        format, but the fabric will be in an errored state if the mac address
        sent via REST is any format other than dotted-quad format
        (xxxx.xxxx.xxxx). So, we convert all mac address formats to
        dotted-quad before passing them to NDFC.

        Set self.result to False and update self.msg if anything is not valid
        that we couldn't fix
        """
        if not self.config:
            msg = "config: element is mandatory for state merged"
            self._append_msg(msg)
            self.result = False
            return
        if "fabric_name" not in self.config:
            msg = "fabric_name is mandatory"
            self._append_msg(msg)
            self.result = False
            return
        if "bgp_as" not in self.config:
            msg = "bgp_as is mandatory"
            self._append_msg(msg)
            self.result = False
            return
        if "anycast_gw_mac" in self.config:
            result = translate_mac_address(self.config["anycast_gw_mac"])
            if result is False:
                msg = f"invalid anycast_gw_mac {self.config['anycast_gw_mac']}"
                self._append_msg(msg)
                self.result = False
                return
            self.config["anycast_gw_mac"] = result
        self._verify_vrf_list_length("dns_server_vrf", "dns_server_ip_list")
        for key in [
            "dns_server_ip_list",
            "ntp_server_ip_list",
            "syslog_server_ip_list"]:
            if key in self.config:
                result = verify_ip_list(self.config[key])
                if result is False:
                    msg = f"invalid {key} {self.config[key]}"
                    self._append_msg(msg)
                    self.result = False
                    return
        if "macsec_algorithm" in self.config:
            key = "macsec_algorithm"
            result = self._translate_macsec_algorithm(self.config[key])
            if result is False:
                msg = f"invalid {key} "
                msg += f"{self.config[key]}. "
                msg += "Expected one of "
                msg += f"{self._get_parameter_alias_values(key)}"
                self._append_msg(msg)
                self.result = False
                return
            self.config["macsec_algorithm"] = result
        if "macsec_cipher_suite" in self.config:
            key = "macsec_cipher_suite"
            result = self._translate_macsec_cipher_suite(self.config[key])
            if result is False:
                msg = f"invalid {key} "
                msg += f"{self.config[key]}. "
                msg += "Expected one of "
                msg += f"{self._get_parameter_alias_values(key)}"
                self._append_msg(msg)
                self.result = False
                return
            self.config["macsec_cipher_suite"] = result
        if "macsec_fallback_algorithm" in self.config:
            key = "macsec_fallback_algorithm"
            result = self._translate_macsec_algorithm(self.config[key])
            if result is False:
                msg = f"invalid {key} "
                msg += f"{self.config[key]}. "
                msg += "Expected one of "
                msg += f"{self._get_parameter_alias_values(key)}"
                self._append_msg(msg)
                self.result = False
                return
            self.config[key] = result
        if "macsec_fallback_key_string" in self.config:
            key = "macsec_fallback_key_string"
            result = self._verify_macsec_key_string(
                key,
                self.config[key],
                self.config["macsec_fallback_algorithm"]
            )
            if result["result"] is False:
                self._append_msg(result["msg"])
                self.result = False
                return
        if "macsec_key_string" in self.config:
            key = "macsec_key_string"
            result = self._verify_macsec_key_string(
                key,
                self.config[key],
                self.config["macsec_algorithm"]
            )
            if result["result"] is False:
                self._append_msg(result["msg"])
                self.result = False
                return
        if "netflow_exporter_list" in self.config:
            self._validate_netflow_exporter_list(self.config["netflow_exporter_list"])
            if self.result is False:
                return
        if "netflow_record_list" in self.config:
            self._validate_netflow_record_list(self.config["netflow_record_list"])
            if self.result is False:
                return
            self.config["netflow_record_list"] = self._translate_netflow_record_list(self.config["netflow_record_list"])
        if "netflow_monitor_list" in self.config:
            self._validate_netflow_monitor_list(self.config["netflow_monitor_list"])
            if self.result is False:
                return

        self._verify_vrf_list_length("ntp_server_vrf", "ntp_server_ip_list")
        self._verify_vrf_list_length("syslog_server_vrf", "syslog_server_ip_list")
        # We're sorta overloading this function, but it's convenient to use it.
        self._verify_vrf_list_length("syslog_sev", "syslog_server_ip_list")
        if "syslog_sev" in self.config:
            key = "syslog_sev"
            values = self.config[key].split(",")
            for value in values:
                try:
                    int(value)
                except ValueError:
                    msg = f"invalid {key} ({value}) in {self.config[key]}. "
                    self._append_msg(msg)
                    self.result = False
                    return

        if "vrf_lite_autoconfig" in self.config:
            key = "vrf_lite_autoconfig"
            result = translate_vrf_lite_autoconfig(self.config[key])
            if result is False:
                msg = f"invalid {key} "
                msg += f"{self.config[key]}. "
                msg += "Expected one of "
                msg += f"{self._get_parameter_alias_values(key)}"
                self._append_msg(msg)
                self.result = False
                return
            self.config["vrf_lite_autoconfig"] = result

        # Update default nvPairs if underlay_is_v6 is True
        self._update_default_nv_pairs_ipv6()
        # Update default nvPairs if use_link_local is False
        self._update_default_nv_pairs_use_link_local_false()
        # validate self.config for cross-parameter dependencies
        self._validate_dependencies()
        if self.result is False:
            return
        self._build_payload()

    def _verify_macsec_key_string(self, key, value, algorithm):
        """
        Verify macsec key string.
        key:
            The playbook key to verify. One of:
            - macsec_key_string
            - macsec_fallback_key_string
        value:
            The value of the playbook key
        algorithm:
            -   If key == macsec_key_string, the value of
                playbook key: macsec_algorithm
            -   If key == macsec_fallback_key_string, the value of
                playbook key macsec_fallback_algorithm
        Returns dictionary result, with the following keys:

        -   result:
            -   True, if algorithm is AES_128_CMAC and value is a 66
                character hex string
            -   True, if algorithm is AES_256_CMAC and value is a 130
                character hex string
            -   False, otherwise
        -   msg: message explaining result
        """
        algo_keys = {}
        algo_keys["macsec_key_string"] = "macsec_algorithm"
        algo_keys["macsec_fallback_key_string"] = "macsec_fallback_algorithm"
        result = {"result": True, "msg": "Validated"}
        if not re.search("^[A-Fa-f0-9]+$", value):
            msg = f"{key} string must be a hex string. "
            msg += f"Got {value}."
            return {"result": False, "msg": msg}
        if algorithm not in self._get_parameter_alias_keys(algo_keys[key]):
            msg = f"invalid {algo_keys[key]}. "
            msg += "Expected one of "
            msg += f"{self._get_parameter_alias_values(algorithm)}. "
            msg += f"Got {algorithm}."
            return {"result": False, "msg": msg}
        if algorithm == "AES_128_CMAC" and len(value) != 66:
            msg = f"{key} length must be 66 when "
            msg += f"{algo_keys[key]} is set to 1 ({algorithm}). "
            msg += f"Got {value} of length {len(value)}."
            return {"result": False, "msg": msg}
        if algorithm == "AES_256_CMAC" and len(value) != 130:
            msg = f"{key} length must be 130 when "
            msg += f"{algo_keys[key]} is set to 2 ({algorithm}). "
            msg += f"Got {value} of length {len(value)}."
            return {"result": False, "msg": msg}
        return result

    def _build_default_nv_pairs(self):
        """
        Caller: __init__()

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
        Caller: __init__()

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

    def _update_default_nv_pairs_ipv6(self):
        """
        Update the default nvPairs with the following default values
        if the playbook value of underlay_is_v6 is True.
        We overwrite these later with the playbook values if they are present.
        TODO:3 We should clear ipv4 defaults here, but NDFC doesn't seem to mind if IPv4 values are set.

        Caller: self._validate_merged_state_config()
        """
        if "underlay_is_v6" not in self.config:
            return
        if self.config["underlay_is_v6"] is False:
            return
        self._default_nv_pairs["ANYCAST_LB_ID"] = 10
        self._default_nv_pairs["LOOPBACK0_IPV6_RANGE"] = "fd00::a02:0/119"
        self._default_nv_pairs["LOOPBACK1_IPV6_RANGE"] = "fd00::a03:0/118"
        self._default_nv_pairs["ROUTER_ID_RANGE"] = "10.2.0.0/23"
        self._default_nv_pairs["USE_LINK_LOCAL"] = True

    def _update_default_nv_pairs_use_link_local_false(self):
        """
        Update the default nvPairs with the following default values
        if the playbook value of use_link_local is False.
        We overwrite these later with the playbook values if they are present.

        Caller: self._validate_merged_state_config()
        """
        if "use_link_local" not in self.config:
            return
        if self.config["use_link_local"] is True:
            return
        self._default_nv_pairs["V6_SUBNET_RANGE"] = "fd00::a04:0/112"
        self._default_nv_pairs["V6_SUBNET_TARGET_MASK"] = 126

    def _add_default_nv_pairs_12_1_3b(self):
        """
        Caller: __init__()
        NDFC 12.1.3b adds the following nvPairs:

        Mandatory (will cause fabric errors if not present)):
            AUTO_UNIQUE_VRF_LITE_IP_PREFIX: "false"
            BANNER: ""
            NXAPI_HTTPS_PORT: "443"
            NXAPI_HTTP_PORT: "80"
            OBJECT_TRACKING_NUMBER_RANGE: "100-299"
            PER_VRF_LOOPBACK_AUTO_PROVISION: "false"
            SLA_ID_RANGE: "10000-19999"
            TOPDOWN_CONFIG_RM_TRACKING: "notstarted"

        Optional:
            ADVERTISE_PIP_ON_BORDER: "true"
            ALLOW_NXC: "true"
            ALLOW_NXC_PREV: "true"
            AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV: "false"
            DOMAIN_NAME_INTERNAL: ""
            ESR_OPTION: "PBR"
            EXT_FABRIC_TYPE: ""
            NXC_DEST_VRF: "management"
            NXC_PROXY_PORT: "8080"
            NXC_PROXY_SERVER: ""
            NXC_SRC_INTF: ""
            OVERWRITE_GLOBAL_NXC: "false"
            PER_VRF_LOOPBACK_AUTO_PROVISION_PREV: "false"
            PER_VRF_LOOPBACK_IP_RANGE: ""
            UPGRADE_FROM_VERSION: ""

        All:
            ADVERTISE_PIP_ON_BORDER: "true"
            ALLOW_NXC: "true"
            ALLOW_NXC_PREV: "true"
            AUTO_UNIQUE_VRF_LITE_IP_PREFIX: "false"
            AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV: "false"
            BANNER: ""
            DOMAIN_NAME_INTERNAL: ""
            ESR_OPTION: "PBR"
            EXT_FABRIC_TYPE: ""
            NXAPI_HTTPS_PORT: "443"
            NXAPI_HTTP_PORT: "80"
            NXC_DEST_VRF: "management"
            NXC_PROXY_PORT: "8080"
            NXC_PROXY_SERVER: ""
            NXC_SRC_INTF: ""
            OBJECT_TRACKING_NUMBER_RANGE: "100-299"
            OVERWRITE_GLOBAL_NXC: "false"
            PER_VRF_LOOPBACK_AUTO_PROVISION: "false"
            PER_VRF_LOOPBACK_AUTO_PROVISION_PREV: "false"
            PER_VRF_LOOPBACK_IP_RANGE: ""
            SLA_ID_RANGE: "10000-19999"
            TOPDOWN_CONFIG_RM_TRACKING: "notstarted"
            UPGRADE_FROM_VERSION: ""

        """
        self._default_nv_pairs["ADVERTISE_PIP_ON_BORDER"] = True
        self._default_nv_pairs["ALLOW_NXC"] = True
        self._default_nv_pairs["ALLOW_NXC_PREV"] = True
        self._default_nv_pairs["AUTO_UNIQUE_VRF_LITE_IP_PREFIX"] = False
        self._default_nv_pairs["AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV"] = False
        self._default_nv_pairs["BANNER"] = ""
        self._default_nv_pairs["DOMAIN_NAME_INTERNAL"] = ""
        self._default_nv_pairs["ESR_OPTION"] = "PBR"
        self._default_nv_pairs["EXT_FABRIC_TYPE"] = ""
        self._default_nv_pairs["NXAPI_HTTPS_PORT"] = "443"
        self._default_nv_pairs["NXAPI_HTTP_PORT"] = "80"
        self._default_nv_pairs["NXC_DEST_VRF"] = "management"
        self._default_nv_pairs["NXC_PROXY_PORT"] = "8080"
        self._default_nv_pairs["NXC_PROXY_SERVER"] = ""
        self._default_nv_pairs["NXC_SRC_INTF"] = ""
        self._default_nv_pairs["OBJECT_TRACKING_NUMBER_RANGE"] = "100-299"
        self._default_nv_pairs["OVERWRITE_GLOBAL_NXC"] = False
        self._default_nv_pairs["PER_VRF_LOOPBACK_AUTO_PROVISION"] = False
        self._default_nv_pairs["PER_VRF_LOOPBACK_AUTO_PROVISION_PREV"] = False
        self._default_nv_pairs["PER_VRF_LOOPBACK_IP_RANGE"] = ""
        self._default_nv_pairs["SLA_ID_RANGE"] = "10000-19999"
        self._default_nv_pairs["TOPDOWN_CONFIG_RM_TRACKING"] = "notstarted"
        self._default_nv_pairs["UPGRADE_FROM_VERSION"] = ""

    def _build_translatable_nv_pairs(self):
        """
        Caller: _translate_to_ndfc_nv_pairs()

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
        Caller: self._build_payload()

        translate keys in params dict into what NDFC
        expects in nvPairs and populate dict
        self._translated_nv_pairs

        """
        self._build_translatable_nv_pairs()
        # TODO:4 We currently don't handle non-dunder uppercase and lowercase,
        #   e.g. THIS or that.  But (knock on wood), so far there are no
        #   cases like this (or THAT).  Apparentely we did not knock hard
        #  enough on wood, as we now have a case where we need to handle
        #  non-dunder uppercase for BANNER in NDFC 2.3.1f
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
        camel_keys = {
            "enableRealTimeBackup": "enable_real_time_backup",
            "enableScheduledBackup": "enable_scheduled_backup",
            "scheduledTime": "scheduled_time",
        }
        for ndfc_key, user_key in camel_keys.items():
            if user_key not in params:
                continue
            self._translated_nv_pairs[ndfc_key] = params[user_key]

        # Keys with typos
        # Lastly, NDFC has several keys with typos which we don't
        # want the user to have to compensate for.  We map these from
        # the correct spelling back into the incorrect spelling
        # that NDFC requires and update the translated nvPairs
        # dictionary accordingly.
        typo_keys = {
            "DEAFULT_QUEUING_POLICY_CLOUDSCALE": "default_queuing_policy_cloudscale",
            "DEAFULT_QUEUING_POLICY_OTHER": "default_queuing_policy_other",
            "DEAFULT_QUEUING_POLICY_R_SERIES": "default_queuing_policy_r_series",
        }
        for ndfc_key, user_key in typo_keys.items():
            value = params.pop(user_key, None)
            if value is None:
                continue
            self._translated_nv_pairs[ndfc_key] = value

    def _build_mandatory_params(self):
        """
        Caller: self._validate_dependencies()

        build a map of mandatory parameters.

        Certain parameters become mandatory only if another parameter is
        set, or only if it's set to a specific value.  For example, if
        stp_root_option is set to "rpvst+" the following parameters become
        mandatory:
        -   stp_vlan_range

        self._mandatory_params is a dictionary, keyed on parameter.
        The value is a dictionary with the following keys:

        value:  The parameter value that makes the dependent parameters
                mandatory.  Using stp_root_option as an example, it must
                have a value of rpvst+, for stp_vlan_range to be considered
                mandatory.
        mandatory:  a python dict() containing mandatory parameters and what
                    value (if any) they must have.  Indicate that the value
                    should not be considered by setting it to None.

        NOTE: Generalized parameter value validation is handled elsewhere

        Hence, we have the following structure for the
        self._mandatory_params dictionary, to handle the case where
        stp_root_option is set to rpvst+.  Below, we don't care what the
        value for any of the mandatory parameters is.  We only care that
        they are set.

        self._mandatory_params = {
            "stp_root_option": {
                "value": "rpvst+",
                "mandatory": {
                    "stp_vlan_range": None
                }
            }
        }

        Above, we validate that all mandatory parameters are set, only
        if the value of stp_root_option is rpvst+.

        Set "value:" above to "__any__" if the dependent parameters are
        mandatory regardless of the parameter's value.  For example, if
        we wanted to verify that underlay_is_v6 is set to True in the case
        that anycast_lb_id (which can be a value between 1-1023) is set, we
        don't care what the value of anycast_lb_id is.  We only care that
        underlay_is_v6 is set to True.  In this case, we could add the
        following:

        self._mandatory_params.update = {
            "anycast_lb_id": {
                "value": "__any__",
                "mandatory": {
                    "underlay_is_v6": True
                }
            }
        }

        NOTE: We considered the following validator, but it does not
        provide the functionality we need:

        ansible.module_utils.common.arg_spec.ArgumentSpecValidator()

        Specifically:
        
        1. "required_if" does allow to specify the value that a parameter
        must have, but it doesn't allow to specify what value (if any) the
        dependent parameter(s) must have.  It also does not allow us to
        specify that a parameter must be present, but the value need not be
        considered, when triggering the dependencies.

        2. "required_by" does not allow us to specify the value that a
        parameter must have, nor the value that any dependent parameters
        must have.
        """
        self._mandatory_params = {}
        self._mandatory_params.update(
            {
                "anycast_lb_id": {
                    "value": "__any__",
                    "mandatory": {"underlay_is_v6": True},
                }
            }
        )
        self._mandatory_params.update(
            {
                "auto_symmetric_default_vrf": {
                    "value": True,
                    "mandatory": {
                        "vrf_lite_autoconfig": "Back2Back&ToExternal",
                        "auto_vrflite_ifc_default_vrf": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "auto_symmetric_vrf_lite": {
                    "value": True,
                    "mandatory": {"vrf_lite_autoconfig": "Back2Back&ToExternal"},
                }
            }
        )
        self._mandatory_params.update(
            {
                "auto_vrflite_ifc_default_vrf": {
                    "value": True,
                    "mandatory": {
                        "vrf_lite_autoconfig": "Back2Back&ToExternal",
                        "default_vrf_redis_bgp_rmap": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_auth_enable": {
                    "value": True,
                    "mandatory": {
                        "bfd_enable": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_auth_key": {
                    "value": "__any__",
                    "mandatory": {
                        "bfd_enable": True,
                        "bfd_auth_enable": True,
                        "bfd_auth_key_id": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_auth_key_id": {
                    "value": "__any__",
                    "mandatory": {
                        "bfd_enable": True,
                        "bfd_auth_enable": True,
                        "bfd_auth_key": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_ibgp_enable": {
                    "value": True,
                    "mandatory": {
                        "bfd_enable": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_isis_enable": {
                    "value": True,
                    "mandatory": {
                        "bfd_enable": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_ospf_enable": {
                    "value": True,
                    "mandatory": {
                        "bfd_enable": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bfd_pim_enable": {
                    "value": True,
                    "mandatory": {
                        "bfd_enable": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bgp_auth_enable": {
                    "value": True,
                    "mandatory": {
                        "bgp_auth_key": None,
                        "bgp_auth_key_type": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "bootstrap_multisubnet": {
                    "value": True,
                    "mandatory": {
                        "bootstrap_enable": True,
                        "dhcp_enable": True,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "dhcp_enable": {
                    "value": True,
                    "mandatory": {
                        "bootstrap_enable": True,
                        "dhcp_end": None,
                        # dhcp_ipv6_enable _is_ mandatory, when
                        # dhcp_enable is set to True.  However,
                        # NDFC currently only has one value for this
                        # (DHCPv4), and does set this value for the
                        # user when dhcp_enable is True. BUT, this may
                        # change in the future.
                        #"dhcp_ipv6_enable": "DHCPv4",
                        "dhcp_start": None,
                        "mgmt_gw": None,
                        "mgmt_prefix": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "enable_fabric_vpc_domain_id": {
                    "value": True,
                    "mandatory": {
                        "fabric_vpc_domain_id": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "enable_macsec": {
                    "value": True,
                    "mandatory": {
                        "macsec_algorithm": None,
                        "macsec_cipher_suite": None,
                        "macsec_fallback_algorithm": None,
                        "macsec_fallback_key_string": None,
                        "macsec_key_string": None,
                        "macsec_report_timer": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "enable_netflow": {
                    "value": True,
                    "mandatory": {
                        "netflow_exporter_list": None,
                        "netflow_record_list": None,
                        "netflow_monitor_list": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "dns_server_ip_list": {
                    "value": "__any__",
                    "mandatory": {
                        "dns_server_vrf": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "dns_server_vrf": {
                    "value": "__any__",
                    "mandatory": {
                        "dns_server_ip_list": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "enable_default_queuing_policy": {
                    "value": True,
                    "mandatory": {
                        "default_queuing_policy_cloudscale": None,
                        "default_queuing_policy_other": None,
                        "default_queuing_policy_r_series": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "mpls_handoff": {
                    "value": True,
                    "mandatory": {
                        "mpls_lb_id": None,
                        "mpls_loopback_ip_range": None,
                    },
                }
            }
        )
        # While NDFC has a default for mst_instance_range,
        # i.e. 0, and the GUI does display this default
        # if it's not set via the API, the fabric will be in
        # error state if the user doesn't set it via the API
        # (until the user manually edits the fabric in the GUI
        # and clicks Save).
        # Hence, we force the user to set it here.
        # TODO:3 We can fix this in the same way we handle underlay_is_v6.
        self._mandatory_params.update(
            {
                "stp_root_option": {
                    "value": "mst",
                    "mandatory": {
                        "mst_instance_range": None,
                    },
                }
            }
        )
        # While NDFC has a default for stp_vlan_range,
        # i.e. 1-3967, and the GUI does display this default
        # if it's not set via the API, the fabric will be in
        # error state if the user doesn't set it via the API
        # (until the user manually edits the fabric in the GUI
        # and clicks Save).
        # Hence, we force the user to set it here.
        # TODO:3 We can fix this in the same way we handle underlay_is_v6.
        self._mandatory_params.update(
            {
                "stp_root_option": {
                    "value": "rpvst+",
                    "mandatory": {
                        "stp_vlan_range": None,
                    },
                }
            }
        )
        self._mandatory_params.update(
            {
                "syslog_server_ip_list": {
                    "value": "__any__",
                    "mandatory": {
                        "syslog_sev": None,
                    },
                }
            }
        )

    def _validate_dependencies(self):
        """
        Validate cross-parameter dependencies.

        Caller: self._validate_merged_state_config()

        Generate a set() of parameters that require validation:
        - self._requires_validation

        If the set is empty, there's nothing to validate, so return.
        Else, call:
        - self._build_failed_dependencies()
        - self._handle_failed_dependencies()
        """
        self._build_mandatory_params()
        self._requires_validation = set()
        for user_param in self.config:
            # param doesn't have any dependent parameters
            if user_param not in self._mandatory_params:
                continue
            # need to run validation for user_param with value "__any__"
            if self._mandatory_params[user_param]["value"] == "__any__":
                self._requires_validation.add(user_param)
            # need to run validation because user_param is a specific value
            if self.config[user_param] == self._mandatory_params[user_param]["value"]:
                self._requires_validation.add(user_param)
        if not self._requires_validation:
            return
        self._build_failed_dependencies()
        self._handle_failed_dependencies()

    def _build_failed_dependencies(self):
        """
        If the user has set one or more parameters that, in turn, cause
        other parameters to become mandatory, build a dictionary of these
        dependencies and what value is expected for each.

        Example self._failed_dependencies.

        {
            'vrf_lite_autoconfig': 'Back2Back&ToExternal'
        }

        In this case, the user set auto_symmetric_vrf_lite to True,
        which makes vrf_lite_autoconfig mandatory. Too, vrf_lite_autoconfig
        MUST have a value of Back2Back&ToExternal. Though, in the playbook,
        the user sets vrf_lite_autoconfig to 1, since 1 is an alias for
        Back2Back&ToExternal.  See self._handle_failed_dependencies()
        for how we handle aliased parameters.
        """
        if not self._requires_validation:
            return
        self._failed_dependencies = {}
        for user_param in self._requires_validation:
            # mandatory_params associated with user_param
            mandatory_params = self._mandatory_params[user_param]["mandatory"]
            for check_param in mandatory_params:
                check_value = mandatory_params[check_param]
                if check_param not in self.config and check_value is None:
                    # The playbook doesn't contain this mandatory parameter,
                    # and we need not consider its value (e.g. there is
                    # no default) for it.  Hence, add it to failed
                    # dependencies without checking the default value.
                    self._failed_dependencies[check_param] = check_value
                    continue
                if check_param not in self.config and check_value is not None:
                    # The playbook doesn't contain this mandatory parameter,
                    # but its default value might be sufficient if it matches
                    # the required value. Add it to the failed dependencies
                    # only if the default value doesn't match the required
                    # value.
                    param_up = check_param.upper()
                    if param_up not in self._default_nv_pairs:
                        # If we're here, then there's likely a new parameter
                        # in some future NDFC release that we forgot to add
                        # to self._default_nv_pairs.
                        #
                        # Clear self_failed_dependencies to skip
                        # self._handle_failed_dependencies() and set result to
                        # False.
                        self._failed_dependencies = {}
                        msg = f"This should never happen. {param_up} not "
                        msg += "found in default_nv_pairs.  Please open an "
                        msg += "issue."
                        self._append_msg(msg)
                        self.result = False
                        return
                    if self._default_nv_pairs[param_up] != check_value:
                        self._failed_dependencies[check_param] = check_value
                        continue
                if self.config[check_param] != check_value and check_value is not None:
                    # The playbook does contain this mandatory parameter, but
                    # the value in the playbook doesn't match the required value
                    self._failed_dependencies[check_param] = check_value
                    continue

    def _handle_failed_dependencies(self):
        """
        If there are failed dependencies:
        1.  Set self.result to False
        2.  Build a useful message for the user that lists
            the additional parameters that NDFC expects
        """
        if not self._failed_dependencies:
            return
        for user_param in self._requires_validation:
            if self._mandatory_params[user_param]["value"] == "__any__":
                msg = f"When {user_param} is set, "
            else:
                msg = f"When {user_param} is set to "
                msg += f"{self._mandatory_params[user_param]['value']}, "
            msg += "the following parameters are mandatory: "

            for key, value in self._failed_dependencies.items():
                msg += f"[{key}, "
                if value is None:
                    msg += "value <any>] "
                else:
                    # If the value expected in the playbook is different
                    # from the value sent to NDFC, use the value expected in
                    # the playbook so as not to confuse the user.
                    alias = self._get_parameter_alias(key, value)
                    if alias is None:
                        msg_value = value
                    else:
                        msg_value = alias
                    msg += f"value {msg_value}] "
            self._append_msg(msg)
            self.result = False

    def _build_parameter_aliases(self):
        """
        Caller self._handle_failed_dependencies()

        For some parameters, like vrf_lite_autoconfig, we don't
        want the user to have to remember the spelling for
        their values e.g. Back2Back&ToExternal.  So, we alias
        the value NDFC expects (Back2Back&ToExternal) to something
        easier.  In this case, 1.

        See also: accessor method self._get_parameter_alias()
        """
        self._parameter_aliases = {}
        self._parameter_aliases["macsec_algorithm"] = {
            "AES_128_CMAC": 1,
            "AES_256_CMAC": 2,
        }
        self._parameter_aliases["macsec_cipher_suite"] = {
            "GCM-AES-128": 1,
            "GCM-AES-256": 2,
            "GCM-AES-XPN-128": 3,
            "GCM-AES-XPN-256": 4,
        }
        self._parameter_aliases["macsec_fallback_algorithm"] = {
            "AES_128_CMAC": 1,
            "AES_256_CMAC": 2,
        }
        self._parameter_aliases["vrf_lite_autoconfig"] = {
            "Back2Back&ToExternal": 1,
            "Manual": 0,
        }

    def _translate_macsec_algorithm(self, value):
        """
        Translate macsec_algorithm and macsec_fallback_algorithm
        playbook values to those expected by NDFC.

        TODO: If the values for macsec_algorithm and macsec_fallback_algorithm
        ever diverge, we'll need to split this into two methods.
        """
        try:
            value = int(value)
        except ValueError:
            return False
        for key, val in self._parameter_aliases["macsec_algorithm"].items():
            if value == val:
                return key
        return False

    def _translate_macsec_cipher_suite(self, value):
        """
        Translate macsec_cipher_suite playbook values
        to those expected by NDFC
        """
        try:
            value = int(value)
        except ValueError:
            return False
        for key, val in self._parameter_aliases["macsec_cipher_suite"].items():
            if value == val:
                return key
        return False

    def _get_parameter_alias(self, param, value):
        """
        Caller: self._handle_failed_dependencies()

        Accessor method for self._parameter_aliases

        param: the parameter
        value: the parameter's value that NDFC expects

        Return the value alias for param (i.e. param's value
        prior to translation, i.e. the value that's used in the
        playbook) if it exists.

        Return None otherwise

        See also: self._build_parameter_aliases()
        """
        if param not in self._parameter_aliases:
            return None
        if value not in self._parameter_aliases[param]:
            return None
        return self._parameter_aliases[param][value]

    def _get_parameter_alias_values(self, param):
        """
        Accessor method for self._parameter_aliases
        Return the value(s) associated with param.
        Caller self._validate_merged_state_config()
        """
        if param not in self._parameter_aliases:
            return []
        return sorted(self._parameter_aliases[param].values())

    def _get_parameter_alias_keys(self, param):
        """
        Accessor method for self._parameter_aliases
        Return the key(s) associated with param.
        Caller self._validate_merged_state_config()
        """
        if param not in self._parameter_aliases:
            return []
        return sorted(self._parameter_aliases[param].keys())

    def _build_payload(self):
        """
        Build the payload to create the fabric specified in self.config
        Caller: self._validate_merged_state_config()
        """
        self.payload = self._default_fabric_params
        self.payload["fabricName"] = self.config["fabric_name"]
        self.payload["asn"] = self.config["bgp_as"]
        self.payload["nvPairs"] = self._default_nv_pairs
        self._translate_to_ndfc_nv_pairs(self.config)
        for key, value in self._translated_nv_pairs.items():
            self.payload["nvPairs"][key] = value
        # TODO:4 clean this netflow stuff up.  It works, but it's messy.
        netflow_list_keys = ["NETFLOW_EXPORTER_LIST", "NETFLOW_RECORD_LIST", "NETFLOW_MONITOR_LIST"]
        for key in netflow_list_keys:
            if key not in self.payload["nvPairs"]:
                continue
            # The default values for these keys are empty strings (i.e. if
            # the fabric is created manually using NDFC GUI). But NDFC 12.1.3b
            # does not like a value of an empty string for these keys when sent
            # via REST (12.1.2e was fine with this).  So, we delete these keys
            # if the user hasn't set them.
            # TODO:1 Test with 12.1.2e to verify that the absense of thes keys doesn't cause a problem.
            if not isinstance(self.payload["nvPairs"][key], list):
                self.payload["nvPairs"].pop(key, None)
                continue
            tmp_dict = {}
            tmp_dict[key] = self.payload["nvPairs"][key]
            self.payload["nvPairs"][key] = json.dumps(tmp_dict)
            
    @property
    def config(self):
        """
        Basic initial validatation for individual fabric configuration
        Verifies that config is a dict() and that mandatory keys are
        present.
        """
        return self.properties["config"]

    @config.setter
    def config(self, param):
        if not self._validate_config(param):
            return
        self.properties["config"] = param

    @property
    def msg(self):
        """
        messages to return to the caller
        """
        return self.properties["msg"]

    @msg.setter
    def msg(self, param):
        self.properties["msg"] = param

    @property
    def payload(self):
        """
        The payload to send to NDFC
        """
        return self.properties["payload"]

    @payload.setter
    def payload(self, param):
        self.properties["payload"] = param

    @property
    def result(self):
        """
        get/set intermediate results and final result
        """
        return self.properties["result"]

    @result.setter
    def result(self, param):
        self.properties["result"] = param

    @property
    def state(self):
        """
        The Ansible state provided by the caller
        """
        return self.properties["state"]

    @state.setter
    def state(self, param):
        if param not in self._valid_states:
            msg = f"invalid state {param}. "
            msg += f"expected one of: {','.join(sorted(self._valid_states))}"
            self.result = False
            self._append_msg(msg)
        self.properties["state"] = param
