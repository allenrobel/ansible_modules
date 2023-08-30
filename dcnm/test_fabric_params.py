#!/usr/bin/env python
from ansible_collections.cisco.dcnm.plugins.module_utils.fabric.fabric import (
    VerifyFabricParams,
)

def print_result(test_name, result, msg, payload, show_payload=True):
    _payload = ""
    if show_payload:
        _payload = f", payload {payload}"
    print(f"{test_name}: result {result}, message {msg}{_payload}")

def test_aaa():
    test_name = "aaa"
    config = {}
    config["fabric_name"] = "AAA"
    config["bgp_as"] = "65000.869"
    config["enable_aaa"] = True
    config["aaa_server_conf"] = """
aaa group server radius radius 
snmp-server aaa-user cache-timeout 3600
no snmp-server disable snmp-aaa sync
no snmp-server enable traps aaa server-state-change
aaa authentication login default local 
aaa authorization ssh-publickey default local 
aaa authorization ssh-certificate default local 
aaa accounting default local 
aaa user default-role 
aaa authentication login default fallback error local 
aaa authentication login console fallback error local 
no aaa authentication login invalid-username-log 
no aaa authentication login error-enable 
no aaa authentication login mschap enable 
no aaa authentication login mschapv2 enable 
no aaa authentication login chap enable 
no aaa authentication login ascii-authentication 
"""
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, True)

def test_bfd():
    test_name = "bfd"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["bfd_auth_key_id"] = "100"
    config["bfd_enable"] = True
    config["bfd_auth_enable"] = True
    config["bfd_auth_key"] = "asadflkajsdff"
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_bgp_auth():
    test_name = "bgp_auth"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["bgp_auth_enable"] = True
    config["bgp_auth_key_type"] = 0
    config["bgp_auth_key"] = "foo"
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_bootstrap():
    test_name = "bootstrap"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["bootstrap_enable"] = True
    config["dhcp_enable"] = True
    config["dhcp_end"] = "5.1.1.5"
    config["dhcp_start"] = "5.1.1.2"
    config["mgmt_gw"] = "5.1.1.1"
    config["mgmt_prefix"] = 24
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_dns_server_ip_list():
    test_name = "dns_server_ip_list"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["dns_server_ip_list"] = "1.1.1.1, 2001:1:2::1, 2.2.2.2"
    config["dns_server_vrf"] = "management, foo, bar"
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_macsec_cipher_suite():
    test_name = "macsec_cipher_suite"
    hex_values = {}
    hex_values["good_algo_1"] = "F" * 66
    hex_values["good_algo_2"] = "E" * 130
    hex_values["bad_len"] = "A" * 10
    hex_values["bad_chars"] = "badhex"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["enable_macsec"] = True
    config["macsec_algorithm"] = 1
    config["macsec_cipher_suite"] = 3
    config["macsec_fallback_algorithm"] = 2
    config["macsec_fallback_key_string"] = hex_values["good_algo_2"]
    config["macsec_key_string"] = hex_values["good_algo_1"]
    config["macsec_report_timer"] = 10
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_mpls_handoff():
    test_name = "mpls_handoff"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "7"
    config["mpls_handoff"] = True
    config["mpls_lb_id"] = 1023
    config["mpls_loopback_ip_range"] = "10.103.0.0/25"
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_netflow():
    exporter_dict = {}
    exporter_dict["EXPORTER_NAME"] = "foo"
    exporter_dict["IP"] = "10.1.1.1"
    exporter_dict["VRF"] = "default"
    exporter_dict["SRC_IF_NAME"] = "Loopback0"
    exporter_dict["UDP_PORT"] = "5050"
    record_dict = {}
    record_dict["RECORD_NAME"] = "foo"
    record_dict["RECORD_TEMPLATE"] = "netflow_ipv4_record"
    record_dict["LAYER2_RECORD"] = False
    monitor_dict = {}
    monitor_dict["MONITOR_NAME"] = "netflow-monitor"
    monitor_dict["RECORD_NAME"] = "ipv4-record"
    monitor_dict["EXPORTER1"] = "exporter1"
    monitor_dict["EXPORTER2"] = "exporter2"
    test_name = "netflow"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = 65008
    config["enable_netflow"] = True
    config["netflow_exporter_list"] = [exporter_dict]
    config["netflow_record_list"] = [record_dict]
    config["netflow_monitor_list"] = [monitor_dict]
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_vrf_lite():
    test_name = "vrf_lite"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["auto_symmetric_vrf_lite"] = True
    config["vrf_lite_autoconfig"] = 1
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

def test_queuing():
    test_name = "queuing"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["enable_default_queuing_policy"] = True
    config["default_queuing_policy_cloudscale"] = "queuing_policy_default_4q_cloudscale"
    config["default_queuing_policy_other"] = "queuing_policy_default_other"
    config["default_queuing_policy_r_series"] = "queuing_policy_default_r_series"
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload, False)

test_aaa()
test_bfd()
test_bootstrap()
test_bgp_auth()
test_dns_server_ip_list()
test_macsec_cipher_suite()
test_mpls_handoff()
test_netflow()
test_vrf_lite()
test_queuing()