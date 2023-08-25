#!/usr/bin/env python
from ansible_collections.cisco.dcnm.plugins.module_utils.fabric.fabric import (
    VerifyFabricParams,
)
SHOW_PAYLOAD = False

def print_result(test_name, result, msg, payload):
    _payload = ""
    if SHOW_PAYLOAD:
        _payload = f", payload {payload}"
    print(f"{test_name}: result {result}, message {msg}{_payload}")

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
    print_result(test_name, verify.result, verify.msg, verify.payload)

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
    print_result(test_name, verify.result, verify.msg, verify.payload)

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
    print_result(test_name, verify.result, verify.msg, verify.payload)

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
    print_result(test_name, verify.result, verify.msg, verify.payload)

def test_macsec_cipher_suite():
    test_name = "macsec_cipher_suite"
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["enable_macsec"] = True
    config["macsec_algorithm"] = 1
    config["macsec_cipher_suite"] = 3
    config["macsec_fallback_algorithm"] = 1
    config["macsec_fallback_key_string"] = "f77844"
    config["macsec_key_string"] = "f77844"
    config["macsec_report_timer"] = 10
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(test_name, verify.result, verify.msg, verify.payload)

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
    print_result(test_name, verify.result, verify.msg, verify.payload)

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
    print_result(test_name, verify.result, verify.msg, verify.payload)

test_bfd()
test_bootstrap()
test_bgp_auth()
test_dns_server_ip_list()
test_macsec_cipher_suite()
test_vrf_lite()
test_queuing()