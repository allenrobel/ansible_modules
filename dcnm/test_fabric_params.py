#!/usr/bin/env python
from ansible_collections.cisco.dcnm.plugins.module_utils.fabric.fabric import (
    VerifyFabricParams,
)
SHOW_PAYLOAD = False

def print_result(result, msg, payload):
    _payload = ""
    if SHOW_PAYLOAD:
        _payload = f", payload {payload}"
    print(f"result {result}, message {msg}{_payload}")

def test_bfd():
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
    print_result(verify.result, verify.msg, verify.payload)

def test_vrf_lite():
    config = {}
    config["fabric_name"] = "foo"
    config["bgp_as"] = "65000.869"
    config["auto_symmetric_vrf_lite"] = True
    config["vrf_lite_autoconfig"] = 0
    verify = VerifyFabricParams()
    verify.config = config
    verify.state = "merged"
    verify.validate_config()
    print_result(verify.result, verify.msg, verify.payload)

test_bfd()
test_vrf_lite()