#!/usr/bin/env python
import sys
from ansible_collections.cisco.dcnm.plugins.module_utils.fabric.fabric import (
    VerifyFabricParams,
)

config = {}
config["fabric_name"] = "foo"
config["bgp_as"] = "65000.869"
config["auto_symmetric_vrf_lite"] = True
config["vrf_lite_autoconfig"] = 0
verify = VerifyFabricParams()
verify.config = config
verify.state = "merged"
verify.validate_config()
if verify.result == False:
    print(f"result {verify.result}, message {verify.msg}")
    sys.exit(1)
print(f"result {verify.result}, message {verify.msg}, payload {verify.payload}")
