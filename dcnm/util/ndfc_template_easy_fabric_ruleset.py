#!/usr/bin/env python
"""
Print ruleset for the NDFC Easy Fabric Template.
"""
from ndfc_template_easy_fabric import NdfcTemplateEasyFabric

# TODO:2 replace base_path with the official repo location
# We may have to read an environment variable to get this.
base_path = "/Users/arobel/repos/ansible_modules/dcnm/util/templates/12_1_3b"
ef_json = f"{base_path}/Easy_Fabric.json"

template = NdfcTemplateEasyFabric()
template.template_json = ef_json
template.load()
template.build_ruleset()
for key in template.ruleset:
    print(f"{key}: {template.ruleset[key]}")

print("Usage example:")

parameter = "unnum_dhcp_end"
bootstrap_enable = True
inband_mgmt = True
dhcp_enable = True
fabric_interface_type = "unnumbered"
print(f"parameter {parameter} ruleset: {template.ruleset[parameter]}")
result = eval(f"{template.ruleset[parameter]}")
if result:
    print(f"parameter {parameter} is mandatory")
else:
    print(f"parameter {parameter} is optional")
