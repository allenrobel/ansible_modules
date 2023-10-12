#!/usr/bin/env python
"""
Print Ansible documentation for the NDFC Easy Fabric Template.

Use documentation_json to print the documentation in JSON format.
Use documentation_yaml to print the documentation in YAML format.
"""
from ndfc_template_custom_swift_issu import NdfcTemplateCustomSwiftIssu

# TODO:2 replace base_path with the official repo location
# We may have to read an environment variable to get this.
base_path = "/Users/arobel/repos/ansible_modules/dcnm/util/templates/12_1_3b"
template_json = f"{base_path}/custom_swift_issu.json"

template = NdfcTemplateCustomSwiftIssu()
template.template_json = template_json
template.load()

template.build_documentation()
#template.documentation_json()
template.documentation_yaml()