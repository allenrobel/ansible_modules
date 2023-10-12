#!/usr/bin/env python
"""
Print Ansible documentation for the NDFC Easy Fabric Template.

Use documentation_json to print the documentation in JSON format.
Use documentation_yaml to print the documentation in YAML format.
"""
from ndfc_template_easy_fabric import NdfcTemplateEasyFabric
from ndfc_template_all import NdfcTemplates

# TODO:2 replace base_path with the official repo location
# We may have to read an environment variable to get this.
base_path = "/Users/arobel/repos/ansible_modules/dcnm/util/templates/12_1_3b"
ef_json = f"{base_path}/Easy_Fabric.json"
all_json = f"{base_path}/templates.json"

ef_template = NdfcTemplateEasyFabric()
ef_template.template_json = ef_json
ef_template.load()

# NdfcTemplates() instance is required to get the choices for
# several EasyFabric parameters e.g. default_network_universal
# choices of Default_Network_Universal and Service_Network_Universal
all_template = NdfcTemplates()
all_template.template_json = all_json
all_template.load()

ef_template.template_all = all_template
ef_template.build_documentation()
#ef_template.documentation_json()
ef_template.documentation_yaml()