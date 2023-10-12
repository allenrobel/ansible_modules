Several utilities for retrieving and parsing NDFC templates

Classes:

NdfcTemplate(), ndfc_template.py
    -   superclass for NdfcTemplateEasyFabric() and NdfcTemplates()
NdfcTemplateEasyFabric(), ndfc_template_easy_fabric.py
    -   Methods to load, parse, and print documetation
        for the NDFC Easy_Fabric template.
NdfcTemplates(), ndfc_template_all.py
    -   Methods to load and parse the list of all NDFC templates
NdfcGetTemplate(), ndfc_get_template.py
    -   Methods to retrieve templates from NDFC and write them
        as JSON files.

Scripts:

ndfc_template_easy_fabric_ruleset.py
  - Convert rulesets to python
  - As an example, use EasyFabric template
  - For a given parameter, set a couple parameters and eval() the converted pythonized ruleset

ndfc_write_template.py
  - Write an NDFC template to a file
  - Uses the following:
    -   NdfcGetTemplate(), ndfc_get_template.py
    -   NDFC(),SimpleLogger(), ndfc.py

ndfc_template_easy_fabric_documentation.py
    - Generate Ansible documentation for the dcnm.dcnm_easy_fabric module
    - Uses the following:
        -   NdfcTemplateEasyFabric(), ndfc_template_easy_fabric.py
        -   NdfcTemplates(), ndfc_templates.py
