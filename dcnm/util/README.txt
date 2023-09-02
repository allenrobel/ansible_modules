Several utilities for retrieving and parsing NDFC templates

Scripts:

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

Classes:

NdfcTemplateEasyFabric(), ndfc_template_easy_fabric.py
    -   Methods to load, parse, and print documetation
        for the NDFC Easy_Fabric template.
NdfcTemplates(), ndfc_template_all.py
    -   Methods to load and parse the list of all NDFC templates
NdfcTemplate(), ndfc_template.py
    -   superclass for NdfcTemplateEasyFabric() and NdfcTemplates()
NdfcGetTemplate(), ndfc_get_template.py
    -   Methods to retrieve templates from NDFC and write them
        as JSON files.

