#!/usr/bin/env python
"""
Name: ndfc_template_all.py

Description:

Retrieve and process previously-stored list of NDFC templates.

The stored JSON should have been retieved from the following URL:

https://<ndfc_ip>/appcenter/cisco/ndfc/api/v1/configtemplate/rest/config/templates #noqa
"""
import json
import sys
import yaml
from ndfc_template import NdfcTemplate

class NdfcTemplateRaw(NdfcTemplate):
    def __init__(self):
        super().__init__()

    def validate_base_prerequisites(self):
        """
        1. Validate that the prerequisites are met before proceeding.
            Specifically:
            - User has set self.template
        2. Call self.init_translation() if self.translation is None
        """
        if self.template_json is None:
            msg = "exiting. call instance.load_template() first."
            print(f"{msg}")
            sys.exit(1)
        if self.template is None:
            self.load()


    def print_yaml(self):
        """
        Dump the template in YAML format
        """
        self.validate_base_prerequisites()
        print(yaml.dump(self.template, indent=4))

    def print_json(self):
        """
        Dump the documentation in JSON format
        """
        self.validate_base_prerequisites()
        print(json.dumps(self.template, indent=4))
