#!/usr/bin/env python
"""
Name: ndfc_template_all.py

Description:

Retrieve and process previously-stored list of NDFC templates.

The stored JSON should have been retieved from the following URL:

https://<ndfc_ip>/appcenter/cisco/ndfc/api/v1/configtemplate/rest/config/templates #noqa
"""
import sys
from ndfc_template import NdfcTemplate

class NdfcTemplates(NdfcTemplate):
    def __init__(self):
        super().__init__()

    def get_templates_by_tag(self, tag):
        """
        return a list of template names that match tag
        """
        if self.template is None:
            msg = "exiting. call instance.load_template() first."
            print(f"{msg}")
            sys.exit(1)
        template_list = []
        for template in self.template:
            tags = template.get("tags", None)
            if tags is None:
                continue
            tags = self.clean_string(tags)
            tags = tags.split(",")
            tags = [x.strip() for x in tags]
            if tag not in tags:
                continue
            template_list.append(template.get("name", None))
        return template_list



