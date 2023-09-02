#!/usr/bin/env python
"""
Name: ndfc_template_easy_fabric.py
Description:

Generate documetation from previously-stored NDFC EasyFabric template.

The stored JSON should have been retieved via the following URL:

https://<ndfc_ip>/appcenter/cisco/ndfc/api/v1/configtemplate/rest/config/templates/Easy_Fabric #noqa
"""
import json
import re
import sys
import yaml
from ndfc_template import NdfcTemplate

class NdfcTemplateEasyFabric(NdfcTemplate):
    def __init__(self):
        super().__init__()
        self.translation = None
        self.suboptions = None
        self.documentation = None

    @property
    def template_all(self):
        return self._properties["template_all"]
    @template_all.setter
    def template_all(self, value):
        """
        An instance of NdfcTemplateAll()
        """
        self._properties["template_all"] = value

    def is_internal(self, item):
        """
        Return True if item["annotations"]["IsInternal"] is True
        Return False otherwise
        """
        if not item.get("annotations", None):
            return False
        if not item["annotations"].get("IsInternal", None):
            return False
        return self.make_bool(item["annotations"]["IsInternal"])

    def is_mandatory(self, item):
        """
        Return True if item["annotations"]["IsMandatory"] is True
        Return False otherwise
        """
        if not item.get("annotations", None):
            return False
        if not item["annotations"].get("IsMandatory", None):
            return False
        return self.make_bool(item["annotations"]["IsMandatory"])

    @staticmethod
    def is_hidden(item):
        """
        Return True if item["annotations"]["Section"] is "Hidden"
        Return False otherwise
        """
        if not item.get("annotations", None):
            return False
        if not item["annotations"].get("Section", None):
            return False
        if "Hidden" in item["annotations"]["Section"]:
            return True
        return False

    def init_translation(self):
        """
        All parameters in the playbook are lowercase dunder, while
        NDFC nvPairs contains a mish-mash of styles (and typos),
        for example:
        - enableScheduledBackup
        - default_vrf
        - REPLICATION_MODE
        - DEAFULT_QUEUING_POLICY_CLOUDSCALE

        This method builds a dictionary which maps between NDFC's expected
        parameter names and the corresponding playbook names.
        e.g.:
        DEAFULT_QUEUING_POLICY_CLOUDSCALE -> default_queuing_policy_cloudscale

        The dictionary excludes hidden and internal parameters.
        """
        if self.template is None:
            msg = "exiting. call instance.load_template() first."
            print(f"{msg}")
            sys.exit(1)
        re_uppercase_dunder = "^[A-Z0-9_]+$"
        self.translation = {}
        typo_keys = {
            "DEAFULT_QUEUING_POLICY_CLOUDSCALE": "default_queuing_policy_cloudscale",
            "DEAFULT_QUEUING_POLICY_OTHER": "default_queuing_policy_other",
            "DEAFULT_QUEUING_POLICY_R_SERIES": "default_queuing_policy_r_series",
        }
        camel_keys = {
            "enableRealTimeBackup": "enable_real_time_backup",
            "enableScheduledBackup": "enable_scheduled_backup",
            "scheduledTime": "scheduled_time",
        }
        other_keys = {
            "VPC_ENABLE_IPv6_ND_SYNC": "vpc_enable_ipv6_nd_sync",
            "default_vrf": "default_vrf",
            "default_network": "default_network",
            "vrf_extension_template": "vrf_extension_template",
            "network_extension_template": "network_extension_template",
            "default_pvlan_sec_network": "default_pvlan_sec_network",
        }
        for item in self.template.get("parameters"):
            if self.is_internal(item):
                continue
            if self.is_hidden(item):
                continue
            if not item.get('name', None):
                continue
            if item['name'] in typo_keys:
                self.translation[item['name']] = typo_keys[item['name']]
                continue
            if item['name'] in camel_keys:
                self.translation[item['name']] = camel_keys[item['name']]
                continue
            if item['name'] in other_keys:
                self.translation[item['name']] = other_keys[item['name']]
                continue
            if re.search(re_uppercase_dunder, item['name']):
                self.translation[item['name']] = item['name'].lower()

    def default(self, item):
        """
        Return the default value for item, i.e.:
        item["metaProperties"]["defaultValue"]
        """
        if "metaProperties" not in item:
            return None
        if "defaultValue" not in item["metaProperties"]:
            return None
        default = self.make_bool(item["metaProperties"]["defaultValue"])
        try:
            default = int(default)
        except ValueError:
            pass
        return default

    def choices(self, item):
        """
        Return the choices for an item as a list(), i.e.:
        item["annotations"]["Enum"]
        """
        if "annotations" not in item:
            return []
        if "Enum" not in item["annotations"]:
            return []
        choices = self.clean_string(item["annotations"]["Enum"])
        choices = choices.split(",")
        try:
            choices = [int(x) for x in choices]
        except ValueError:
            pass
        return choices

    def description(self, item):
        """
        Return the description of an item, i.e.:
        item['annotations']['Description']
        """
        try:
            description = item['annotations']['Description']
        except KeyError:
            description = "unknown"
        return self.clean_string(description)

    @staticmethod
    def param_type(item):
        """
        Return the parameter type of an item, i.e.:
        item['parameterType']

        This is translated to the Ansible type, e.g.
        string -> str
        boolean -> bool
        ipV4Address -> ipv4
        etc.
        """
        ndfc_type = item.get('parameterType', None)
        if ndfc_type is None:
            return None
        if ndfc_type in ["STRING", "string", "str"]:
            return "str"
        if ndfc_type in ["INTEGER", "INT", "integer", "int"]:
            return "int"
        if ndfc_type in ["BOOLEAN", "boolean", "bool"]:
            return "bool"
        if ndfc_type in ["ipAddress", "ipV4Address"]:
            return "ipv4"
        if ndfc_type in ["ipV4AddressWithSubnet"]:
            return "ipv4_subnet"
        if ndfc_type in ["ipV6Address"]:
            return "ipv6"
        if ndfc_type in ["ipV6AddressWithSubnet"]:
            return "ipv6_subnet"
        return ndfc_type

    def is_required(self,item):
        """
        Return the required status of an item, i.e.:
        The inverse of item['optional']
        """
        optional = self.make_bool(item.get('optional', None))
        if optional is True:
            return False
        if optional is False:
            return True
        return "unknown"

    def min_max(self, item):
        """
        Return the min and max values of an item, i.e.:
        If item['annotations']['Description'] contains
        "(Min: X, Max: Y)" return int(X), and int(Y)
        Otherwise return None, None
        """
        description = self.description(item)
        # (Min:240, Max:3600)
        m = re.search("\(Min:\s*(\d+),\s*Max:\s*(\d+)\)", description)
        if m:
            return int(m.group(1)), int(m.group(2))
        return None, None

    def label(self, item):
        """
        Return the NDFC GUI label for an item, i.e.:
        item['annotations']['DisplayName']
        """
        label = item.get('annotations', {}).get('DisplayName', None)
        if label is None:
            return None
        return self.clean_string(label)

    def section(self, item):
        """
        Return the NDFC GUI section/tab for an item, i.e.:
        item['annotations']['Section']
        """
        section = item.get('annotations', {}).get('Section', None)
        if section is None:
            return None
        return self.clean_string(section)

    def build_documentation(self):
        """
        Build the documentation for the EasyFabric template.
        """
        if self.template is None:
            msg = "exiting. call instance.load_template() first."
            print(f"{msg}")
            sys.exit(1)
        if self.template_all is None:
            msg = "exiting. call instance.template_all first."
            print(f"{msg}")
            sys.exit(1)
        if self.translation is None:
            self.init_translation()
        self.documentation = {}
        self.documentation["module"] = "dcnm_easy_fabric"
        self.documentation["author"] = "Cisco Systems, Inc."
        self.documentation["description"] = []
        try:
            description = self.template['description'].strip()
            self.documentation["description"].append(description)
        except KeyError:
            self.documentation["description"].append("unknown")
        self.documentation["options"] = {}
        self.documentation["options"]["state"] = {}
        self.documentation["options"]["state"]["description"] = []
        value = "The state of DCNM after module completion"
        self.documentation["options"]["state"]["description"].append(value)
        value = "I(merged) and I(query) are the only states supported."
        self.documentation["options"]["state"]["description"].append(value)
        self.documentation["options"]["state"]["type"] = "str"
        self.documentation["options"]["state"]["choices"] = ["merged", "query"]
        self.documentation["options"]["state"]["default"] = "merged"
        self.documentation["options"]["config"] = {}
        self.documentation["options"]["config"]["description"] = []
        value = "A list of fabric configuration dictionaries"
        self.documentation["options"]["config"]["description"].append(value)
        self.documentation["options"]["config"]["type"] = "list"
        self.documentation["options"]["config"]["elements"] = "dict"
        self.documentation["options"]["config"]["suboptions"] = {}

        suboptions = {}
        for item in self.template.get("parameters"):
            if self.is_internal(item):
                continue
            if self.is_hidden(item):
                continue
            if not item.get('name', None):
                continue
            name = self.translation.get(item['name'], None)
            if name is None:
                print(f"WARNING: skipping {item['name']}")
                continue
            suboptions[name] = {}
            suboptions[name]["description"] = []
            suboptions[name]["description"].append(self.description(item))
            suboptions[name]["type"] = self.param_type(item)
            suboptions[name]["required"] = self.is_required(item)
            default = self.default(item)
            if default is not None:
                suboptions[name]["default"] = default
            choices  = self.choices(item)
            if len(choices) > 0:
                if "TEMPLATES" in str(choices[0]):
                    tag = str(choices[0]).split(".")[1]
                    choices = self.template_all.get_templates_by_tag(tag)
                suboptions[name]["choices"] = choices
            min_value, max_value = self.min_max(item)
            if min_value is not None:
                suboptions[name]["min"] = min_value
            if max_value is not None:
                suboptions[name]["max"] = max_value
            ndfc_label = self.label(item)
            if ndfc_label is not None:
                suboptions[name]["ndfc_gui_label"] = ndfc_label
            ndfc_section = self.section(item)
            if ndfc_section is not None:
                suboptions[name]["ndfc_gui_section"] = ndfc_section

        self.documentation["options"]["config"]["suboptions"] = []
        for key in sorted(suboptions.keys()):
            self.documentation["options"]["config"]["suboptions"].append({key: suboptions[key]})

    def documentation_yaml(self):
        """
        Dump the documentation in YAML format
        """
        if self.documentation is None:
            self.build_documentation()
        print(yaml.dump(self.documentation, indent=4))

    def documentation_json(self):
        """
        Dump the documentation in JSON format
        """
        if self.documentation is None:
            self.build_documentation()
        print(json.dumps(self.documentation, indent=4))
