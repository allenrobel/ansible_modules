#!/usr/bin/env python
"""
Name: ndfc_template.py
Description:

Superclass for NdfcTemplateEasyFabric() and NdfcTemplateAll()
"""
import re
import sys
import json

class NdfcTemplate:
    """
    Superclass for NdfcTemplate*() classes
    """
    def __init__(self):
        self._properties = {}
        self._properties["template_json"] = None

    @property
    def template(self):
        return self._properties["template"]
    @template.setter
    def template(self, value):
        """
        The template contents supported by the subclass
        """
        self._properties["template"] = value

    @property
    def template_json(self):
        return self._properties["template_json"]
    @template_json.setter
    def template_json(self, value):
        """
        Full path to a file containing the template content
        in JSON format
        """
        self._properties["template_json"] = value

    @staticmethod
    def make_bool(value):
        """
        Translate various string values to a boolean value
        """
        if value in ["true", "yes", "True", "Yes", "TRUE", "YES"]:
            return True
        if value in ["false", "no", "False", "No", "FALSE", "NO"]:
            return False
        return value

    @staticmethod
    def clean_string(string):
        """
        Remove unwanted characters found in various locations
        within the returned NDFC JSON.
        """
        sting = string.strip()
        string = re.sub('<br />', ' ', string)
        string = re.sub('&#39;', '', string)
        string = re.sub('&#43;', '+', string)
        string = re.sub('&#61;', '=', string)
        string = re.sub('amp;', '', string)
        string = re.sub('\[', '', string)
        string = re.sub('\]', '', string)
        string = re.sub('\"', '', string)
        string = re.sub("\'", '', string)
        string = re.sub(r"\s+", " ", string)
        return string

    def load(self):
        """
        Load the template from a JSON file
        """
        if self.template_json is None:
            msg = "exiting. set instance.template_json to the file "
            msg += "path of the JSON content before calling "
            msg += "load_template()"
            print(f"{msg}")
            sys.exit(1)
        with open(self.template_json, 'r', encoding="utf-8") as handle:
            self.template = json.load(handle)
