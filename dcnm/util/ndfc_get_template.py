#!/usr/bin/env python
"""
Name: ndfc_get_template.py
Description:

Retrieve an NDFC template and write it as a JSON file.

Supported templates are:
    easy_fabric - Easy Fabric Template
    templates - All Templates
"""
import sys

class NdfcGetTemplate:
    def __init__(self):
        self._properties = {}
        self._properties["ndfc"] = None
        self._properties["template"] = None
        self._properties["filename"] = None
        self._url_base = "/appcenter/cisco/ndfc/api/v1/configtemplate/rest/config/templates"

    @property
    def ndfc(self):
        return self._properties["ndfc"]
    @ndfc.setter
    def ndfc(self, value):
        self._properties["ndfc"] = value

    @property
    def template(self):
        return self._properties["template"]
    @template.setter
    def template(self, value):
        self._properties["template"] = value

    @property
    def filename(self):
        return self._properties["filename"]
    @filename.setter
    def filename(self, value):
        self._properties["filename"] = value

    def get_url(self):
        if self.ndfc == None:
            print("Exiting. ndfc property is not set")
            sys.exit(1)
        if self.template == None:
            print("Exiting. template property is not set")
            sys.exit(1)
        if self.template == "templates":
            url = f"https://{self.ndfc.ip4}/{self._url_base}"
        else:
            url = f"https://{self.ndfc.ip4}/{self._url_base}/{self.template}"
        return url

    def get_template(self):
        url = self.get_url()
        self.ndfc.get(url, self.ndfc.make_headers())
        if self.ndfc.response.status_code != 200:
            msg = f"exiting. got non-200 status code {self.ndfc.response.status_code} "
            msg += f"for url {url}"
            self.ndfc.log.error(msg)
            sys.exit(1)
        self.template_json = self.ndfc.response.text

    def write_template(self):
        if self.template_json == None:
            msg = "Exiting. Call instance.get_template() before "
            msg += "calling instance.write_template()"
            self.ndfc.log.error(msg)
            sys.exit(1)
        if self.filename == None:
            msg = "Exiting. Set instance.filename property before "
            msg += "calling instance.write_template()"
            self.ndfc.log.error(msg)
            sys.exit(1)
        with open(self.filename, "w") as f:
            f.write(self.template_json)
