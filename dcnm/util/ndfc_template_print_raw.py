#!/usr/bin/env python
"""
Name: ndfc_template_print_raw.py
Description:

Pretty print a raw template file retrieved from NDFC.
"""
from ndfc_template_raw import NdfcTemplateRaw
from optparse import OptionParser
import sys

parser = OptionParser()
parser.add_option("-t", "--template", dest="template_name",
                  help="Name of the template to pretty-print",
                  metavar="TEMPLATE_NAME")

(options, args) = parser.parse_args()
if options.template_name is None:
    parser.error("Need a template name. E.g. --template aaa_radius")
    sys.exit(1)

base_path = "/Users/arobel/repos/ansible_modules/dcnm/util/templates/12_1_3b"
template = NdfcTemplateRaw()
template.template_json = f"{base_path}/{options.template_name}.json"
template.load()
template.delete_key("content", template.template)
template.delete_key("newContent", template.template)
template.print_json()
