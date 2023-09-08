#!/usr/bin/env python
"""
Write an NDFC template to a file.
"""
from ndfc_get_template import NdfcGetTemplate
from ndfc import NDFC, SimpleLogger
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

template_dir = "/Users/arobel/repos/ansible_modules/dcnm/util/templates/12_1_3b"
logger = SimpleLogger()
ndfc = NDFC()
ndfc.ip4 = "172.22.150.244"
ndfc.username = "admin"
ndfc.password = "ins3965!"
ndfc.log = logger
ndfc.login()

template = NdfcGetTemplate()
template.ndfc = ndfc
template.template = options.template_name
template.filename = f"{template_dir}/{template.template}.json"
template.get_template()
template.write_template()
