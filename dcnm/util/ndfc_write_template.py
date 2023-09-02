#!/usr/bin/env python
"""
Write an NDFC template to a file.
"""
from ndfc_get_template import NdfcGetTemplate
from ndfc import NDFC, SimpleLogger

logger = SimpleLogger()
ndfc = NDFC()
ndfc.ip4 = "172.22.150.244"
ndfc.username = "admin"
ndfc.password = "ins3965!"
ndfc.log = logger
ndfc.login()

template = NdfcGetTemplate()
template.ndfc = ndfc
template.template = "easy_fabric"
template.filename = "easy_fabric_v12_1_3b.json"
template.get_template()
template.write_template()
