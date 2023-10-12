#!/usr/bin/env python

switch_details = {'172.22.150.103': {'switchRoleEnum': 'Leaf', 'vrf': 'management', 'fabricTechnology': 'VXLANFabric', 'deviceType': 'Switch_Fabric', 'fabricId': 2, 'name': None, 'domainID': 0, 'wwn': None, 'membership': None, 'ports': 0, 'model': 'N9K-C93180YC-EX', 'version': None, 'upTime': 0, 'ipAddress': '172.22.150.103', 'mgmtAddress': None, 'vendor': 'Cisco', 'displayHdrs': None, 'displayValues': None, 'colDBId': 0, 'fid': 0, 'isLan': False, 'is_smlic_enabled': False, 'present': True, 'licenseViolation': False, 'managable': True, 'mds': False, 'connUnitStatus': 0, 'standbySupState': 0, 'activeSupSlot': 0, 'unmanagableCause': '', 'lastScanTime': 0, 'fabricName': 'fff', 'modelType': 0, 'logicalName': 'cvd-1312-leaf', 'switchDbID': 8430, 'uid': 0, 'release': '10.3(2)', 'location': None, 'contact': None, 'upTimeStr': '18:45:48', 'upTimeNumber': 0, 'network': None, 'nonMdsModel': None, 'numberOfPorts': 0, 'availPorts': 0, 'usedPorts': 0, 'vsanWwn': None, 'vsanWwnName': None, 'swWwn': None, 'swWwnName': None, 'serialNumber': 'FDO211218GC', 'domain': None, 'principal': None, 'status': 'ok', 'index': 0, 'licenseDetail': None, 'isPmCollect': False, 'sanAnalyticsCapable': False, 'vdcId': 0, 'vdcName': '', 'vdcMac': None, 'fcoeEnabled': False, 'cpuUsage': 0, 'memoryUsage': 0, 'scope': None, 'fex': False, 'health': -1, 'npvEnabled': False, 'linkName': None, 'username': None, 'primaryIP': '', 'primarySwitchDbID': 0, 'secondaryIP': '', 'secondarySwitchDbID': 0, 'isEchSupport': False, 'moduleIndexOffset': 9999, 'sysDescr': '', 'isTrapDelayed': False, 'switchRole': 'leaf', 'mode': 'Normal', 'hostName': 'cvd-1312-leaf', 'ipDomain': '', 'systemMode': 'Normal', 'sourceVrf': 'management', 'sourceInterface': 'mgmt0', 'protoDiscSettings': None, 'operMode': None, 'modules': None, 'fexMap': {}, 'isVpcConfigured': False, 'vpcDomain': 0, 'role': None, 'peer': None, 'peerSerialNumber': None, 'peerSwitchDbId': 0, 'peerlinkState': None, 'keepAliveState': None, 'consistencyState': False, 'sendIntf': None, 'recvIntf': None, 'interfaces': None, 'elementType': None, 'monitorMode': None, 'freezeMode': None, 'cfsSyslogStatus': 1, 'isNonNexus': False, 'swUUIDId': 4750, 'swUUID': 'DCNM-UUID-4750', 'swType': None, 'ccStatus': 'NA', 'operStatus': 'Minor', 'intentedpeerName': ''}}

def switch_fabric_name(ip_address):
    """
    Return the fabricName of the switch with ip_address, if it exists.
    Return None otherwise
    """
    return switch_details.get(ip_address, {}).get("fabricName")

def switch_hostname(ip_address):
    """
    Return the hostName of the switch with ip_address, if it exists.
    Return None otherwise
    """
    return switch_details.get(ip_address, {}).get("hostName")

def switch_logical_name(ip_address):
    """
    Return the logicalName of the switch with ip_address, if it exists.
    Return None otherwise
    """
    return switch_details.get(ip_address, {}).get("logicalName")

def switch_model(ip_address):
    """
    Return the model of the switch with ip_address, if it exists.
    Return None otherwise
    """
    return switch_details.get(ip_address, {}).get("model")

def switch_platform(ip_address):
    """
    Return the platform of the switch with ip_address, if it exists.
    Return None otherwise
    """
    model = switch_model(ip_address)
    if model is None:
        return None
    return model.split("-")[0]

def switch_role(ip_address):
    """
    Return the switchRole of the switch with ip_address, if it exists.
    Return None otherwise
    """
    return switch_details.get(ip_address, {}).get("switchRole")

def switch_serial_number(ip_address):
    """
    Return the serialNumber of the switch with ip_address, if it exists.
    Return None otherwise
    """
    return switch_details.get(ip_address, {}).get("serialNumber")

ip = "172.22.150.103"

for function in [switch_fabric_name, switch_hostname, switch_logical_name, switch_model, switch_platform, switch_role, switch_serial_number]:
    print("{:<25} {:<50}".format(function.__name__, function(ip)))

