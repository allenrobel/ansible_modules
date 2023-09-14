#!/usr/bin/env python
import json
import re

def easy_fabric_template():
    template = """{
    "instanceClassId": 1000,
    "assignedInstanceClassId": 0,
    "instanceName": "com.cisco.dcbu.dcm.model.cfgtemplate.ConfigTemplate:name=Easy_Fabric:type=true",
    "name": "Easy_Fabric",
    "description": " Fabric for a VXLAN EVPN deployment with Nexus 9000 and 3000 switches.",
    "userDefined": true,
    "parameters": [
        {
            "name": "FABRIC_NAME",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "32"
            },
            "annotations": {
                "DisplayName": "Fabric Name",
                "Description": "Please provide the fabric name to create it (Max Size 32)",
                "IsMandatory": "true",
                "IsFabricName": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BGP_AS",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "regularExpr": "^(((\\+)?[1-9]{1}[0-9]{0,8}|(\\+)?[1-3]{1}[0-9]{1,9}|(\\+)?[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])(\\.([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]|0))?)$",
                "minLength": "1",
                "maxLength": "11"
            },
            "annotations": {
                "DisplayName": "BGP ASN",
                "Description": "1-4294967295 | 1-65535[.0-65535]<br />It is a good practice to have a unique ASN for each Fabric.",
                "IsAsn": "true",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BGP_AS_PREV",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "UNDERLAY_IS_V6",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable IPv6 Underlay",
                "Description": "If not enabled, IPv4 underlay is used",
                "IsMandatory": "false"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "USE_LINK_LOCAL",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable IPv6 Link-Local Address",
                "IsShow": "\"UNDERLAY_IS_V6==true\"",
                "Description": "If not enabled, Spine-Leaf interfaces will use global IPv6 addresses",
                "IsMandatory": "false"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "FABRIC_INTERFACE_TYPE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "p2p"
            },
            "annotations": {
                "Enum": "\"p2p,unnumbered\"",
                "DisplayName": "Fabric Interface Numbering",
                "IsShow": "\"UNDERLAY_IS_V6!=true\"",
                "Description": "Numbered(Point-to-Point) or Unnumbered",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "SUBNET_TARGET_MASK",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "30",
                "max": "31",
                "defaultValue": "30"
            },
            "annotations": {
                "Enum": "\"30,31\"",
                "DisplayName": "Underlay Subnet IP Mask",
                "IsShow": "\"UNDERLAY_IS_V6==false\"",
                "Description": "Mask for Underlay Subnet IP Range",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "V6_SUBNET_TARGET_MASK",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "126",
                "max": "127",
                "defaultValue": "126"
            },
            "annotations": {
                "Enum": "\"126,127\"",
                "DisplayName": "Underlay Subnet IPv6 Mask",
                "IsShow": "\"UNDERLAY_IS_V6==true && USE_LINK_LOCAL==false\"",
                "Description": "Mask for Underlay Subnet IPv6 Range",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "LINK_STATE_ROUTING",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "ospf"
            },
            "annotations": {
                "Enum": "\"ospf,is-is\"",
                "DisplayName": "Underlay Routing Protocol",
                "Description": "Used for Spine-Leaf Connectivity",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "RR_COUNT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "defaultValue": "2"
            },
            "annotations": {
                "Enum": "\"2,4\"",
                "DisplayName": "Route-Reflectors",
                "Description": "Number of spines acting as Route-Reflectors",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ANYCAST_GW_MAC",
            "description": null,
            "parameterType": "macAddress",
            "metaProperties": {
                "defaultValue": "2020.0000.00aa"
            },
            "annotations": {
                "DisplayName": "Anycast Gateway MAC",
                "IsAnycastGatewayMac": "true",
                "Description": "Shared MAC address for all leafs (xxxx.xxxx.xxxx)",
                "IsMandatory": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PM_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Performance Monitoring",
                "NoConfigChg": "true",
                "IsMandatory": "false"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PM_ENABLE_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "REPLICATION_MODE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Multicast"
            },
            "annotations": {
                "Enum": "\"Multicast,Ingress\"",
                "Description": "Replication Mode for BUM Traffic",
                "IsMandatory": "true",
                "DisplayName": "Replication Mode",
                "IsShow": "\"UNDERLAY_IS_V6!=true\"",
                "IsReplicationMode": "true",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MULTICAST_GROUP_SUBNET",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "239.1.1.0/25"
            },
            "annotations": {
                "IsMulticastGroupSubnet": "true",
                "Description": "Multicast pool prefix between 8 to 30. A multicast group IP<br />from this pool is used for BUM traffic for each overlay network.",
                "IsMandatory": "true",
                "DisplayName": "Multicast Group Subnet",
                "IsShow": "\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\"",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ENABLE_TRM",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Tenant Routed Multicast (TRM)",
                "IsShow": "\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\"",
                "Description": "For Overlay Multicast Support In VXLAN Fabrics",
                "IsMandatory": "false",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "L3VNI_MCAST_GROUP",
            "description": null,
            "parameterType": "ipV4Address",
            "metaProperties": {
                "defaultValue": "239.1.1.0"
            },
            "annotations": {
                "Description": "Default Underlay Multicast group IP assigned for every overlay VRF.",
                "IsMandatory": "true",
                "DisplayName": "Default MDT Address for TRM VRFs",
                "IsShow": "\"REPLICATION_MODE==Multicast && ENABLE_TRM==true && UNDERLAY_IS_V6!=true\"",
                "Section": "\"Replication\"",
                "IsMcastUnderlay": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "RP_COUNT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "defaultValue": "2"
            },
            "annotations": {
                "Enum": "\"2,4\"",
                "Description": "Number of spines acting as Rendezvous-Point (RP)",
                "IsMandatory": "true",
                "DisplayName": "Rendezvous-Points",
                "IsShow": "\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\"",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "RP_MODE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "asm"
            },
            "annotations": {
                "Enum": "\"asm,bidir\"",
                "Description": "Multicast RP Mode",
                "IsMandatory": "true",
                "DisplayName": "RP Mode",
                "IsShow": "\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\"",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "RP_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "254"
            },
            "annotations": {
                "DisplayName": "Underlay RP Loopback Id",
                "IsShow": "\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\"",
                "Description": "(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PHANTOM_RP_LB_ID1",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "2"
            },
            "annotations": {
                "DisplayName": "Underlay Primary <br />RP Loopback Id",
                "IsShow": "\"REPLICATION_MODE==Multicast && RP_MODE==bidir && UNDERLAY_IS_V6!=true\"",
                "Description": "Used for Bidir-PIM Phantom RP <br />(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PHANTOM_RP_LB_ID2",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "3"
            },
            "annotations": {
                "DisplayName": "Underlay Backup <br />RP Loopback Id",
                "IsShow": "\"REPLICATION_MODE==Multicast && RP_MODE==bidir && UNDERLAY_IS_V6!=true\"",
                "Description": "Used for Fallback Bidir-PIM Phantom RP <br />(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PHANTOM_RP_LB_ID3",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "4"
            },
            "annotations": {
                "DisplayName": "Underlay Second Backup <br />RP Loopback Id",
                "IsShow": "\"REPLICATION_MODE==Multicast && RP_MODE==bidir && RP_COUNT==4 && UNDERLAY_IS_V6!=true\"",
                "Description": "Used for second Fallback Bidir-PIM Phantom RP <br />(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PHANTOM_RP_LB_ID4",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "5"
            },
            "annotations": {
                "DisplayName": "Underlay Third Backup <br />RP Loopback Id",
                "IsShow": "\"REPLICATION_MODE==Multicast && RP_MODE==bidir && RP_COUNT==4 && UNDERLAY_IS_V6!=true\"",
                "Description": "Used for third Fallback Bidir-PIM Phantom RP <br />(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Replication\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "VPC_PEER_LINK_VLAN",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "2",
                "max": "4094",
                "defaultValue": "3600"
            },
            "annotations": {
                "DisplayName": "vPC Peer Link VLAN Range",
                "Description": "VLAN range for vPC Peer Link SVI (Min:2, Max:4094)",
                "IsMandatory": "true",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ENABLE_VPC_PEER_LINK_NATIVE_VLAN",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Make vPC Peer Link VLAN as Native VLAN",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "VPC_PEER_KEEP_ALIVE_OPTION",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "management"
            },
            "annotations": {
                "Enum": "\"loopback,management\"",
                "DisplayName": "vPC Peer Keep Alive option",
                "Description": "Use vPC Peer Keep Alive with Loopback or Management",
                "IsMandatory": "true",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "VPC_AUTO_RECOVERY_TIME",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "240",
                "max": "3600",
                "defaultValue": "360"
            },
            "annotations": {
                "DisplayName": "vPC Auto Recovery Time <br />(In Seconds)",
                "Description": "(Min:240, Max:3600)",
                "IsMandatory": "true",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "VPC_DELAY_RESTORE",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "3600",
                "defaultValue": "150"
            },
            "annotations": {
                "DisplayName": "vPC Delay Restore Time <br />(In Seconds)",
                "Description": "(Min:1, Max:3600)",
                "IsMandatory": "true",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "VPC_PEER_LINK_PO",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "4096",
                "defaultValue": "500"
            },
            "annotations": {
                "DisplayName": "vPC Peer Link Port Channel ID",
                "Description": "(Min:1, Max:4096)",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "VPC_ENABLE_IPv6_ND_SYNC",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "vPC IPv6 ND Synchronize",
                "Description": "Enable IPv6 ND synchronization between vPC peers",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ADVERTISE_PIP_BGP",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "vPC advertise-pip",
                "Description": "For Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ADVERTISE_PIP_ON_BORDER",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "vPC advertise-pip on Border only",
                "IsShow": "\"ADVERTISE_PIP_BGP!=true\"",
                "Description": "Enable advertise-pip on vPC borders and border gateways only. Applicable only when vPC advertise-pip is not enabled",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_FABRIC_VPC_DOMAIN_ID",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable the same vPC Domain Id <br />for all vPC Pairs",
                "Description": "(Not Recommended) ",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_FABRIC_VPC_DOMAIN_ID_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "FABRIC_VPC_DOMAIN_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "1000",
                "defaultValue": "1"
            },
            "annotations": {
                "DisplayName": "vPC Domain Id",
                "IsShow": "\"ENABLE_FABRIC_VPC_DOMAIN_ID==true\"",
                "Description": "vPC Domain Id to be used on all vPC pairs",
                "IsMandatory": "true",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "FABRIC_VPC_DOMAIN_ID_PREV",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "1000"
            },
            "annotations": {
                "DisplayName": "Internal Fabric Wide vPC Domain Id",
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "VPC_DOMAIN_ID_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "1000",
                "defaultValue": "1-1000"
            },
            "annotations": {
                "DisplayName": "vPC Domain Id Range",
                "IsShow": "\"ENABLE_FABRIC_VPC_DOMAIN_ID==false\"",
                "Description": "vPC Domain id range to use for new pairings",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "FABRIC_VPC_QOS",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Qos for Fabric vPC-Peering",
                "IsShow": "\"ENABLE_DEFAULT_QUEUING_POLICY==false\"",
                "Description": "Qos on spines for guaranteed delivery of vPC Fabric Peering communication",
                "IsMandatory": "false",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "FABRIC_VPC_QOS_POLICY_NAME",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "spine_qos_for_fabric_vpc_peering",
                "minLength": "1",
                "maxLength": "40"
            },
            "annotations": {
                "DisplayName": "Qos Policy Name",
                "IsShow": "\"FABRIC_VPC_QOS==true\"",
                "Description": "Qos Policy name should be same on all spines",
                "IsMandatory": "true",
                "Section": "\"vPC\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BGP_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "0"
            },
            "annotations": {
                "DisplayName": "Underlay Routing Loopback Id",
                "Description": "(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "NVE_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "1"
            },
            "annotations": {
                "DisplayName": "Underlay VTEP Loopback Id",
                "Description": "(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ANYCAST_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "10"
            },
            "annotations": {
                "DisplayName": "Underlay Anycast Loopback Id",
                "IsShow": "\"UNDERLAY_IS_V6==true\"",
                "Description": "Used for vPC Peering in VXLANv6 Fabrics (Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "LINK_STATE_ROUTING_TAG",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "UNDERLAY",
                "minLength": "1",
                "maxLength": "20"
            },
            "annotations": {
                "DisplayName": "Underlay Routing Protocol Tag",
                "Description": "Underlay Routing Process Tag",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "LINK_STATE_ROUTING_TAG_PREV",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "OSPF_AREA_ID",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "0.0.0.0",
                "minLength": "1",
                "maxLength": "15"
            },
            "annotations": {
                "DisplayName": "OSPF Area Id",
                "IsShow": "\"LINK_STATE_ROUTING==ospf\"",
                "Description": "OSPF Area Id in IP address format",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "OSPF_AUTH_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable OSPF Authentication",
                "IsShow": "\"LINK_STATE_ROUTING==ospf && UNDERLAY_IS_V6==false\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "OSPF_AUTH_KEY_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "255",
                "defaultValue": "127"
            },
            "annotations": {
                "DisplayName": "OSPF Authentication Key ID",
                "IsShow": "\"LINK_STATE_ROUTING==ospf && OSPF_AUTH_ENABLE==true\"",
                "Description": "(Min:0, Max:255)",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "OSPF_AUTH_KEY",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "256"
            },
            "annotations": {
                "DisplayName": "OSPF Authentication Key",
                "IsShow": "\"LINK_STATE_ROUTING==ospf && OSPF_AUTH_ENABLE==true\"",
                "Description": "3DES Encrypted",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ISIS_LEVEL",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "level-2"
            },
            "annotations": {
                "Enum": "\"level-1,level-2\"",
                "Description": "Supported IS types: level-1, level-2",
                "IsMandatory": "true",
                "DisplayName": "IS-IS Level",
                "IsShow": "\"LINK_STATE_ROUTING==is-is\"",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ISIS_P2P_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable IS-IS Network Point-to-Point",
                "IsShow": "\"LINK_STATE_ROUTING==is-is\"",
                "Description": "This will enable network point-to-point on fabric interfaces which are numbered",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ISIS_AUTH_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable IS-IS Authentication",
                "IsShow": "\"LINK_STATE_ROUTING==is-is && UNDERLAY_IS_V6==false\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ISIS_AUTH_KEYCHAIN_NAME",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "63"
            },
            "annotations": {
                "DisplayName": "IS-IS Authentication Keychain Name",
                "IsShow": "\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\"",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ISIS_AUTH_KEYCHAIN_KEY_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "65535",
                "defaultValue": "127"
            },
            "annotations": {
                "DisplayName": "IS-IS Authentication Key ID",
                "IsShow": "\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\"",
                "Description": "(Min:0, Max:65535)",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ISIS_AUTH_KEY",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "255"
            },
            "annotations": {
                "DisplayName": "IS-IS Authentication Key",
                "IsShow": "\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\"",
                "Description": "Cisco Type 7 Encrypted",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ISIS_OVERLOAD_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Set IS-IS Overload Bit",
                "IsShow": "\"LINK_STATE_ROUTING==is-is\"",
                "Description": "When enabled, set the overload bit for an elapsed time after a reload",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ISIS_OVERLOAD_ELAPSE_TIME",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "5",
                "max": "86400",
                "defaultValue": "60"
            },
            "annotations": {
                "DisplayName": "IS-IS Overload Bit Elapsed Time",
                "IsShow": "\"LINK_STATE_ROUTING==is-is && ISIS_OVERLOAD_ENABLE==true\"",
                "Description": "Clear the overload bit after an elapsed time in seconds",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BGP_AUTH_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BGP Authentication",
                "IsShow": "\"UNDERLAY_IS_V6==false\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BGP_AUTH_KEY_TYPE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "3"
            },
            "annotations": {
                "Enum": "\"3,7\"",
                "Description": "BGP Key Encryption Type: 3 - 3DES, 7 - Cisco",
                "IsMandatory": "true",
                "DisplayName": "BGP Authentication Key <br />Encryption Type",
                "IsShow": "\"BGP_AUTH_ENABLE==true\"",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BGP_AUTH_KEY",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "256"
            },
            "annotations": {
                "DisplayName": "BGP Authentication Key",
                "IsShow": "\"BGP_AUTH_ENABLE==true\"",
                "Description": "Encrypted BGP Authentication Key based on type",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PIM_HELLO_AUTH_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable PIM Hello Authentication",
                "IsShow": "\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6==false\"",
                "Description": "Valid for IPv4 Underlay only",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PIM_HELLO_AUTH_KEY",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "256"
            },
            "annotations": {
                "DisplayName": "PIM Hello Authentication Key",
                "IsShow": "\"PIM_HELLO_AUTH_ENABLE==true\"",
                "Description": "3DES Encrypted",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BFD_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BFD",
                "IsShow": "\"UNDERLAY_IS_V6==false\"",
                "Description": "Valid for IPv4 Underlay only",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BFD_IBGP_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BFD For iBGP",
                "IsShow": "\"UNDERLAY_IS_V6==false && BFD_ENABLE==true\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BFD_OSPF_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BFD For OSPF",
                "IsShow": "\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && LINK_STATE_ROUTING==ospf\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BFD_ISIS_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BFD For ISIS",
                "IsShow": "\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && LINK_STATE_ROUTING==is-is\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BFD_PIM_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BFD For PIM",
                "IsShow": "\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && REPLICATION_MODE==Multicast\"",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BFD_AUTH_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable BFD Authentication",
                "IsShow": "\"UNDERLAY_IS_V6==false && FABRIC_INTERFACE_TYPE==p2p && BFD_ENABLE==true\"",
                "Description": "Valid for P2P Interfaces only",
                "IsMandatory": "false",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BFD_AUTH_KEY_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "255",
                "defaultValue": "100"
            },
            "annotations": {
                "DisplayName": "BFD Authentication Key ID",
                "IsShow": "\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && FABRIC_INTERFACE_TYPE==p2p && BFD_AUTH_ENABLE==true\"",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BFD_AUTH_KEY",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "minLength": "1",
                "maxLength": "40"
            },
            "annotations": {
                "DisplayName": "BFD Authentication Key",
                "IsShow": "\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && FABRIC_INTERFACE_TYPE==p2p && BFD_AUTH_ENABLE==true\"",
                "Description": "Encrypted SHA1 secret value",
                "IsMandatory": "true",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "IBGP_PEER_TEMPLATE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMultiLineString": "true",
                "Warning": "\"Speficies the config used for RR and<br/> spines with border or border gateway role. <br/> This field should begin with<br/>'  template peer' or '  template peer-session'. <br/> This must have 2 leading spaces. <br/>Note ! All configs should <br/>strictly match show run output, <br/>with respect to case and newlines. <br/>Any mismatches will yield <br/>unexpected diffs during deploy.\"",
                "Description": "Speficies the iBGP Peer-Template config used for RR and<br />spines with border role. ",
                "IsMandatory": "false",
                "DisplayName": "iBGP Peer-Template Config",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "IBGP_PEER_TEMPLATE_LEAF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMultiLineString": "true",
                "Warning": "\"Specifies the config used for leaf, border or<br/> border gateway.<br/>If this field is empty, the peer template defined in<br/>iBGP Peer-Template Config is used on all BGP<br/>enabled devices (RRs, leafs,<br/> border or border gateway roles).<br/>This field should begin with<br/>'  template peer' or '  template peer-session'.<br/> This must have 2 leading spaces. <br/>Note ! All configs should <br/>strictly match 'show run' output, <br/>with respect to case and newlines. <br/>Any mismatches will yield <br/>unexpected diffs during deploy.\"",
                "Description": "Specifies the config used for leaf, border or<br /> border gateway.<br />If this field is empty, the peer template defined in<br />iBGP Peer-Template Config is used on all BGP enabled devices<br />(RRs,leafs, border or border gateway roles.",
                "IsMandatory": "false",
                "DisplayName": "Leaf/Border/Border Gateway<br />iBGP Peer-Template Config ",
                "Section": "\"Protocols\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "default_vrf",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Default_VRF_Universal"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.vrf\"",
                "IsVrfTemplate": "true",
                "Description": "Default Overlay VRF Template For Leafs",
                "IsMandatory": "true",
                "DisplayName": "VRF Template",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "default_network",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Default_Network_Universal"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.network\"",
                "Description": "Default Overlay Network Template For Leafs",
                "IsMandatory": "true",
                "DisplayName": "Network Template",
                "IsNetworkTemplate": "true",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "vrf_extension_template",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Default_VRF_Extension_Universal"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.vrfExtension\"",
                "IsVrfExtensionTemplate": "true",
                "Description": "Default Overlay VRF Template For Borders",
                "IsMandatory": "true",
                "DisplayName": "VRF Extension Template",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "network_extension_template",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Default_Network_Extension_Universal"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.networkExtension\"",
                "Description": "Default Overlay Network Template For Borders",
                "IsMandatory": "true",
                "DisplayName": "Network Extension Template",
                "IsNetworkExtensionTemplate": "true",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "OVERLAY_MODE",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "defaultValue": "cli",
                "validValues": "config-profile,cli"
            },
            "annotations": {
                "DisplayName": "Overlay Mode",
                "Description": "VRF/Network configuration using config-profile or CLI",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "OVERLAY_MODE_PREV",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "validValues": "config-profile,cli"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_PVLAN",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Private VLAN (PVLAN)",
                "Description": "Enable PVLAN on switches except spines and super spines",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_PVLAN_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "default_pvlan_sec_network",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Pvlan_Secondary_Network"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.pvlanSecNetwork\"",
                "Description": "Default PVLAN Secondary Network Template",
                "IsMandatory": "\"ENABLE_PVLAN==true\"",
                "DisplayName": "PVLAN Secondary Network Template",
                "IsShow": "\"ENABLE_PVLAN==true\"",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SITE_ID",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "regularExpr": "^(((\\+)?[1-9]{1}[0-9]{0,13}|(\\+)?[1]{1}[0-9]{1,14}|(\\+)?[2]{1}([0-7]{1}[0-9]{13}|[8]{1}([0-0]{1}[0-9]{12}|[1]{1}([0-3]{1}[0-9]{11}|[4]{1}([0-6]{1}[0-9]{10}|[7]{1}([0-3]{1}[0-9]{9}|[4]{1}([0-8]{1}[0-9]{8}|[9]{1}([0-6]{1}[0-9]{7}|[7]{1}([0-5]{1}[0-9]{6}|[6]{1}([0-6]{1}[0-9]{5}|[7]{1}([0-0]{1}[0-9]{4}|[1]{1}([0]{0}[0-9]{3}|[0]{1}([0-5]{1}[0-9]{2}|[6]{1}([0-4]{1}[0-9]{1}|[5]{1}[0-5]{1}))))))))))))))|([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])(\\.([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]|0))?)$",
                "minLength": "1",
                "maxLength": "15"
            },
            "annotations": {
                "Description": "For EVPN Multi-Site Support (Min:1, Max: 281474976710655). <br />Defaults to Fabric ASN",
                "IsMandatory": "false",
                "DisplayName": "Site Id",
                "Section": "\"Advanced\"",
                "IsSiteId": "true",
                "AutoPopulate": "\"BGP_AS\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "FABRIC_MTU",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "576",
                "max": "9216",
                "defaultValue": "9216"
            },
            "annotations": {
                "DisplayName": "Intra Fabric Interface MTU",
                "Description": "(Min:576, Max:9216). Must be an even number",
                "IsMandatory": "true",
                "Section": "\"Advanced\"",
                "IsMTU": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "FABRIC_MTU_PREV",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "576",
                "max": "9216",
                "defaultValue": "9216"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "L2_HOST_INTF_MTU",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1500",
                "max": "9216",
                "defaultValue": "9216"
            },
            "annotations": {
                "DisplayName": "Layer 2 Host Interface MTU",
                "Description": "(Min:1500, Max:9216). Must be an even number",
                "IsMandatory": "true",
                "Section": "\"Advanced\"",
                "IsMTU": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "L2_HOST_INTF_MTU_PREV",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1500",
                "max": "9216",
                "defaultValue": "9216"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "HOST_INTF_ADMIN_STATE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Unshut Host Interfaces by Default",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "POWER_REDUNDANCY_MODE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "ps-redundant"
            },
            "annotations": {
                "Enum": "\"ps-redundant,combined,insrc-redundant\"",
                "DisplayName": "Power Supply Mode",
                "Description": "Default Power Supply Mode For The Fabric",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "COPP_POLICY",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "strict"
            },
            "annotations": {
                "Enum": "\"dense,lenient,moderate,strict,manual\"",
                "DisplayName": "CoPP Profile",
                "Description": "Fabric Wide CoPP Policy. Customized CoPP policy should be <br /> provided when &#39;manual&#39; is selected",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "HD_TIME",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "1500",
                "defaultValue": "180"
            },
            "annotations": {
                "DisplayName": "VTEP HoldDown Time",
                "Description": "NVE Source Inteface HoldDown Time (Min:1, Max:1500) in seconds",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BROWNFIELD_NETWORK_NAME_FORMAT",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$",
                "minLength": "1",
                "maxLength": "80"
            },
            "annotations": {
                "DisplayName": "Brownfield Overlay Network Name <br />Format",
                "Description": "Generated network name should be &lt; 64 characters",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BROWNFIELD_SKIP_OVERLAY_NETWORK_ATTACHMENTS",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Skip Overlay Network Interface Attachments",
                "Description": "Enable to skip overlay network interface attachments for Brownfield and Host Port Resync cases",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "CDP_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable CDP for Bootstrapped Switch",
                "Description": "Enable CDP on management interface",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_NGOAM",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable VXLAN OAM",
                "Description": "Enable the Next Generation (NG) OAM feature for all switches in the fabric to aid in trouble-shooting VXLAN EVPN fabrics",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_TENANT_DHCP",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable Tenant DHCP",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_NXAPI",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable NX-API",
                "Description": "Enable HTTPS NX-API",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NXAPI_HTTPS_PORT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "65535",
                "defaultValue": "443"
            },
            "annotations": {
                "DisplayName": "NX-API HTTPS Port Number",
                "IsShow": "\"ENABLE_NXAPI==true\"",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_NXAPI_HTTP",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable HTTP NX-API",
                "IsShow": "\"ENABLE_NXAPI==true\"",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NXAPI_HTTP_PORT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "65535",
                "defaultValue": "80"
            },
            "annotations": {
                "DisplayName": "NX-API HTTP Port Number",
                "IsShow": "\"ENABLE_NXAPI_HTTP==true\"",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ESR_OPTION",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "defaultValue": "PBR",
                "validValues": "ePBR,PBR"
            },
            "annotations": {
                "DisplayName": "Elastic Services Re-direction (ESR) Options",
                "NoConfigChg": "true",
                "Description": "Policy-Based Routing (PBR) or Enhanced PBR (ePBR)",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_PBR",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Policy-Based Routing (PBR)/Enhanced PBR (ePBR)",
                "Description": "When ESR option is ePBR, enable ePBR will enable pbr, sla sender and epbr features on the switch",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "STRICT_CC_MODE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Strict Config Compliance",
                "Description": "Enable bi-directional compliance checks to flag additional configs in the running config that are not in the intent/expected config",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "AAA_REMOTE_IP_ENABLED",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable AAA IP Authorization",
                "Description": "Enable only, when IP Authorization is enabled in the AAA Server",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SNMP_SERVER_HOST_TRAP",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable NDFC as Trap Host",
                "Description": "Configure NDFC as a receiver for SNMP traps",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ANYCAST_BGW_ADVERTISE_PIP",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Anycast Border Gateway advertise-pip",
                "Description": "To advertise Anycast Border Gateway PIP as VTEP. Effective on MSD fabric &#39;Recalculate Config&#39;",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DEPLOYMENT_FREEZE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Disable all deployments in this fabric",
                "IsMandatory": "false",
                "Section": "\"Hidden\"",
                "IsFreezeMode": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "GRFIELD_DEBUG_FLAG",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Disable"
            },
            "annotations": {
                "Enum": "\"Enable,Disable\"",
                "Description": "Enable to clean switch configuration without reload when PreserveConfig&#61;no",
                "IsMandatory": "true",
                "DisplayName": "Greenfield Cleanup Option",
                "IsShow": "\"AAA_REMOTE_IP_ENABLED==false\"",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "FEATURE_PTP",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Precision Time Protocol (PTP)",
                "IsShow": "\"UNDERLAY_IS_V6!=true\"",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PTP_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "0"
            },
            "annotations": {
                "DisplayName": "PTP Source Loopback Id",
                "IsShow": "\"FEATURE_PTP==true\"",
                "Description": "(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "PTP_DOMAIN_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "127",
                "defaultValue": "0"
            },
            "annotations": {
                "DisplayName": "PTP Domain Id",
                "IsShow": "\"FEATURE_PTP==true\"",
                "Description": "Multiple Independent PTP Clocking Subdomains <br />on a Single Network (Min:0, Max:127)",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MPLS_HANDOFF",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable MPLS Handoff",
                "IsShow": "\"UNDERLAY_IS_V6==false\"",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MPLS_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "101"
            },
            "annotations": {
                "DisplayName": "Underlay MPLS Loopback Id",
                "IsShow": "\"MPLS_HANDOFF==true && UNDERLAY_IS_V6==false\"",
                "Description": "Used for VXLAN to MPLS SR/LDP Handoff <br />(Min:0, Max:1023)",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "TCAM_ALLOCATION",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable TCAM Allocation",
                "Description": "TCAM commands are automatically generated for VxLAN and vPC Fabric Peering when Enabled",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_DEFAULT_QUEUING_POLICY",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Default Queuing Policies",
                "IsShow": "\"FABRIC_VPC_QOS==false\"",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DEAFULT_QUEUING_POLICY_CLOUDSCALE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "queuing_policy_default_8q_cloudscale"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.QoS_Cloud\"",
                "Description": "Queuing Policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX <br />series switches in the fabric",
                "IsMandatory": "true",
                "DisplayName": "N9K Cloud Scale Platform <br />Queuing Policy",
                "IsShow": "\"ENABLE_DEFAULT_QUEUING_POLICY==true\"",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "DEAFULT_QUEUING_POLICY_R_SERIES",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "queuing_policy_default_r_series"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.QoS_R_Series\"",
                "Description": "Queuing Policy for all R-Series <br />switches in the fabric",
                "IsMandatory": "true",
                "DisplayName": "N9K R-Series Platform <br />Queuing Policy",
                "IsShow": "\"ENABLE_DEFAULT_QUEUING_POLICY==true\"",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "DEAFULT_QUEUING_POLICY_OTHER",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "queuing_policy_default_other"
            },
            "annotations": {
                "Enum": "\"%TEMPLATES.QoS_Other\"",
                "Description": "Queuing Policy for all other <br />switches in the fabric",
                "IsMandatory": "true",
                "DisplayName": "Other N9K Platform <br />Queuing Policy",
                "IsShow": "\"ENABLE_DEFAULT_QUEUING_POLICY==true\"",
                "Section": "\"Advanced\"",
                "AlwaysSetDefault": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ENABLE_MACSEC",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable MACsec",
                "Description": "Enable MACsec in the fabric",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MACSEC_KEY_STRING",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "regularExpr": "^[a-fA-F0-9]+$",
                "minLength": "1",
                "maxLength": "130"
            },
            "annotations": {
                "DisplayName": "MACsec Primary Key String",
                "IsShow": "\"ENABLE_MACSEC==true\"",
                "Description": "Cisco Type 7 Encrypted Octet String",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MACSEC_ALGORITHM",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "defaultValue": "AES_128_CMAC",
                "validValues": "AES_128_CMAC,AES_256_CMAC"
            },
            "annotations": {
                "DisplayName": "MACsec Primary Cryptographic <br />Algorithm",
                "IsShow": "\"ENABLE_MACSEC==true\"",
                "Description": "AES_128_CMAC or AES_256_CMAC",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MACSEC_FALLBACK_KEY_STRING",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "regularExpr": "^[a-fA-F0-9]+$",
                "minLength": "1",
                "maxLength": "130"
            },
            "annotations": {
                "DisplayName": "MACsec Fallback Key String",
                "IsShow": "\"ENABLE_MACSEC==true\"",
                "Description": "Cisco Type 7 Encrypted Octet String",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MACSEC_FALLBACK_ALGORITHM",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "defaultValue": "AES_128_CMAC",
                "validValues": "AES_128_CMAC,AES_256_CMAC"
            },
            "annotations": {
                "DisplayName": "MACsec Fallback Cryptographic <br />Algorithm",
                "IsShow": "\"ENABLE_MACSEC==true\"",
                "Description": "AES_128_CMAC or AES_256_CMAC",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MACSEC_CIPHER_SUITE",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "defaultValue": "GCM-AES-XPN-256",
                "validValues": "GCM-AES-128,GCM-AES-256,GCM-AES-XPN-128,GCM-AES-XPN-256"
            },
            "annotations": {
                "DisplayName": "MACsec Cipher Suite",
                "IsShow": "\"ENABLE_MACSEC==true\"",
                "Description": "Configure Cipher Suite",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MACSEC_REPORT_TIMER",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "5",
                "max": "60",
                "defaultValue": "5"
            },
            "annotations": {
                "DisplayName": "MACsec Status Report Timer",
                "IsShow": "\"ENABLE_MACSEC==true\"",
                "Description": "MACsec Operational Status periodic report timer in minutes",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "STP_ROOT_OPTION",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "unmanaged"
            },
            "annotations": {
                "Enum": "\"rpvst+,mst,unmanaged\"",
                "DisplayName": "Spanning Tree Root Bridge Protocol",
                "Description": "Which protocol to use for configuring root bridge? rpvst&#43;: Rapid Per-VLAN Spanning Tree, mst: Multiple Spanning Tree, unmanaged (default): STP Root not managed by NDFC",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "STP_VLAN_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "4092",
                "defaultValue": "1-3967"
            },
            "annotations": {
                "DisplayName": "Spanning Tree VLAN Range",
                "IsShow": "\"STP_ROOT_OPTION==rpvst+\"",
                "Description": "Vlan range, Example: 1,3-5,7,9-11, Default is 1-3967",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MST_INSTANCE_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "0",
                "max": "4094",
                "defaultValue": "0"
            },
            "annotations": {
                "DisplayName": "MST Instance Range",
                "IsShow": "\"STP_ROOT_OPTION==mst\"",
                "Description": "MST instance range, Example: 0-3,5,7-9, Default is 0",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "STP_BRIDGE_PRIORITY",
            "description": null,
            "parameterType": "enum",
            "metaProperties": {
                "defaultValue": "0",
                "validValues": "0,4096,8192,12288,16384,20480,24576,28672,32768,36864,40960,45056,49152,53248,57344,61440"
            },
            "annotations": {
                "DisplayName": "Spanning Tree Bridge Priority",
                "IsShow": "\"STP_ROOT_OPTION==rpvst+||STP_ROOT_OPTION==mst\"",
                "Description": "Bridge priority for the spanning tree in increments of 4096",
                "IsMandatory": "true",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "EXTRA_CONF_LEAF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Leaf Freeform Config",
                "IsMultiLineString": "true",
                "Description": "Additional CLIs For All Leafs As Captured From Show Running Configuration",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "EXTRA_CONF_SPINE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Spine Freeform Config",
                "IsMultiLineString": "true",
                "Description": "Additional CLIs For All Spines As Captured From Show Running Configuration",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "EXTRA_CONF_TOR",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "ToR Freeform Config",
                "IsMultiLineString": "true",
                "Description": "Additional CLIs For All ToRs As Captured From Show Running Configuration",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "EXTRA_CONF_INTRA_LINKS",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Intra-fabric Links Additional Config",
                "IsMultiLineString": "true",
                "Description": "Additional CLIs For All Intra-Fabric Links",
                "IsMandatory": "false",
                "Section": "\"Advanced\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "STATIC_UNDERLAY_IP_ALLOC",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Manual Underlay IP Address <br />Allocation",
                "Description": "Checking this will disable Dynamic Underlay IP Address Allocations",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "LOOPBACK0_IP_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.2.0.0/22"
            },
            "annotations": {
                "DisplayName": "Underlay Routing Loopback IP <br />Range",
                "IsShow": "\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "Description": "Typically Loopback0 IP Address Range",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "LOOPBACK1_IP_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.3.0.0/22"
            },
            "annotations": {
                "DisplayName": "Underlay VTEP Loopback IP Range",
                "IsShow": "\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "Description": "Typically Loopback1 IP Address Range",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ANYCAST_RP_IP_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.254.254.0/24"
            },
            "annotations": {
                "DisplayName": "Underlay RP Loopback IP Range",
                "IsShow": "\"($$STATIC_UNDERLAY_IP_ALLOC$$=='false' && $$UNDERLAY_IS_V6$$=='false' && $$REPLICATION_MODE$$=='Multicast') || ($$STATIC_UNDERLAY_IP_ALLOC$$=='true' && $$UNDERLAY_IS_V6$$=='false' && $$REPLICATION_MODE$$=='Multicast' && $$RP_MODE$$=='bidir')\"",
                "Description": "Anycast or Phantom RP IP Address Range",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "SUBNET_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.4.0.0/16"
            },
            "annotations": {
                "DisplayName": "Underlay Subnet IP Range",
                "IsShow": "\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "Description": "Address range to assign Numbered and Peer Link SVI IPs",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MPLS_LOOPBACK_IP_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.101.0.0/25"
            },
            "annotations": {
                "DisplayName": "Underlay MPLS Loopback IP Range",
                "IsShow": "\"MPLS_HANDOFF==true && UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "Description": "Used for VXLAN to MPLS SR/LDP Handoff",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "LOOPBACK0_IPV6_RANGE",
            "description": null,
            "parameterType": "ipV6AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "fd00::a02:0/119"
            },
            "annotations": {
                "DisplayName": "Underlay Routing Loopback IPv6 <br />Range",
                "IsShow": "\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "Description": "Typically Loopback0 IPv6 Address Range",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "LOOPBACK1_IPV6_RANGE",
            "description": null,
            "parameterType": "ipV6AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "fd00::a03:0/118"
            },
            "annotations": {
                "DisplayName": "Underlay VTEP Loopback IPv6 <br />Range",
                "IsShow": "\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "Description": "Typically Loopback1 and Anycast Loopback IPv6 Address Range",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "V6_SUBNET_RANGE",
            "description": null,
            "parameterType": "ipV6AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "fd00::a04:0/112"
            },
            "annotations": {
                "DisplayName": "Underlay Subnet IPv6 Range",
                "IsShow": "\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false && USE_LINK_LOCAL==false\"",
                "Description": "IPv6 Address range to assign Numbered and Peer Link SVI IPs",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ROUTER_ID_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.2.0.0/23"
            },
            "annotations": {
                "DisplayName": "BGP Router ID Range for IPv6 Underlay",
                "IsShow": "\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\"",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "L2_SEGMENT_ID_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "16777214",
                "defaultValue": "30000-49000"
            },
            "annotations": {
                "DisplayName": "Layer 2 VXLAN VNI Range",
                "Description": "Overlay Network Identifier Range (Min:1, Max:16777214)",
                "IsMandatory": "true",
                "IsL2VniRange": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "L3_PARTITION_ID_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "16777214",
                "defaultValue": "50000-59000"
            },
            "annotations": {
                "DisplayName": "Layer 3 VXLAN VNI Range",
                "IsL3VniRange": "true",
                "Description": "Overlay VRF Identifier Range (Min:1, Max:16777214)",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "NETWORK_VLAN_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "2",
                "max": "4094",
                "defaultValue": "2300-2999"
            },
            "annotations": {
                "DisplayName": "Network VLAN Range",
                "Description": "Per Switch Overlay Network VLAN Range (Min:2, Max:4094)",
                "IsMandatory": "true",
                "Section": "\"Resources\"",
                "IsNetworkVlanRange": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "VRF_VLAN_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "2",
                "max": "4094",
                "defaultValue": "2000-2299"
            },
            "annotations": {
                "DisplayName": "VRF VLAN Range",
                "Description": "Per Switch Overlay VRF VLAN Range (Min:2, Max:4094)",
                "IsVrfVlanRange": "true",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "SUBINTERFACE_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "2",
                "max": "4093",
                "defaultValue": "2-511"
            },
            "annotations": {
                "DisplayName": "Subinterface Dot1q Range",
                "Description": "Per Border Dot1q Range For VRF Lite Connectivity (Min:2, Max:4093)",
                "IsMandatory": "true",
                "Section": "\"Resources\"",
                "IsDot1qIdRange": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "VRF_LITE_AUTOCONFIG",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Manual"
            },
            "annotations": {
                "Enum": "\"Manual,Back2Back&ToExternal\"",
                "DisplayName": "VRF Lite Deployment",
                "Description": "VRF Lite Inter-Fabric Connection Deployment Options. If &#39;Back2Back&amp;ToExternal&#39; is selected, VRF Lite IFCs are auto created between border devices of two Easy Fabrics, and between border devices in Easy Fabric and edge routers in External Fabric. The IP address is taken from the &#39;VRF Lite Subnet IP Range&#39; pool.",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "AUTO_SYMMETRIC_VRF_LITE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Auto Deploy for Peer",
                "IsShow": "\"VRF_LITE_AUTOCONFIG!=Manual\"",
                "Description": "Whether to auto generate VRF LITE sub-interface and BGP peering configuration on managed neighbor devices. If set, auto created VRF Lite IFC links will have &#39;Auto Deploy for Peer&#39; enabled.",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "AUTO_VRFLITE_IFC_DEFAULT_VRF",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Auto Deploy Default VRF",
                "IsShow": "\"VRF_LITE_AUTOCONFIG!=Manual\"",
                "Description": "Whether to auto generate Default VRF interface and BGP peering configuration on VRF LITE IFC auto deployment. If set, auto created VRF Lite IFC links will have &#39;Auto Deploy Default VRF&#39; enabled.",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "AUTO_SYMMETRIC_DEFAULT_VRF",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Auto Deploy Default VRF for Peer",
                "IsShow": "\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\"",
                "Description": "Whether to auto generate Default VRF interface and BGP peering configuration on managed neighbor devices. If set, auto created VRF Lite IFC links will have &#39;Auto Deploy Default VRF for Peer&#39; enabled.",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DEFAULT_VRF_REDIS_BGP_RMAP",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "extcon-rmap-filter"
            },
            "annotations": {
                "DisplayName": "Redistribute BGP Route-map Name",
                "IsShow": "\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\"",
                "Description": "Route Map used to redistribute BGP routes to IGP in default vrf in auto created VRF Lite IFC links",
                "IsMandatory": "\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\"",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DCI_SUBNET_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.33.0.0/16"
            },
            "annotations": {
                "DisplayName": "VRF Lite Subnet IP Range",
                "Description": "Address range to assign P2P Interfabric Connections",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "DCI_SUBNET_TARGET_MASK",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "8",
                "max": "31",
                "defaultValue": "30"
            },
            "annotations": {
                "DisplayName": "VRF Lite Subnet Mask",
                "Description": "(Min:8, Max:31)",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "AUTO_UNIQUE_VRF_LITE_IP_PREFIX",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Auto Allocation of Unique IP on VRF Extension over VRF Lite IFC",
                "Description": "When enabled, IP prefix allocated to the VRF LITE IFC is not reused on VRF extension over VRF LITE IFC. Instead, unique IP Subnet is allocated for each VRF extension over VRF LITE IFC.",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "IsMandatory": "false",
                "Section": "\"Resources\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PER_VRF_LOOPBACK_AUTO_PROVISION",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Per VRF Per VTEP Loopback Auto-Provisioning",
                "Description": "Auto provision a loopback on a VTEP on VRF attachment",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PER_VRF_LOOPBACK_AUTO_PROVISION_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "IsMandatory": "false",
                "Section": "\"Resources\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PER_VRF_LOOPBACK_IP_RANGE",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {
                "defaultValue": "10.5.0.0/22"
            },
            "annotations": {
                "DisplayName": "Per VRF Per VTEP IP Pool for Loopbacks",
                "IsShow": "\"PER_VRF_LOOPBACK_AUTO_PROVISION==true\"",
                "Description": "Prefix pool to assign IP addresses to loopbacks on VTEPs on a per VRF basis",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "SLA_ID_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "2147483647",
                "defaultValue": "10000-19999"
            },
            "annotations": {
                "DisplayName": "Service Level Agreement (SLA) ID Range",
                "Description": "Per switch SLA ID Range (Min:1, Max: 2147483647)",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "OBJECT_TRACKING_NUMBER_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "512",
                "defaultValue": "100-299"
            },
            "annotations": {
                "DisplayName": "Tracked Object ID Range",
                "Description": "Per switch tracked object ID Range (Min:1, Max: 512)",
                "IsMandatory": "false",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SERVICE_NETWORK_VLAN_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "2",
                "max": "4094",
                "defaultValue": "3000-3199"
            },
            "annotations": {
                "DisplayName": "Service Network VLAN Range",
                "Description": "Per Switch Overlay Service Network VLAN Range (Min:2, Max:4094)",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ROUTE_MAP_SEQUENCE_NUMBER_RANGE",
            "description": null,
            "parameterType": "integerRange",
            "metaProperties": {
                "min": "1",
                "max": "65534",
                "defaultValue": "1-65534"
            },
            "annotations": {
                "DisplayName": "Route Map Sequence Number Range",
                "Description": "(Min:1, Max:65534)",
                "IsMandatory": "true",
                "Section": "\"Resources\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "INBAND_MGMT",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Inband Management",
                "IsShow": "\"LINK_STATE_ROUTING==ospf && UNDERLAY_IS_V6==false\"",
                "Description": "Manage switches with only Inband connectivity",
                "IsMandatory": "false",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "INBAND_MGMT_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DNS_SERVER_IP_LIST",
            "description": null,
            "parameterType": "ipAddressList",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "DNS Server IPs",
                "Description": "Comma separated list of IP Addresses(v4/v6)",
                "IsMandatory": "false",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DNS_SERVER_VRF",
            "description": null,
            "parameterType": "string[]",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "DNS Server VRFs",
                "IsShow": "\"DNS_SERVER_IP_LIST!=null\"",
                "Description": "One VRF for all DNS servers or a comma separated<br />list of VRFs, one per DNS server",
                "IsMandatory": "\"DNS_SERVER_IP_LIST!=null\"",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NTP_SERVER_IP_LIST",
            "description": null,
            "parameterType": "ipAddressList",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "NTP Server IPs",
                "Description": "Comma separated list of IP Addresses(v4/v6)",
                "IsMandatory": "false",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NTP_SERVER_VRF",
            "description": null,
            "parameterType": "string[]",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "NTP Server VRFs",
                "IsShow": "\"NTP_SERVER_IP_LIST!=null\"",
                "Description": "One VRF for all NTP servers or a comma separated<br />list of VRFs, one per NTP server",
                "IsMandatory": "\"NTP_SERVER_IP_LIST!=null\"",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SYSLOG_SERVER_IP_LIST",
            "description": null,
            "parameterType": "ipAddressList",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Syslog Server IPs",
                "Description": "Comma separated list of IP Addresses(v4/v6)",
                "IsMandatory": "false",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SYSLOG_SEV",
            "description": null,
            "parameterType": "string[]",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Syslog Server Severity",
                "IsShow": "\"SYSLOG_SERVER_IP_LIST!=null\"",
                "Description": "Comma separated list of Syslog severity values,<br />one per Syslog server (Min:0, Max:7)",
                "IsMandatory": "\"SYSLOG_SERVER_IP_LIST!=null\"",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SYSLOG_SERVER_VRF",
            "description": null,
            "parameterType": "string[]",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Syslog Server VRFs",
                "IsShow": "\"SYSLOG_SERVER_IP_LIST!=null\"",
                "Description": "One VRF for all Syslog servers or a comma separated<br />list of VRFs, one per Syslog server",
                "IsMandatory": "\"SYSLOG_SERVER_IP_LIST!=null\"",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "AAA_SERVER_CONF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "AAA Freeform Config",
                "IsMultiLineString": "true",
                "Description": "AAA Configurations",
                "IsMandatory": "false",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BANNER",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Banner",
                "IsMultiLineString": "true",
                "Description": "Message of the Day (motd) banner. Delimiter char (very first char is delimiter char) followed by message ending with delimiter",
                "IsMandatory": "false",
                "Section": "\"Manageability\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BOOTSTRAP_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "Description": "Automatic IP Assignment For POAP",
                "IsMandatory": "false",
                "IsDhcpFlag": "true",
                "DisplayName": "Enable Bootstrap",
                "NoConfigChg": "true",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BOOTSTRAP_ENABLE_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DHCP_ENABLE",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "Description": "Automatic IP Assignment For POAP From Local DHCP Server",
                "IsMandatory": "false",
                "DisplayName": "Enable Local DHCP Server",
                "NoConfigChg": "true",
                "IsShow": "\"BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DHCP_IPV6_ENABLE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "DHCPv4"
            },
            "annotations": {
                "Enum": "\"DHCPv4,DHCPv6\"",
                "IsMandatory": "false",
                "DisplayName": "DHCP Version",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DHCP_START",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "Description": "Start Address For Switch POAP",
                "IsMandatory": "true",
                "DisplayName": "DHCP Scope Start Address",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "DHCP_END",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "Description": "End Address For Switch POAP",
                "IsMandatory": "true",
                "DisplayName": "DHCP Scope End Address",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MGMT_GW",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "Description": "Default Gateway For Management VRF On The Switch",
                "IsMandatory": "true",
                "DisplayName": "Switch Mgmt Default Gateway",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MGMT_PREFIX",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "8",
                "max": "30",
                "defaultValue": "24"
            },
            "annotations": {
                "Description": "(Min:8, Max:30)",
                "IsMandatory": "true",
                "DisplayName": "Switch Mgmt IP Subnet Prefix",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true && DHCP_IPV6_ENABLE==DHCPv4\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MGMT_V6PREFIX",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "64",
                "max": "126",
                "defaultValue": "64"
            },
            "annotations": {
                "Description": "(Min:64, Max:126)",
                "IsMandatory": "false",
                "DisplayName": "Switch Mgmt IPv6 Subnet Prefix",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true && DHCP_IPV6_ENABLE==DHCPv6\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BOOTSTRAP_MULTISUBNET",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix"
            },
            "annotations": {
                "IsMultiLineString": "true",
                "Warning": "\"Enter One Subnet Scope per line. <br/> Start_IP, End_IP, Gateway, Prefix <br/> e.g. <br>10.6.0.2, 10.6.0.9, 10.6.0.1, 24 <br>10.7.0.2, 10.7.0.9, 10.7.0.1, 24\"",
                "Description": "lines with # prefix are ignored here",
                "IsMandatory": "false",
                "DisplayName": "DHCPv4 Multi Subnet Scope",
                "NoConfigChg": "true",
                "IsShow": "\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SEED_SWITCH_CORE_INTERFACES",
            "description": null,
            "parameterType": "interfaceRange",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Seed Switch Fabric Interfaces",
                "IsShow": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\"",
                "Description": "Core-facing Interface list on Seed Switch (e.g. e1/1-30,e1/32)",
                "IsMandatory": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SPINE_SWITCH_CORE_INTERFACES",
            "description": null,
            "parameterType": "interfaceRange",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Spine Switch Fabric Interfaces",
                "IsShow": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\"",
                "Description": "Core-facing Interface list on all Spines (e.g. e1/1-30,e1/32)",
                "IsMandatory": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "INBAND_DHCP_SERVERS",
            "description": null,
            "parameterType": "ipAddressList",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "External DHCP Server IP Addresses",
                "IsShow": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==false\"",
                "Description": "Comma separated list of IPv4 Addresses (Max 3)",
                "IsMandatory": "true",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "UNNUM_BOOTSTRAP_LB_ID",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "0",
                "max": "1023",
                "defaultValue": "253"
            },
            "annotations": {
                "DisplayName": "Bootstrap Seed Switch Loopback Interface ID",
                "IsShow": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\"",
                "IsMandatory": "true",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "UNNUM_DHCP_START",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Switch Loopback DHCP Scope <br /> Start Address",
                "IsShow": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\"",
                "Description": "Must be a subset of IGP/BGP Loopback Prefix Pool",
                "IsMandatory": "true",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "UNNUM_DHCP_END",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Switch Loopback DHCP Scope <br /> End Address",
                "IsShow": "\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\"",
                "Description": "Must be a subset of IGP/BGP Loopback Prefix Pool",
                "IsMandatory": "true",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ENABLE_AAA",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "Description": "Include AAA configs from Manageability tab during device bootup",
                "IsMandatory": "false",
                "DisplayName": "Enable AAA Config",
                "NoConfigChg": "true",
                "IsShow": "\"BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BOOTSTRAP_CONF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMultiLineString": "true",
                "Description": "Additional CLIs required during device bootup/login e.g. AAA/Radius",
                "IsMandatory": "false",
                "DisplayName": "Bootstrap Freeform Config",
                "IsShow": "\"BOOTSTRAP_ENABLE==true\"",
                "Section": "\"Bootstrap\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "enableRealTimeBackup",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Hourly Fabric Backup",
                "NoConfigChg": "true",
                "Description": "Backup hourly only if there is any config deployment since last backup",
                "IsMandatory": "false",
                "Section": "\"Configuration Backup\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "enableScheduledBackup",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Scheduled Fabric Backup",
                "NoConfigChg": "true",
                "Description": "Backup at the specified time",
                "IsMandatory": "false",
                "Section": "\"Configuration Backup\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "scheduledTime",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "regularExpr": "^([01]\\d|2[0-3]):([0-5]\\d)$"
            },
            "annotations": {
                "Description": "Time (UTC) in 24hr format. (00:00 to 23:59)",
                "IsMandatory": "true",
                "DisplayName": "Scheduled Time",
                "NoConfigChg": "true",
                "IsShow": "\"enableScheduledBackup==true\"",
                "Section": "\"Configuration Backup\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ENABLE_NETFLOW",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Netflow",
                "IsShow": "\"UNDERLAY_IS_V6==false\"",
                "Description": "Enable Netflow on VTEPs",
                "IsMandatory": "false",
                "Section": "\"Flow Monitor\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_NETFLOW_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NETFLOW_EXPORTER_LIST",
            "description": null,
            "parameterType": "structureArray",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Netflow Exporter",
                "IsShow": "\"ENABLE_NETFLOW==true\"",
                "Description": "One or Multiple Netflow Exporters",
                "IsMandatory": "true",
                "Section": "\"Flow Monitor\""
            },
            "structureParameters": {
                "EXPORTER_NAME": {
                    "name": "EXPORTER_NAME",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Exporter Name\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "IP": {
                    "name": "IP",
                    "description": null,
                    "parameterType": "ipV4Address",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"IP\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "VRF": {
                    "name": "VRF",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "false",
                        "DisplayName": "\"VRF\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": true
                },
                "SRC_IF_NAME": {
                    "name": "SRC_IF_NAME",
                    "description": null,
                    "parameterType": "interface",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Source Interface\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "UDP_PORT": {
                    "name": "UDP_PORT",
                    "description": null,
                    "parameterType": "integer",
                    "metaProperties": {
                        "min": "1",
                        "max": "65535"
                    },
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"UDP Port\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                }
            },
            "parameterTypeStructure": true,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "NETFLOW_RECORD_LIST",
            "description": null,
            "parameterType": "structureArray",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Netflow Record",
                "IsShow": "\"ENABLE_NETFLOW==true\"",
                "Description": "One or Multiple Netflow Records",
                "IsMandatory": "true",
                "Section": "\"Flow Monitor\""
            },
            "structureParameters": {
                "RECORD_NAME": {
                    "name": "RECORD_NAME",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Record Name\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "RECORD_TEMPLATE": {
                    "name": "RECORD_TEMPLATE",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {
                        "defaultValue": "netflow_ipv4_record"
                    },
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Record Template\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "LAYER2_RECORD": {
                    "name": "LAYER2_RECORD",
                    "description": null,
                    "parameterType": "boolean",
                    "metaProperties": {
                        "defaultValue": "false"
                    },
                    "annotations": {
                        "IsMandatory": "false",
                        "DisplayName": "\"Is Layer2 Record\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": true
                }
            },
            "parameterTypeStructure": true,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "NETFLOW_MONITOR_LIST",
            "description": null,
            "parameterType": "structureArray",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Netflow Monitor",
                "IsShow": "\"ENABLE_NETFLOW==true\"",
                "Description": "One or Multiple Netflow Monitors",
                "IsMandatory": "true",
                "Section": "\"Flow Monitor\""
            },
            "structureParameters": {
                "MONITOR_NAME": {
                    "name": "MONITOR_NAME",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Monitor Name\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "RECORD_NAME": {
                    "name": "RECORD_NAME",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Record Name\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "EXPORTER1": {
                    "name": "EXPORTER1",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "true",
                        "DisplayName": "\"Exporter1 Name\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": false
                },
                "EXPORTER2": {
                    "name": "EXPORTER2",
                    "description": null,
                    "parameterType": "string",
                    "metaProperties": {},
                    "annotations": {
                        "IsMandatory": "false",
                        "DisplayName": "\"Exporter2 Name\""
                    },
                    "structureParameters": {},
                    "parameterTypeStructure": false,
                    "defaultValue": null,
                    "optional": true
                }
            },
            "parameterTypeStructure": true,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "ALLOW_NXC",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "DisplayName": "Enable Nexus Cloud",
                "Description": "Allow onboarding of this fabric to Nexus Cloud",
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ALLOW_NXC_PREV",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "OVERWRITE_GLOBAL_NXC",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Overwrite Global NxCloud Settings",
                "IsShow": "\"ALLOW_NXC==true\"",
                "Description": "If enabled, Fabric NxCloud Settings will be used",
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NXC_DEST_VRF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "management",
                "minLength": "1",
                "maxLength": "32"
            },
            "annotations": {
                "DisplayName": "Intersight Destination VRF",
                "IsShow": "\"OVERWRITE_GLOBAL_NXC==true\"",
                "Description": "VRF to be used to reach Nexus Cloud, enter &#39;management&#39; for management VRF and &#39;default&#39; for default VRF",
                "IsMandatory": "\"OVERWRITE_GLOBAL_NXC==true\"",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NXC_SRC_INTF",
            "description": null,
            "parameterType": "interface",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Intersight Source Interface",
                "IsShow": "\"OVERWRITE_GLOBAL_NXC==true && NXC_DEST_VRF!=management\"",
                "Description": "Source interface for communication to Nexus Cloud, mandatory if Destination VRF is not management, supported interfaces: loopback, port-channel, vlan",
                "IsMandatory": "\"OVERWRITE_GLOBAL_NXC==true && NXC_DEST_VRF!=management\"",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NXC_PROXY_SERVER",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "DisplayName": "Intersight Proxy Server",
                "IsShow": "\"OVERWRITE_GLOBAL_NXC==true\"",
                "Description": "IPv4 or IPv6 address, or DNS name of the proxy server",
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "NXC_PROXY_PORT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "65535",
                "defaultValue": "8080"
            },
            "annotations": {
                "DisplayName": "Proxy Server Port",
                "IsShow": "\"NXC_PROXY_SERVER!=null\"",
                "Description": "Proxy port number, default is 8080",
                "IsMandatory": "\"NXC_PROXY_SERVER!=null\"",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "VPC_DELAY_RESTORE_TIME",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "min": "1",
                "max": "3600",
                "defaultValue": "60"
            },
            "annotations": {
                "DisplayName": "vPC Delay Restore Time",
                "Description": "vPC Delay Restore Time For vPC links in seconds (Min:1, Max:3600)",
                "IsMandatory": "true",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "FABRIC_TYPE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Switch_Fabric"
            },
            "annotations": {
                "ReadOnly": "true",
                "DisplayName": "Fabric Type",
                "IsFabricType": "true",
                "IsMandatory": "true",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "EXT_FABRIC_TYPE",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_AGENT",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Enable Agent",
                "Description": "Enable Agnet (developmet purpose only)",
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "AGENT_INTF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "eth0"
            },
            "annotations": {
                "Enum": "\"eth0,eth1\"",
                "DisplayName": "Agent Interface",
                "Description": "Interface to connect to Agent",
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SSPINE_ADD_DEL_DEBUG_FLAG",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Disable"
            },
            "annotations": {
                "Enum": "\"Enable,Disable\"",
                "DisplayName": "Super Spine Force Add Del",
                "Description": "Allow First Super Spine Add or Last Super Spine Delete From Topology",
                "IsMandatory": "true",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "BRFIELD_DEBUG_FLAG",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Disable"
            },
            "annotations": {
                "Enum": "\"Enable,Disable\"",
                "DisplayName": "!!! Only for brf debugging purpose !!!",
                "Description": "Dont&#39; use until you are aware about it",
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ACTIVE_MIGRATION",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "DisplayName": "Active Migration",
                "IsMandatory": "true",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "FF",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "Easy_Fabric"
            },
            "annotations": {
                "DisplayName": "Template Family",
                "IsMandatory": "true",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "MSO_SITE_ID",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MSO_CONTROLER_ID",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MSO_SITE_GROUP_NAME",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "PREMSO_PARENT_FABRIC",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MSO_CONNECTIVITY_DEPLOYED",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ANYCAST_RP_IP_RANGE_INTERNAL",
            "description": null,
            "parameterType": "ipV4AddressWithSubnet",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "Section": "\"Hidden\""
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DHCP_START_INTERNAL",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DHCP_END_INTERNAL",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MGMT_GW_INTERNAL",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MGMT_PREFIX_INTERNAL",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "BOOTSTRAP_MULTISUBNET_INTERNAL",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "MGMT_V6PREFIX_INTERNAL",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "DHCP_IPV6_ENABLE_INTERNAL",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "UNNUM_DHCP_START_INTERNAL",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "UNNUM_DHCP_END_INTERNAL",
            "description": null,
            "parameterType": "ipAddress",
            "metaProperties": {},
            "annotations": {
                "NoConfigChg": "true",
                "IsMandatory": "false",
                "Section": "\"Bootstrap\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "ENABLE_EVPN",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "true"
            },
            "annotations": {
                "IsMandatory": "true",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "FEATURE_PTP_INTERNAL",
            "description": null,
            "parameterType": "boolean",
            "metaProperties": {
                "defaultValue": "false"
            },
            "annotations": {
                "IsMandatory": "true",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "SSPINE_COUNT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "defaultValue": "0"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "SPINE_COUNT",
            "description": null,
            "parameterType": "integer",
            "metaProperties": {
                "defaultValue": "0"
            },
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "abstract_feature_leaf",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_feature_leaf_upg"
            },
            "annotations": {
                "Enum": "\"base_feature_leaf_upg\"",
                "Description": "Feature Configuration for Leaf",
                "IsMandatory": "true",
                "DisplayName": "base_feature_leaf",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_feature_spine",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_feature_spine_upg"
            },
            "annotations": {
                "Enum": "\"base_feature_spine_upg\"",
                "Description": "Feature Configuration for Spine",
                "IsMandatory": "true",
                "DisplayName": "base_feature_spine",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_dhcp",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_dhcp"
            },
            "annotations": {
                "Enum": "\"base_dhcp\"",
                "Description": "DHCP Configuration",
                "IsMandatory": "true",
                "DisplayName": "base_dhcp",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_multicast",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_multicast_11_1"
            },
            "annotations": {
                "Enum": "\"base_multicast_11_1\"",
                "Description": "Multicast Configuration",
                "IsMandatory": "true",
                "DisplayName": "base_multicast",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_anycast_rp",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "anycast_rp"
            },
            "annotations": {
                "Enum": "\"anycast_rp\"",
                "Description": "Anycast RP Configuration",
                "IsMandatory": "true",
                "DisplayName": "anycast_rp",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_loopback_interface",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "int_fabric_loopback_11_1"
            },
            "annotations": {
                "Enum": "\"int_fabric_loopback_11_1\"",
                "Description": "Primary Loopback Interface Configuration",
                "IsMandatory": "true",
                "DisplayName": "loopback_interface",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_isis",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_isis_level2"
            },
            "annotations": {
                "Enum": "\"base_isis_level2\"",
                "Description": "ISIS Network Configuration",
                "IsMandatory": "true",
                "DisplayName": "base_isis_level2",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_ospf",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_ospf"
            },
            "annotations": {
                "Enum": "\"base_ospf\"",
                "Description": "OSPF Network Configuration",
                "IsMandatory": "true",
                "DisplayName": "base_ospf",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_vpc_domain",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_vpc_domain_11_1"
            },
            "annotations": {
                "Enum": "\"base_vpc_domain_11_1\"",
                "Description": "vPC Domain Configuration",
                "IsMandatory": "true",
                "DisplayName": "base_vpc_domain",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_vlan_interface",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "int_fabric_vlan_11_1"
            },
            "annotations": {
                "Enum": "\"int_fabric_vlan_11_1\"",
                "Description": "VLAN Interface Configuration",
                "IsMandatory": "true",
                "DisplayName": "vlan_interface",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_isis_interface",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "isis_interface"
            },
            "annotations": {
                "Enum": "\"isis_interface\"",
                "Description": "ISIS Interface Configuration",
                "IsMandatory": "true",
                "DisplayName": "isis_interface",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_ospf_interface",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "ospf_interface_11_1"
            },
            "annotations": {
                "Enum": "\"ospf_interface\"",
                "Description": "OSPF Interface Configuration",
                "IsMandatory": "true",
                "DisplayName": "ospf_interface_11_1",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_pim_interface",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "pim_interface"
            },
            "annotations": {
                "Enum": "\"pim_interface\"",
                "Description": "PIM Interface Configuration",
                "IsMandatory": "true",
                "DisplayName": "pim_interface",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_route_map",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "route_map"
            },
            "annotations": {
                "Enum": "\"route_map\"",
                "Description": "Route-Map Configuration",
                "IsMandatory": "true",
                "DisplayName": "abstract_route_map",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_bgp",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "base_bgp"
            },
            "annotations": {
                "Enum": "\"base_bgp\"",
                "Description": "BGP Configuration",
                "IsMandatory": "true",
                "DisplayName": "base_bgp",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_bgp_rr",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "evpn_bgp_rr"
            },
            "annotations": {
                "Enum": "\"evpn_bgp_rr\"",
                "Description": "BGP RR Configuration",
                "IsMandatory": "true",
                "DisplayName": "evpn_bgp_rr",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_bgp_neighbor",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "evpn_bgp_rr_neighbor"
            },
            "annotations": {
                "Enum": "\"evpn_bgp_rr_neighbor\"",
                "Description": "BGP Neighbor Configuration",
                "IsMandatory": "true",
                "DisplayName": "evpn_bgp_rr_neighbor",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_extra_config_leaf",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "extra_config_leaf"
            },
            "annotations": {
                "Enum": "\"extra_config_leaf\"",
                "Description": "Add Extra Configuration for Leaf",
                "IsMandatory": "true",
                "DisplayName": "extra_config_leaf",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_extra_config_spine",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "extra_config_spine"
            },
            "annotations": {
                "Enum": "\"extra_config_spine\"",
                "Description": "Add Extra Configuration for Spine",
                "IsMandatory": "true",
                "DisplayName": "extra_config_spine",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_extra_config_tor",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "extra_config_tor"
            },
            "annotations": {
                "Enum": "\"extra_config_tor\"",
                "Description": "Add Extra Configuration for ToR",
                "IsMandatory": "true",
                "DisplayName": "extra_config_tor",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_extra_config_bootstrap",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "extra_config_bootstrap_11_1"
            },
            "annotations": {
                "Enum": "\"extra_config_bootstrap\"",
                "Description": "Add Extra Configuration for Bootstrap",
                "IsMandatory": "true",
                "DisplayName": "extra_config_bootstrap",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "temp_anycast_gateway",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "anycast_gateway"
            },
            "annotations": {
                "Enum": "\"anycast_gateway\"",
                "Description": "Anycast Gateway MAC Configuration",
                "IsMandatory": "true",
                "DisplayName": "anycast_gateway",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "temp_vpc_domain_mgmt",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "vpc_domain_mgmt"
            },
            "annotations": {
                "Enum": "\"vpc_domain_mgmt\"",
                "Description": "vPC Keep-alive Configuration using Management VRF",
                "IsMandatory": "true",
                "DisplayName": "vpc_domain_mgmt",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "temp_vpc_peer_link",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "int_vpc_peer_link_po"
            },
            "annotations": {
                "Enum": "\"vpc_peer_link\"",
                "Description": "vPC Peer-Link Configuration",
                "IsMandatory": "true",
                "DisplayName": "vpc_peer_link",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_routed_host",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "int_routed_host"
            },
            "annotations": {
                "Enum": "\"int_routed_host\"",
                "Description": "Routed Host Port Configuration",
                "IsMandatory": "true",
                "DisplayName": "routed_host",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "abstract_trunk_host",
            "description": null,
            "parameterType": "string",
            "metaProperties": {
                "defaultValue": "int_trunk_host"
            },
            "annotations": {
                "Enum": "\"int_trunk_host\"",
                "Description": "trunk Host Port Configuration",
                "IsMandatory": "true",
                "DisplayName": "trunk_host",
                "Section": "\"Policy Templates\"",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": false
        },
        {
            "name": "UPGRADE_FROM_VERSION",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        },
        {
            "name": "TOPDOWN_CONFIG_RM_TRACKING",
            "description": null,
            "parameterType": "string",
            "metaProperties": {},
            "annotations": {
                "IsMandatory": "false",
                "IsInternal": "true"
            },
            "structureParameters": {},
            "parameterTypeStructure": false,
            "defaultValue": null,
            "optional": true
        }
    ],
    "tags": "[Data Center VXLAN EVPN]",
    "supportedPlatforms": "All",
    "content": "##template properties\nname =Easy_Fabric;\ndescription = Fabric for a VXLAN EVPN deployment with Nexus 9000 and 3000 switches.;\ntags =Data Center VXLAN EVPN;\nuserDefined = true;\nsupportedPlatforms = All;\ntemplateType = FABRIC;\ntemplateSubType = NA;\ncontentType = PYTHON;\nimplements = ;\ndependencies = ;\npublished = false;\nimports = ;\n##\n##template variables\n\n#    Copyright (c) 2018-2023 by Cisco Systems, Inc.\n#    All rights reserved.\n#General\n@(IsMandatory=true, IsFabricName=true, DisplayName=\"Fabric Name\", Description=\"Please provide the fabric name to create it (Max Size 32)\")\nstring FABRIC_NAME{\n  minLength = 1;\n  maxLength = 32;\n};\n\n@(IsMandatory=true, IsAsn=true, Description=\"1-4294967295 | 1-65535[.0-65535]<br/>It is a good practice to have a unique ASN for each Fabric.\", DisplayName=\"BGP ASN\")\nstring BGP_AS{\nminLength=1;\nmaxLength=11;\nregularExpr=^(((\\+)?[1-9]{1}[0-9]{0,8}|(\\+)?[1-3]{1}[0-9]{1,9}|(\\+)?[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])(\\.([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]|0))?)$;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring BGP_AS_PREV;\n\n@(IsMandatory=false, DisplayName=\"Enable IPv6 Underlay\", Description=\"If not enabled, IPv4 underlay is used\")\nboolean UNDERLAY_IS_V6\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==true\", DisplayName=\"Enable IPv6 Link-Local Address\",\nDescription=\"If not enabled, Spine-Leaf interfaces will use global IPv6 addresses\")\nboolean USE_LINK_LOCAL\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=true, Enum=\"p2p,unnumbered\", IsShow=\"UNDERLAY_IS_V6!=true\", DisplayName=\"Fabric Interface Numbering\", Description=\"Numbered(Point-to-Point) or Unnumbered\")\nstring FABRIC_INTERFACE_TYPE\n{\ndefaultValue=p2p;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false\", Enum=\"30,31\", Description=\"Mask for Underlay Subnet IP Range\", DisplayName=\"Underlay Subnet IP Mask\")\ninteger SUBNET_TARGET_MASK\n{\nmin = 30;\nmax = 31;\ndefaultValue=30;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && USE_LINK_LOCAL==false\", Enum=\"126,127\", Description=\"Mask for Underlay Subnet IPv6 Range\", DisplayName=\"Underlay Subnet IPv6 Mask\")\ninteger V6_SUBNET_TARGET_MASK\n{\nmin = 126;\nmax = 127;\ndefaultValue=126;\n};\n\n@(IsMandatory=true, Enum=\"ospf,is-is\", DisplayName=\"Underlay Routing Protocol\", Description=\"Used for Spine-Leaf Connectivity\")\nstring LINK_STATE_ROUTING\n{\ndefaultValue=ospf;\n};\n\n@(IsMandatory=true, Enum=\"2,4\", Description=\"Number of spines acting as Route-Reflectors\", DisplayName=\"Route-Reflectors\")\ninteger RR_COUNT\n{\ndefaultValue=2;\n};\n@(IsMandatory=true, IsAnycastGatewayMac=true, Description=\"Shared MAC address for all leafs (xxxx.xxxx.xxxx)\", DisplayName=\"Anycast Gateway MAC\")\nmacAddress ANYCAST_GW_MAC\n{\ndefaultValue=2020.0000.00aa;\n};\n\n@(IsMandatory=false, NoConfigChg=true, DisplayName=\"Enable Performance Monitoring\")\nboolean PM_ENABLE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean PM_ENABLE_PREV\n{\ndefaultValue=false;\n};\n\n#Multicast Replication\n@(IsMandatory=true, Enum=\"Multicast,Ingress\", IsReplicationMode=true, IsShow=\"UNDERLAY_IS_V6!=true\", Description=\"Replication Mode for BUM Traffic\", DisplayName=\"Replication Mode\", Section=\"Replication\")\nstring REPLICATION_MODE\n{\ndefaultValue=Multicast;\n};\n\n@(IsMandatory=true, IsMulticastGroupSubnet=true,\nIsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Description=\"Multicast pool prefix between 8 to 30. A multicast group IP<br/>from this pool is used for BUM traffic for each overlay network.\", DisplayName=\"Multicast Group Subnet\", Section=\"Replication\")\nipV4AddressWithSubnet MULTICAST_GROUP_SUBNET\n{\ndefaultValue=239.1.1.0/25;\n};\n\n@(IsMandatory=false, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Description=\"For Overlay Multicast Support In VXLAN Fabrics\", DisplayName=\"Enable Tenant Routed Multicast (TRM)\", Section=\"Replication\")\nboolean ENABLE_TRM\n{\ndefaultValue=false;\n};\n\n\n@(IsMandatory=true, IsMcastUnderlay=true,\nIsShow=\"REPLICATION_MODE==Multicast && ENABLE_TRM==true && UNDERLAY_IS_V6!=true\", DisplayName=\"Default MDT Address for TRM VRFs\", Description=\"Default Underlay Multicast group IP assigned for every overlay VRF.\", Section=\"Replication\")\nipV4Address L3VNI_MCAST_GROUP\n{\ndefaultValue=239.1.1.0;\n};\n\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Enum=\"2,4\", Description=\"Number of spines acting as Rendezvous-Point (RP)\", DisplayName=\"Rendezvous-Points\", Section=\"Replication\")\ninteger RP_COUNT\n{\ndefaultValue=2;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Enum=\"asm,bidir\", Description=\"Multicast RP Mode\", DisplayName=\"RP Mode\", Section=\"Replication\")\nstring RP_MODE\n{\ndefaultValue=asm;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Description=\"(Min:0, Max:1023)\", DisplayName=\"Underlay RP Loopback Id\", Section=\"Replication\")\ninteger RP_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=254;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && UNDERLAY_IS_V6!=true\", Description=\"Used for Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Primary <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID1{\nmin=0;\nmax=1023;\ndefaultValue=2;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && UNDERLAY_IS_V6!=true\", Description=\"Used for Fallback Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Backup <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID2{\nmin=0;\nmax=1023;\ndefaultValue=3;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && RP_COUNT==4 && UNDERLAY_IS_V6!=true\", Description=\"Used for second Fallback Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Second Backup <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID3{\nmin=0;\nmax=1023;\ndefaultValue=4;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && RP_COUNT==4 && UNDERLAY_IS_V6!=true\", Description=\"Used for third Fallback Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Third Backup <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID4{\nmin=0;\nmax=1023;\ndefaultValue=5;\n};\n\n#vPC\n@(IsMandatory=true, Description=\"VLAN range for vPC Peer Link SVI (Min:2, Max:4094)\", DisplayName=\"vPC Peer Link VLAN Range\", Section=\"vPC\")\nintegerRange VPC_PEER_LINK_VLAN\n{\nmin=2;\nmax=4094;\ndefaultValue=3600;\n};\n\n@(IsMandatory=false, DisplayName=\"Make vPC Peer Link VLAN as Native VLAN\", Section=\"vPC\")\nboolean ENABLE_VPC_PEER_LINK_NATIVE_VLAN\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, Enum=\"loopback,management\", Description=\"Use vPC Peer Keep Alive with Loopback or Management\", DisplayName=\"vPC Peer Keep Alive option\", Section=\"vPC\")\nstring VPC_PEER_KEEP_ALIVE_OPTION\n{\ndefaultValue=management;\n};\n\n@(IsMandatory=true, Description=\"(Min:240, Max:3600)\", DisplayName=\"vPC Auto Recovery Time <br/>(In Seconds)\", Section=\"vPC\")\ninteger VPC_AUTO_RECOVERY_TIME\n{\nmin = 240;\nmax = 3600;\ndefaultValue=360;\n};\n\n@(IsMandatory=true, Description=\"(Min:1, Max:3600)\", DisplayName=\"vPC Delay Restore Time <br/>(In Seconds)\", Section=\"vPC\")\ninteger VPC_DELAY_RESTORE\n{\nmin = 1;\nmax = 3600;\ndefaultValue=150;\n};\n\n@(IsMandatory=false, Description=\"(Min:1, Max:4096)\", DisplayName=\"vPC Peer Link Port Channel ID\", Section=\"vPC\")\nintegerRange VPC_PEER_LINK_PO\n{\nmin=1;\nmax=4096;\ndefaultValue=500;\n};\n\n@(IsMandatory=false, Description=\"Enable IPv6 ND synchronization between vPC peers\", DisplayName=\"vPC IPv6 ND Synchronize\", Section=\"vPC\")\nboolean VPC_ENABLE_IPv6_ND_SYNC\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, Description=\"For Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes\", DisplayName=\"vPC advertise-pip\", Section=\"vPC\")\nboolean ADVERTISE_PIP_BGP\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"ADVERTISE_PIP_BGP!=true\", Description=\"Enable advertise-pip on vPC borders and border gateways only. Applicable only when vPC advertise-pip is not enabled\", DisplayName=\"vPC advertise-pip on Border only\", Section=\"vPC\")\nboolean ADVERTISE_PIP_ON_BORDER\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, Description=\"(Not Recommended) \", DisplayName=\"Enable the same vPC Domain Id <br/>for all vPC Pairs\", Section=\"vPC\")\nboolean ENABLE_FABRIC_VPC_DOMAIN_ID\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ENABLE_FABRIC_VPC_DOMAIN_ID_PREV;\n\n@(IsMandatory=true, IsShow=\"ENABLE_FABRIC_VPC_DOMAIN_ID==true\", Description=\"vPC Domain Id to be used on all vPC pairs\", DisplayName=\"vPC Domain Id\", Section=\"vPC\")\ninteger FABRIC_VPC_DOMAIN_ID\n{\nmin = 1;\nmax = 1000;\ndefaultValue=1;\n};\n\n@(IsMandatory=false, DisplayName=\"Internal Fabric Wide vPC Domain Id\", IsInternal=true)\ninteger FABRIC_VPC_DOMAIN_ID_PREV\n{\nmin = 1;\nmax = 1000;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_FABRIC_VPC_DOMAIN_ID==false\", Description=\"vPC Domain id range to use for new pairings\", DisplayName=\"vPC Domain Id Range\", Section=\"vPC\")\nintegerRange VPC_DOMAIN_ID_RANGE\n{\nmin=1;\nmax=1000;\ndefaultValue=1-1000;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==false\", Description=\"Qos on spines for guaranteed delivery of vPC Fabric Peering communication\", DisplayName=\"Enable Qos for Fabric vPC-Peering\", Section=\"vPC\")\nboolean FABRIC_VPC_QOS\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"FABRIC_VPC_QOS==true\", Description=\"Qos Policy name should be same on all spines\", DisplayName=\"Qos Policy Name\", Section=\"vPC\")\nstring FABRIC_VPC_QOS_POLICY_NAME\n{\nminLength = 1;\nmaxLength = 40;\ndefaultValue=spine_qos_for_fabric_vpc_peering;\n};\n\n#Protocols\n\n@(IsMandatory=true, Description=\"(Min:0, Max:1023)\", DisplayName=\"Underlay Routing Loopback Id\", Section=\"Protocols\")\ninteger BGP_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=0;\n};\n\n@(IsMandatory=true, Description=\"(Min:0, Max:1023)\", DisplayName=\"Underlay VTEP Loopback Id\", Section=\"Protocols\")\ninteger NVE_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=1;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true\", Description=\"Used for vPC Peering in VXLANv6 Fabrics (Min:0, Max:1023)\", DisplayName=\"Underlay Anycast Loopback Id\", Section=\"Protocols\")\ninteger ANYCAST_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=10;\n};\n\n@(IsMandatory=true, DisplayName=\"Underlay Routing Protocol Tag\", Description=\"Underlay Routing Process Tag\", Section=\"Protocols\")\nstring LINK_STATE_ROUTING_TAG\n{\nminLength = 1;\nmaxLength = 20;\ndefaultValue=UNDERLAY;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring LINK_STATE_ROUTING_TAG_PREV;\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==ospf\", DisplayName=\"OSPF Area Id\", Description=\"OSPF Area Id in IP address format\", Section=\"Protocols\")\nstring OSPF_AREA_ID\n{\nminLength = 1;\nmaxLength = 15;\ndefaultValue=0.0.0.0;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==ospf && UNDERLAY_IS_V6==false\", DisplayName=\"Enable OSPF Authentication\", Section=\"Protocols\")\nboolean OSPF_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==ospf && OSPF_AUTH_ENABLE==true\", DisplayName=\"OSPF Authentication Key ID\", Description=\"(Min:0, Max:255)\", Section=\"Protocols\")\ninteger OSPF_AUTH_KEY_ID\n{\nmin = 0;\nmax = 255;\ndefaultValue = 127;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==ospf && OSPF_AUTH_ENABLE==true\", DisplayName=\"OSPF Authentication Key\", Description=\"3DES Encrypted\", Section=\"Protocols\")\nstring OSPF_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 256;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is\", Enum=\"level-1,level-2\", DisplayName=\"IS-IS Level\", Description=\"Supported IS types: level-1, level-2\", Section=\"Protocols\")\nstring ISIS_LEVEL\n{\ndefaultValue=level-2;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==is-is\", DisplayName=\"Enable IS-IS Network Point-to-Point\", Description=\"This will enable network point-to-point on fabric interfaces which are numbered\", Section=\"Protocols\")\nboolean ISIS_P2P_ENABLE\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==is-is && UNDERLAY_IS_V6==false\", DisplayName=\"Enable IS-IS Authentication\", Section=\"Protocols\")\nboolean ISIS_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\", DisplayName=\"IS-IS Authentication Keychain Name\", Section=\"Protocols\")\nstring ISIS_AUTH_KEYCHAIN_NAME\n{\nminLength = 1;\nmaxLength = 63;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\", DisplayName=\"IS-IS Authentication Key ID\", Description=\"(Min:0, Max:65535)\", Section=\"Protocols\")\ninteger ISIS_AUTH_KEYCHAIN_KEY_ID\n{\nmin = 0;\nmax = 65535;\ndefaultValue = 127;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\", DisplayName=\"IS-IS Authentication Key\", Description=\"Cisco Type 7 Encrypted\", Section=\"Protocols\")\nstring ISIS_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 255;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==is-is\", DisplayName=\"Set IS-IS Overload Bit\", Description=\"When enabled, set the overload bit for an elapsed time after a reload\", Section=\"Protocols\")\nboolean ISIS_OVERLOAD_ENABLE\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_OVERLOAD_ENABLE==true\", DisplayName=\"IS-IS Overload Bit Elapsed Time\", Description=\"Clear the overload bit after an elapsed time in seconds\", Section=\"Protocols\")\ninteger ISIS_OVERLOAD_ELAPSE_TIME\n{\nmin = 5;\nmax = 86400;\ndefaultValue=60;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", DisplayName=\"Enable BGP Authentication\", Section=\"Protocols\")\nboolean BGP_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, Enum=\"3,7\", IsShow=\"BGP_AUTH_ENABLE==true\", DisplayName=\"BGP Authentication Key <br/>Encryption Type\", Description=\"BGP Key Encryption Type: 3 - 3DES, 7 - Cisco\", Section=\"Protocols\")\nstring BGP_AUTH_KEY_TYPE {\ndefaultValue=3;\n};\n\n@(IsMandatory=true, IsShow=\"BGP_AUTH_ENABLE==true\", DisplayName=\"BGP Authentication Key\", Description=\"Encrypted BGP Authentication Key based on type\", Section=\"Protocols\")\nstring BGP_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 256;\n};\n\n@(IsMandatory=false, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6==false\", DisplayName=\"Enable PIM Hello Authentication\", Description=\"Valid for IPv4 Underlay only\", Section=\"Protocols\")\nboolean PIM_HELLO_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"PIM_HELLO_AUTH_ENABLE==true\", DisplayName=\"PIM Hello Authentication Key\", Description=\"3DES Encrypted\", Section=\"Protocols\")\nstring PIM_HELLO_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 256;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", DisplayName=\"Enable BFD\", Description=\"Valid for IPv4 Underlay only\", Section=\"Protocols\")\nboolean BFD_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true\", DisplayName=\"Enable BFD For iBGP\", Section=\"Protocols\")\nboolean BFD_IBGP_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && LINK_STATE_ROUTING==ospf\", DisplayName=\"Enable BFD For OSPF\", Section=\"Protocols\")\nboolean BFD_OSPF_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && LINK_STATE_ROUTING==is-is\", DisplayName=\"Enable BFD For ISIS\", Section=\"Protocols\")\nboolean BFD_ISIS_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && REPLICATION_MODE==Multicast\", DisplayName=\"Enable BFD For PIM\", Section=\"Protocols\")\nboolean BFD_PIM_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && FABRIC_INTERFACE_TYPE==p2p && BFD_ENABLE==true\", DisplayName=\"Enable BFD Authentication\", Description=\"Valid for P2P Interfaces only\", Section=\"Protocols\")\nboolean BFD_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && FABRIC_INTERFACE_TYPE==p2p && BFD_AUTH_ENABLE==true\", DisplayName=\"BFD Authentication Key ID\", Section=\"Protocols\")\ninteger BFD_AUTH_KEY_ID\n{\nmin = 1;\nmax = 255;\ndefaultValue = 100;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && FABRIC_INTERFACE_TYPE==p2p && BFD_AUTH_ENABLE==true\", DisplayName=\"BFD Authentication Key\", Description=\"Encrypted SHA1 secret value\", Section=\"Protocols\")\nstring BFD_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 40;\n};\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"iBGP Peer-Template Config\", Description=\"Speficies the iBGP Peer-Template config used for RR and<br/>spines with border role. \", Warning=\"Speficies the config used for RR and<br/> spines with border or border gateway role. <br/> This field should begin with<br/>'  template peer' or '  template peer-session'. <br/> This must have 2 leading spaces. <br/>Note ! All configs should <br/>strictly match show run output, <br/>with respect to case and newlines. <br/>Any mismatches will yield <br/>unexpected diffs during deploy.\", Section=\"Protocols\")\nstring IBGP_PEER_TEMPLATE;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Leaf/Border/Border Gateway<br/>iBGP Peer-Template Config \", Description=\"Specifies the config used for leaf, border or<br/> border gateway.<br/>If this field is empty, the peer template defined in<br/>iBGP Peer-Template Config is used on all BGP enabled devices<br/>(RRs,leafs, border or border gateway roles.\", Warning=\"Specifies the config used for leaf, border or<br/> border gateway.<br/>If this field is empty, the peer template defined in<br/>iBGP Peer-Template Config is used on all BGP<br/>enabled devices (RRs, leafs,<br/> border or border gateway roles).<br/>This field should begin with<br/>'  template peer' or '  template peer-session'.<br/> This must have 2 leading spaces. <br/>Note ! All configs should <br/>strictly match 'show run' output, <br/>with respect to case and newlines. <br/>Any mismatches will yield <br/>unexpected diffs during deploy.\", Section=\"Protocols\")\nstring IBGP_PEER_TEMPLATE_LEAF;\n\n#Advanced\n@(IsMandatory=true, IsVrfTemplate=true, Enum=\"%TEMPLATES.vrf\", Description=\"Default Overlay VRF Template For Leafs\", DisplayName=\"VRF Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring default_vrf\n{\ndefaultValue=Default_VRF_Universal;\n};\n\n@(IsMandatory=true, IsNetworkTemplate=true, Enum=\"%TEMPLATES.network\", Description=\"Default Overlay Network Template For Leafs\", DisplayName=\"Network Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring default_network\n{\ndefaultValue=Default_Network_Universal;\n};\n\n@(IsMandatory=true, IsVrfExtensionTemplate=true, Enum=\"%TEMPLATES.vrfExtension\", Description=\"Default Overlay VRF Template For Borders\", DisplayName=\"VRF Extension Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring vrf_extension_template\n{\ndefaultValue=Default_VRF_Extension_Universal;\n};\n\n@(IsMandatory=true, IsNetworkExtensionTemplate=true, Enum=\"%TEMPLATES.networkExtension\", Description=\"Default Overlay Network Template For Borders\", DisplayName=\"Network Extension Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring network_extension_template\n{\ndefaultValue=Default_Network_Extension_Universal;\n};\n\n@(IsMandatory=false, DisplayName=\"Overlay Mode\", Description=\"VRF/Network configuration using config-profile or CLI\", Section=\"Advanced\")\nenum OVERLAY_MODE\n{\nvalidValues=config-profile,cli;\ndefaultValue=cli;\n};\n\n@(IsMandatory=false, IsInternal=true)\nenum OVERLAY_MODE_PREV\n{\nvalidValues=config-profile,cli;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Private VLAN (PVLAN)\", Description=\"Enable PVLAN on switches except spines and super spines\", Section=\"Advanced\")\nboolean ENABLE_PVLAN {\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ENABLE_PVLAN_PREV;\n\n@(IsMandatory=\"ENABLE_PVLAN==true\", IsShow=\"ENABLE_PVLAN==true\", IsPvlanSecNetworkTemplate=true, IsPvlanSecNetworkExtTemplate=true, Enum=\"%TEMPLATES.pvlanSecNetwork\", Description=\"Default PVLAN Secondary Network Template\", DisplayName=\"PVLAN Secondary Network Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring default_pvlan_sec_network\n{\ndefaultValue=Pvlan_Secondary_Network;\n};\n\n@(IsMandatory=false, IsSiteId=true,AutoPopulate=\"BGP_AS\", Description=\"For EVPN Multi-Site Support (Min:1, Max: 281474976710655). <br/>Defaults to Fabric ASN\", DisplayName=\"Site Id\", Section=\"Advanced\")\nstring SITE_ID\n{\nminLength=1;\nmaxLength=15;\nregularExpr=^(((\\+)?[1-9]{1}[0-9]{0,13}|(\\+)?[1]{1}[0-9]{1,14}|(\\+)?[2]{1}([0-7]{1}[0-9]{13}|[8]{1}([0-0]{1}[0-9]{12}|[1]{1}([0-3]{1}[0-9]{11}|[4]{1}([0-6]{1}[0-9]{10}|[7]{1}([0-3]{1}[0-9]{9}|[4]{1}([0-8]{1}[0-9]{8}|[9]{1}([0-6]{1}[0-9]{7}|[7]{1}([0-5]{1}[0-9]{6}|[6]{1}([0-6]{1}[0-9]{5}|[7]{1}([0-0]{1}[0-9]{4}|[1]{1}([0]{0}[0-9]{3}|[0]{1}([0-5]{1}[0-9]{2}|[6]{1}([0-4]{1}[0-9]{1}|[5]{1}[0-5]{1}))))))))))))))|([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])(\\.([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]|0))?)$;\n};\n\n\n\n@(IsMandatory=true, IsMTU=true, Description=\"(Min:576, Max:9216). Must be an even number\", DisplayName=\"Intra Fabric Interface MTU\", Section=\"Advanced\")\ninteger FABRIC_MTU\n{\nmin = 576;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger FABRIC_MTU_PREV\n{\nmin = 576;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=true, IsMTU=true, Description=\"(Min:1500, Max:9216). Must be an even number\", DisplayName=\"Layer 2 Host Interface MTU\", Section=\"Advanced\")\ninteger L2_HOST_INTF_MTU\n{\nmin = 1500;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger L2_HOST_INTF_MTU_PREV\n{\nmin = 1500;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=false, DisplayName=\"Unshut Host Interfaces by Default\", Section=\"Advanced\")\nboolean HOST_INTF_ADMIN_STATE {\ndefaultValue=true;\n};\n\n@(IsMandatory=true, Enum=\"ps-redundant,combined,insrc-redundant\", Description=\"Default Power Supply Mode For The Fabric\", DisplayName=\"Power Supply Mode\", Section=\"Advanced\")\nstring POWER_REDUNDANCY_MODE\n{\ndefaultValue=ps-redundant;\n};\n\n@(IsMandatory=true, Enum=\"dense,lenient,moderate,strict,manual\", Description=\"Fabric Wide CoPP Policy. Customized CoPP policy should be <br/> provided when 'manual' is selected\", DisplayName=\"CoPP Profile\", Section=\"Advanced\")\nstring COPP_POLICY\n{\ndefaultValue=strict;\n};\n\n@(IsMandatory=false, Description=\"NVE Source Inteface HoldDown Time (Min:1, Max:1500) in seconds\", DisplayName=\"VTEP HoldDown Time\", Section=\"Advanced\")\ninteger HD_TIME{\nmin = 1;\nmax = 1500;\ndefaultValue=180;\n};\n\n@(IsMandatory=false, DisplayName=\"Brownfield Overlay Network Name <br/>Format\", Description=\"Generated network name should be < 64 characters\", Section=\"Advanced\")\nstring BROWNFIELD_NETWORK_NAME_FORMAT\n{\nminLength = 1;\nmaxLength = 80;\ndefaultValue=Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$;\n};\n\n@(IsMandatory=false, DisplayName=\"Skip Overlay Network Interface Attachments\", Description=\"Enable to skip overlay network interface attachments for Brownfield and Host Port Resync cases\", Section=\"Advanced\")\nboolean BROWNFIELD_SKIP_OVERLAY_NETWORK_ATTACHMENTS\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable CDP for Bootstrapped Switch\", Description=\"Enable CDP on management interface\", Section=\"Advanced\")\nboolean CDP_ENABLE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable VXLAN OAM\", Section=\"Advanced\", Description=\"Enable the Next Generation (NG) OAM feature for all switches in the fabric to aid in trouble-shooting VXLAN EVPN fabrics\")\nboolean ENABLE_NGOAM\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Tenant DHCP\", Section=\"Advanced\")\nboolean ENABLE_TENANT_DHCP\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable NX-API\", Description=\"Enable HTTPS NX-API\", Section=\"Advanced\")\nboolean ENABLE_NXAPI\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_NXAPI==true\", DisplayName=\"NX-API HTTPS Port Number\", Section=\"Advanced\")\ninteger NXAPI_HTTPS_PORT\n{\nmin = 1;\nmax = 65535;\ndefaultValue=443;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_NXAPI==true\", DisplayName=\"Enable HTTP NX-API\", Section=\"Advanced\")\nboolean ENABLE_NXAPI_HTTP\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_NXAPI_HTTP==true\", DisplayName=\"NX-API HTTP Port Number\", Section=\"Advanced\")\ninteger NXAPI_HTTP_PORT\n{\nmin = 1;\nmax = 65535;\ndefaultValue=80;\n};\n\n@(IsMandatory=false, DisplayName=\"Elastic Services Re-direction (ESR) Options\", Description=\"Policy-Based Routing (PBR) or Enhanced PBR (ePBR)\", NoConfigChg=true, Section=\"Advanced\")\nenum ESR_OPTION {\n  validValues=ePBR,PBR;\n  defaultValue=PBR;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Policy-Based Routing (PBR)/Enhanced PBR (ePBR)\", Description=\"When ESR option is ePBR, enable ePBR will enable pbr, sla sender and epbr features on the switch\", Section=\"Advanced\")\nboolean ENABLE_PBR {\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Strict Config Compliance\", Section=\"Advanced\", Description=\"Enable bi-directional compliance checks to flag additional configs in the running config that are not in the intent/expected config\")\nboolean STRICT_CC_MODE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, Description=\"Enable only, when IP Authorization is enabled in the AAA Server\", DisplayName=\"Enable AAA IP Authorization\", Section=\"Advanced\")\nboolean AAA_REMOTE_IP_ENABLED\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable NDFC as Trap Host\", Section=\"Advanced\", Description=\"Configure NDFC as a receiver for SNMP traps\")\nboolean SNMP_SERVER_HOST_TRAP\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, DisplayName=\"Anycast Border Gateway advertise-pip\", Section=\"Advanced\", Description=\"To advertise Anycast Border Gateway PIP as VTEP. Effective on MSD fabric 'Recalculate Config'\")\nboolean ANYCAST_BGW_ADVERTISE_PIP\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsFreezeMode=true, DisplayName=\"Disable all deployments in this fabric\", Section=\"Hidden\")\nboolean DEPLOYMENT_FREEZE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true,Enum=\"Enable,Disable\", IsShow=\"AAA_REMOTE_IP_ENABLED==false\", Description=\"Enable to clean switch configuration without reload when PreserveConfig=no\", DisplayName=\"Greenfield Cleanup Option\", Section=\"Advanced\")\nstring GRFIELD_DEBUG_FLAG\n{\ndefaultValue=Disable;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6!=true\", DisplayName=\"Enable Precision Time Protocol (PTP)\", Section=\"Advanced\")\nboolean FEATURE_PTP {\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"FEATURE_PTP==true\", Description=\"(Min:0, Max:1023)\", DisplayName=\"PTP Source Loopback Id\", Section=\"Advanced\")\ninteger PTP_LB_ID\n{\nmin = 0;\nmax = 1023;\ndefaultValue=0;\n};\n\n@(IsMandatory=true, IsShow=\"FEATURE_PTP==true\", Description=\"Multiple Independent PTP Clocking Subdomains <br/>on a Single Network (Min:0, Max:127)\", DisplayName=\"PTP Domain Id\", Section=\"Advanced\")\ninteger PTP_DOMAIN_ID\n{\nmin = 0;\nmax = 127;\ndefaultValue=0;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", DisplayName=\"Enable MPLS Handoff\", Section=\"Advanced\")\nboolean MPLS_HANDOFF\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"MPLS_HANDOFF==true && UNDERLAY_IS_V6==false\", Description=\"Used for VXLAN to MPLS SR/LDP Handoff <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay MPLS Loopback Id\", Section=\"Advanced\")\ninteger MPLS_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=101;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable TCAM Allocation\", Description=\"TCAM commands are automatically generated for VxLAN and vPC Fabric Peering when Enabled\", Section=\"Advanced\")\nboolean TCAM_ALLOCATION{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"FABRIC_VPC_QOS==false\", DisplayName=\"Enable Default Queuing Policies\", Section=\"Advanced\")\nboolean ENABLE_DEFAULT_QUEUING_POLICY{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==true\", Enum=\"%TEMPLATES.QoS_Cloud\", AlwaysSetDefault=true, DisplayName=\"N9K Cloud Scale Platform <br/>Queuing Policy\", Description=\"Queuing Policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX <br/>series switches in the fabric\", Section=\"Advanced\")\nstring DEAFULT_QUEUING_POLICY_CLOUDSCALE\n{\ndefaultValue=queuing_policy_default_8q_cloudscale;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==true\", Enum=\"%TEMPLATES.QoS_R_Series\", AlwaysSetDefault=true, DisplayName=\"N9K R-Series Platform <br/>Queuing Policy\", Description=\"Queuing Policy for all R-Series <br/>switches in the fabric\", Section=\"Advanced\")\nstring DEAFULT_QUEUING_POLICY_R_SERIES\n{\ndefaultValue=queuing_policy_default_r_series;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==true\", Enum=\"%TEMPLATES.QoS_Other\", AlwaysSetDefault=true, DisplayName=\"Other N9K Platform <br/>Queuing Policy\", Description=\"Queuing Policy for all other <br/>switches in the fabric\", Section=\"Advanced\")\nstring DEAFULT_QUEUING_POLICY_OTHER\n{\ndefaultValue=queuing_policy_default_other;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable MACsec\", Description=\"Enable MACsec in the fabric\", Section=\"Advanced\")\nboolean ENABLE_MACSEC {\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Primary Key String\", Description=\"Cisco Type 7 Encrypted Octet String\", Section=\"Advanced\")\nstring MACSEC_KEY_STRING {\nminLength = 1;\nmaxLength = 130;\nregularExpr=^[a-fA-F0-9]+$;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Primary Cryptographic <br/>Algorithm\", Description=\"AES_128_CMAC or AES_256_CMAC\", Section=\"Advanced\")\nenum MACSEC_ALGORITHM {\nvalidValues=AES_128_CMAC,AES_256_CMAC;\ndefaultValue=AES_128_CMAC;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Fallback Key String\", Description=\"Cisco Type 7 Encrypted Octet String\", Section=\"Advanced\")\nstring MACSEC_FALLBACK_KEY_STRING {\nminLength = 1;\nmaxLength = 130;\nregularExpr=^[a-fA-F0-9]+$;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Fallback Cryptographic <br/>Algorithm\", Description=\"AES_128_CMAC or AES_256_CMAC\", Section=\"Advanced\")\nenum MACSEC_FALLBACK_ALGORITHM {\nvalidValues=AES_128_CMAC,AES_256_CMAC;\ndefaultValue=AES_128_CMAC;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Cipher Suite\", Description=\"Configure Cipher Suite\", Section=\"Advanced\")\nenum MACSEC_CIPHER_SUITE {\nvalidValues=GCM-AES-128,GCM-AES-256,GCM-AES-XPN-128,GCM-AES-XPN-256;\ndefaultValue=GCM-AES-XPN-256;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Status Report Timer\", Description=\"MACsec Operational Status periodic report timer in minutes\", Section=\"Advanced\")\ninteger MACSEC_REPORT_TIMER {\nmin = 5;\nmax = 60;\ndefaultValue=5;\n};\n\n@(IsMandatory=false, Enum=\"rpvst+,mst,unmanaged\", DisplayName=\"Spanning Tree Root Bridge Protocol\", Description=\"Which protocol to use for configuring root bridge? rpvst+: Rapid Per-VLAN Spanning Tree, mst: Multiple Spanning Tree, unmanaged (default): STP Root not managed by NDFC\", Section=\"Advanced\")\nstring STP_ROOT_OPTION\n{\ndefaultValue=unmanaged;\n};\n\n@(IsMandatory=true, IsShow=\"STP_ROOT_OPTION==rpvst+\", DisplayName=\"Spanning Tree VLAN Range\", Description=\"Vlan range, Example: 1,3-5,7,9-11, Default is 1-3967\", Section=\"Advanced\")\nintegerRange STP_VLAN_RANGE\n{\nmin=1;\nmax=4092;\ndefaultValue=1-3967;\n};\n\n@(IsMandatory=true, IsShow=\"STP_ROOT_OPTION==mst\", DisplayName=\"MST Instance Range\", Description=\"MST instance range, Example: 0-3,5,7-9, Default is 0\", Section=\"Advanced\")\nintegerRange MST_INSTANCE_RANGE\n{\nmin=0;\nmax=4094;\ndefaultValue=0;\n};\n\n@(IsMandatory=true, IsShow=\"STP_ROOT_OPTION==rpvst+||STP_ROOT_OPTION==mst\", DisplayName=\"Spanning Tree Bridge Priority\", Description=\"Bridge priority for the spanning tree in increments of 4096\", Section=\"Advanced\")\nenum STP_BRIDGE_PRIORITY\n{\nvalidValues=0,4096,8192,12288,16384,20480,24576,28672,32768,36864,40960,45056,49152,53248,57344,61440;\ndefaultValue=0;\n};\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Leaf Freeform Config\", Description=\"Additional CLIs For All Leafs As Captured From Show Running Configuration\", Section=\"Advanced\")\nstring EXTRA_CONF_LEAF;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Spine Freeform Config\", Description=\"Additional CLIs For All Spines As Captured From Show Running Configuration\", Section=\"Advanced\")\nstring EXTRA_CONF_SPINE;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"ToR Freeform Config\", Description=\"Additional CLIs For All ToRs As Captured From Show Running Configuration\", Section=\"Advanced\")\nstring EXTRA_CONF_TOR;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Intra-fabric Links Additional Config\", Description=\"Additional CLIs For All Intra-Fabric Links\", Section=\"Advanced\")\nstring EXTRA_CONF_INTRA_LINKS;\n\n#Resources\n@(IsMandatory=false, Description=\"Checking this will disable Dynamic Underlay IP Address Allocations\", DisplayName=\"Manual Underlay IP Address <br/>Allocation\", Section=\"Resources\")\nboolean STATIC_UNDERLAY_IP_ALLOC\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback0 IP Address Range\", DisplayName=\"Underlay Routing Loopback IP <br/>Range\", Section=\"Resources\")\nipV4AddressWithSubnet LOOPBACK0_IP_RANGE\n{\ndefaultValue=10.2.0.0/22;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback1 IP Address Range\", DisplayName=\"Underlay VTEP Loopback IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet LOOPBACK1_IP_RANGE\n{\ndefaultValue=10.3.0.0/22;\n};\n\n@(IsMandatory=true, IsShow=\"($$STATIC_UNDERLAY_IP_ALLOC$$=='false' && $$UNDERLAY_IS_V6$$=='false' && $$REPLICATION_MODE$$=='Multicast') || ($$STATIC_UNDERLAY_IP_ALLOC$$=='true' && $$UNDERLAY_IS_V6$$=='false' && $$REPLICATION_MODE$$=='Multicast' && $$RP_MODE$$=='bidir')\", Description=\"Anycast or Phantom RP IP Address Range\", DisplayName=\"Underlay RP Loopback IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet ANYCAST_RP_IP_RANGE\n{\ndefaultValue=10.254.254.0/24;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Address range to assign Numbered and Peer Link SVI IPs\", DisplayName=\"Underlay Subnet IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet SUBNET_RANGE\n{\ndefaultValue=10.4.0.0/16;\n};\n\n@(IsMandatory=true, IsShow=\"MPLS_HANDOFF==true && UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Used for VXLAN to MPLS SR/LDP Handoff\", DisplayName=\"Underlay MPLS Loopback IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet MPLS_LOOPBACK_IP_RANGE\n{\ndefaultValue=10.101.0.0/25;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback0 IPv6 Address Range\", DisplayName=\"Underlay Routing Loopback IPv6 <br/>Range\", Section=\"Resources\")\nipV6AddressWithSubnet LOOPBACK0_IPV6_RANGE\n{\ndefaultValue=fd00::a02:0/119;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback1 and Anycast Loopback IPv6 Address Range\", DisplayName=\"Underlay VTEP Loopback IPv6 <br/>Range\", Section=\"Resources\")\nipV6AddressWithSubnet LOOPBACK1_IPV6_RANGE\n{\ndefaultValue=fd00::a03:0/118;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false && USE_LINK_LOCAL==false\", Description=\"IPv6 Address range to assign Numbered and Peer Link SVI IPs\", DisplayName=\"Underlay Subnet IPv6 Range\", Section=\"Resources\")\nipV6AddressWithSubnet V6_SUBNET_RANGE\n{\ndefaultValue=fd00::a04:0/112;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\", DisplayName=\"BGP Router ID Range for IPv6 Underlay\", Section=\"Resources\")\nipV4AddressWithSubnet ROUTER_ID_RANGE\n{\ndefaultValue=10.2.0.0/23;\n};\n\n@(IsMandatory=true, IsL2VniRange=true, Description=\"Overlay Network Identifier Range (Min:1, Max:16777214)\", DisplayName=\"Layer 2 VXLAN VNI Range\", Section=\"Resources\")\nintegerRange L2_SEGMENT_ID_RANGE\n{\nmin=1;\nmax=16777214;\ndefaultValue=30000-49000;\n};\n\n@(IsMandatory=true, IsL3VniRange=true, Description=\"Overlay VRF Identifier Range (Min:1, Max:16777214)\", DisplayName=\"Layer 3 VXLAN VNI Range\", Section=\"Resources\")\nintegerRange L3_PARTITION_ID_RANGE\n{\nmin=1;\nmax=16777214;\ndefaultValue=50000-59000;\n};\n\n@(IsMandatory=true, IsNetworkVlanRange=true, Description=\"Per Switch Overlay Network VLAN Range (Min:2, Max:4094)\", DisplayName=\"Network VLAN Range\", Section=\"Resources\")\nintegerRange NETWORK_VLAN_RANGE\n{\nmin=2;\nmax=4094;\ndefaultValue=2300-2999;\n};\n\n@(IsMandatory=true, IsVrfVlanRange=true, Description=\"Per Switch Overlay VRF VLAN Range (Min:2, Max:4094)\", DisplayName=\"VRF VLAN Range\", Section=\"Resources\")\nintegerRange VRF_VLAN_RANGE\n{\nmin=2;\nmax=4094;\ndefaultValue=2000-2299;\n};\n\n@(IsMandatory=true, IsDot1qIdRange=true, Description=\"Per Border Dot1q Range For VRF Lite Connectivity (Min:2, Max:4093)\", DisplayName=\"Subinterface Dot1q Range\", Section=\"Resources\")\nintegerRange SUBINTERFACE_RANGE\n{\nmin=2;\nmax=4093;\ndefaultValue=2-511;\n};\n\n@(IsMandatory=true, Enum=\"Manual,Back2Back&ToExternal\", Description=\"VRF Lite Inter-Fabric Connection Deployment Options. If 'Back2Back&ToExternal' is selected, VRF Lite IFCs are auto created between border devices of two Easy Fabrics, and between border devices in Easy Fabric and edge routers in External Fabric. The IP address is taken from the 'VRF Lite Subnet IP Range' pool.\", DisplayName=\"VRF Lite Deployment\", Section=\"Resources\")\nstring VRF_LITE_AUTOCONFIG\n{\ndefaultValue=Manual;\n};\n\n@(IsMandatory=false, IsShow=\"VRF_LITE_AUTOCONFIG!=Manual\", DisplayName=\"Auto Deploy for Peer\", Description=\"Whether to auto generate VRF LITE sub-interface and BGP peering configuration on managed neighbor devices. If set, auto created VRF Lite IFC links will have 'Auto Deploy for Peer' enabled.\", Section=\"Resources\")\nboolean AUTO_SYMMETRIC_VRF_LITE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"VRF_LITE_AUTOCONFIG!=Manual\", DisplayName=\"Auto Deploy Default VRF\", Description=\"Whether to auto generate Default VRF interface and BGP peering configuration on VRF LITE IFC auto deployment. If set, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF' enabled.\", Section=\"Resources\")\nboolean AUTO_VRFLITE_IFC_DEFAULT_VRF\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\", DisplayName=\"Auto Deploy Default VRF for Peer\", Description=\"Whether to auto generate Default VRF interface and BGP peering configuration on managed neighbor devices. If set, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF for Peer' enabled.\", Section=\"Resources\")\nboolean AUTO_SYMMETRIC_DEFAULT_VRF\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\", IsShow=\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\", DisplayName=\"Redistribute BGP Route-map Name\", Description=\"Route Map used to redistribute BGP routes to IGP in default vrf in auto created VRF Lite IFC links\", Section=\"Resources\")\nstring DEFAULT_VRF_REDIS_BGP_RMAP\n{\ndefaultValue=extcon-rmap-filter;\n};\n\n@(IsMandatory=true, Description=\"Address range to assign P2P Interfabric Connections\", DisplayName=\"VRF Lite Subnet IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet DCI_SUBNET_RANGE\n{\ndefaultValue=10.33.0.0/16;\n};\n\n@(IsMandatory=true,  Description=\"(Min:8, Max:31)\", DisplayName=\"VRF Lite Subnet Mask\", Section=\"Resources\")\ninteger DCI_SUBNET_TARGET_MASK\n{\nmin = 8;\nmax = 31;\ndefaultValue=30;\n};\n\n@(IsMandatory=false, DisplayName=\"Auto Allocation of Unique IP on VRF Extension over VRF Lite IFC\", Description=\"When enabled, IP prefix allocated to the VRF LITE IFC is not reused on VRF extension over VRF LITE IFC. Instead, unique IP Subnet is allocated for each VRF extension over VRF LITE IFC.\", Section=\"Resources\")\nboolean AUTO_UNIQUE_VRF_LITE_IP_PREFIX\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true, Section=\"Resources\")\nboolean AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Per VRF Per VTEP Loopback Auto-Provisioning\", Description=\"Auto provision a loopback on a VTEP on VRF attachment\", Section=\"Resources\")\nboolean PER_VRF_LOOPBACK_AUTO_PROVISION\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true, Section=\"Resources\")\nboolean PER_VRF_LOOPBACK_AUTO_PROVISION_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"PER_VRF_LOOPBACK_AUTO_PROVISION==true\", DisplayName=\"Per VRF Per VTEP IP Pool for Loopbacks\", Description=\"Prefix pool to assign IP addresses to loopbacks on VTEPs on a per VRF basis\", Section=\"Resources\")\nipV4AddressWithSubnet PER_VRF_LOOPBACK_IP_RANGE\n{\ndefaultValue=10.5.0.0/22;\n};\n\n@(IsMandatory=false, DisplayName=\"Service Level Agreement (SLA) ID Range\", Description=\"Per switch SLA ID Range (Min:1, Max: 2147483647)\", Section=\"Resources\")\nintegerRange SLA_ID_RANGE\n{\nmin=1;\nmax=2147483647;\ndefaultValue=10000-19999;\n};\n\n@(IsMandatory=false, DisplayName=\"Tracked Object ID Range\", Description=\"Per switch tracked object ID Range (Min:1, Max: 512)\", Section=\"Resources\")\nintegerRange OBJECT_TRACKING_NUMBER_RANGE\n{\nmin=1;\nmax=512;\ndefaultValue=100-299;\n};\n\n@(IsMandatory=true, Description=\"Per Switch Overlay Service Network VLAN Range (Min:2, Max:4094)\", DisplayName=\"Service Network VLAN Range\", Section=\"Resources\")\nintegerRange SERVICE_NETWORK_VLAN_RANGE\n{\nmin=2;\nmax=4094;\ndefaultValue=3000-3199;\n};\n\n@(IsMandatory=true, Description=\"(Min:1, Max:65534)\", DisplayName=\"Route Map Sequence Number Range\", Section=\"Resources\")\nintegerRange ROUTE_MAP_SEQUENCE_NUMBER_RANGE\n{\nmin=1;\nmax=65534;\ndefaultValue=1-65534;\n};\n\n@(IsMandatory=false, DisplayName=\"Inband Management\", IsShow=\"LINK_STATE_ROUTING==ospf && UNDERLAY_IS_V6==false\", Description=\"Manage switches with only Inband connectivity\", Section=\"Manageability\")\nboolean INBAND_MGMT\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean INBAND_MGMT_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, Description=\"Comma separated list of IP Addresses(v4/v6)\", DisplayName=\"DNS Server IPs\", Section=\"Manageability\")\nipAddressList DNS_SERVER_IP_LIST;\n\n@(IsMandatory=\"DNS_SERVER_IP_LIST!=null\", IsShow=\"DNS_SERVER_IP_LIST!=null\", Description=\"One VRF for all DNS servers or a comma separated<br/>list of VRFs, one per DNS server\", DisplayName=\"DNS Server VRFs\", Section=\"Manageability\")\nstring[] DNS_SERVER_VRF {\n     \n};\n\n@(IsMandatory=false, Description=\"Comma separated list of IP Addresses(v4/v6)\", DisplayName=\"NTP Server IPs\", Section=\"Manageability\")\nipAddressList NTP_SERVER_IP_LIST;\n\n@(IsMandatory=\"NTP_SERVER_IP_LIST!=null\", IsShow=\"NTP_SERVER_IP_LIST!=null\", Description=\"One VRF for all NTP servers or a comma separated<br/>list of VRFs, one per NTP server\", DisplayName=\"NTP Server VRFs\", Section=\"Manageability\")\nstring[] NTP_SERVER_VRF {\n   \n};\n\n@(IsMandatory=false, Description=\"Comma separated list of IP Addresses(v4/v6)\", DisplayName=\"Syslog Server IPs\", Section=\"Manageability\")\nipAddressList SYSLOG_SERVER_IP_LIST;\n\n@(IsMandatory=\"SYSLOG_SERVER_IP_LIST!=null\", IsShow=\"SYSLOG_SERVER_IP_LIST!=null\", Description=\"Comma separated list of Syslog severity values,<br/>one per Syslog server (Min:0, Max:7)\", DisplayName=\"Syslog Server Severity\", Section=\"Manageability\")\nstring[] SYSLOG_SEV {\n    \n};\n\n@(IsMandatory=\"SYSLOG_SERVER_IP_LIST!=null\", IsShow=\"SYSLOG_SERVER_IP_LIST!=null\", Description=\"One VRF for all Syslog servers or a comma separated<br/>list of VRFs, one per Syslog server\", DisplayName=\"Syslog Server VRFs\", Section=\"Manageability\")\nstring[] SYSLOG_SERVER_VRF {\n  \n};\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"AAA Freeform Config\", Description=\"AAA Configurations\", Section=\"Manageability\")\nstring AAA_SERVER_CONF;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Banner\", Description=\"Message of the Day (motd) banner. Delimiter char (very first char is delimiter char) followed by message ending with delimiter\", Section=\"Manageability\")\nstring BANNER;\n\n@(IsMandatory=false, NoConfigChg=true, IsDhcpFlag=true, Description=\"Automatic IP Assignment For POAP\", DisplayName=\"Enable Bootstrap\", Section=\"Bootstrap\")\nboolean BOOTSTRAP_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true, Section=\"Bootstrap\")\nboolean BOOTSTRAP_ENABLE_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"BOOTSTRAP_ENABLE==true\", Description=\"Automatic IP Assignment For POAP From Local DHCP Server\", DisplayName=\"Enable Local DHCP Server\", Section=\"Bootstrap\")\nboolean DHCP_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, NoConfigChg=true, Enum=\"DHCPv4,DHCPv6\", IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", DisplayName=\"DHCP Version\", Section=\"Bootstrap\")\nstring DHCP_IPV6_ENABLE\n{\ndefaultValue=DHCPv4;\n};\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", Description=\"Start Address For Switch POAP\", DisplayName=\"DHCP Scope Start Address\", Section=\"Bootstrap\")\nipAddress DHCP_START;\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", Description=\"End Address For Switch POAP\", DisplayName=\"DHCP Scope End Address\", Section=\"Bootstrap\")\nipAddress DHCP_END;\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", Description=\"Default Gateway For Management VRF On The Switch\", DisplayName=\"Switch Mgmt Default Gateway\", Section=\"Bootstrap\")\nipAddress MGMT_GW;\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true && DHCP_IPV6_ENABLE==DHCPv4\", Description=\"(Min:8, Max:30)\", DisplayName=\"Switch Mgmt IP Subnet Prefix\", Section=\"Bootstrap\")\ninteger MGMT_PREFIX\n{\nmin = 8;\nmax = 30;\ndefaultValue=24;\n};\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true && DHCP_IPV6_ENABLE==DHCPv6\", Description=\"(Min:64, Max:126)\", DisplayName=\"Switch Mgmt IPv6 Subnet Prefix\", Section=\"Bootstrap\")\ninteger MGMT_V6PREFIX\n{\nmin = 64;\nmax = 126;\ndefaultValue=64;\n};\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", IsMultiLineString=true, DisplayName=\"DHCPv4 Multi Subnet Scope\",  Description=\"lines with # prefix are ignored here\", Warning=\"Enter One Subnet Scope per line. <br/> Start_IP, End_IP, Gateway, Prefix <br/> e.g. <br>10.6.0.2, 10.6.0.9, 10.6.0.1, 24 <br>10.7.0.2, 10.7.0.9, 10.7.0.1, 24\", Section=\"Bootstrap\")\nstring BOOTSTRAP_MULTISUBNET\n{\ndefaultValue=#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix;\n};\n\n@(IsMandatory=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", DisplayName=\"Seed Switch Fabric Interfaces\", Description=\"Core-facing Interface list on Seed Switch (e.g. e1/1-30,e1/32)\", Section=\"Bootstrap\")\ninterfaceRange SEED_SWITCH_CORE_INTERFACES;\n\n@(IsMandatory=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", DisplayName=\"Spine Switch Fabric Interfaces\", Description=\"Core-facing Interface list on all Spines (e.g. e1/1-30,e1/32)\", Section=\"Bootstrap\")\ninterfaceRange SPINE_SWITCH_CORE_INTERFACES;\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==false\", Description=\"Comma separated list of IPv4 Addresses (Max 3)\", DisplayName=\"External DHCP Server IP Addresses\", Section=\"Bootstrap\")\nipAddressList INBAND_DHCP_SERVERS;\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\", DisplayName=\"Bootstrap Seed Switch Loopback Interface ID\", Section=\"Bootstrap\")\ninteger UNNUM_BOOTSTRAP_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=253;\n};\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\", Description=\"Must be a subset of IGP/BGP Loopback Prefix Pool\", DisplayName=\"Switch Loopback DHCP Scope <br/> Start Address\", Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_START;\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\", Description=\"Must be a subset of IGP/BGP Loopback Prefix Pool\", DisplayName=\"Switch Loopback DHCP Scope <br/> End Address\", Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_END;\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"BOOTSTRAP_ENABLE==true\", Description=\"Include AAA configs from Manageability tab during device bootup\", DisplayName=\"Enable AAA Config\", Section=\"Bootstrap\")\nboolean ENABLE_AAA{\ndefaultValue = false;\n};\n\n@(IsMandatory=false, IsShow=\"BOOTSTRAP_ENABLE==true\", IsMultiLineString=true, DisplayName=\"Bootstrap Freeform Config\", Description=\"Additional CLIs required during device bootup/login e.g. AAA/Radius\", Section=\"Bootstrap\")\nstring BOOTSTRAP_CONF;\n\n#Configuration Backup settings\n@(IsMandatory=false, NoConfigChg=true, Description=\"Backup hourly only if there is any config deployment since last backup\", DisplayName=\"Hourly Fabric Backup\", Section=\"Configuration Backup\")\nboolean enableRealTimeBackup;\n@(IsMandatory=false, NoConfigChg=true, Description=\"Backup at the specified time\", DisplayName=\"Scheduled Fabric Backup\", Section=\"Configuration Backup\")\nboolean enableScheduledBackup;\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"enableScheduledBackup==true\", Description=\"Time (UTC) in 24hr format. (00:00 to 23:59)\", DisplayName=\"Scheduled Time\", Section=\"Configuration Backup\")\nstring scheduledTime\n{\n    regularExpr=^([01]\\d|2[0-3]):([0-5]\\d)$;\n\n};\n\n# netflow is not supported for VXLANv6\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", Description=\"Enable Netflow on VTEPs\", DisplayName=\"Enable Netflow\", Section=\"Flow Monitor\")\nboolean ENABLE_NETFLOW\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ENABLE_NETFLOW_PREV;\n\n@(IsMandatory=true, IsShow=\"ENABLE_NETFLOW==true\", Description=\"One or Multiple Netflow Exporters\", DisplayName=\"Netflow Exporter\", Section=\"Flow Monitor\")\nstruct ITEM {\n  @(IsMandatory=true, DisplayName=\"Exporter Name\")\n  string EXPORTER_NAME;\n  @(IsMandatory=true, DisplayName=\"IP\")\n  ipV4Address IP;\n  @(IsMandatory=false, DisplayName=\"VRF\")\n  string VRF;\n  @(IsMandatory=true, DisplayName=\"Source Interface\")\n  interface SRC_IF_NAME;\n  @(IsMandatory=true, DisplayName=\"UDP Port\")\n  integer UDP_PORT {\n    min = 1;\n    max = 65535;\n  };\n} NETFLOW_EXPORTER_LIST[];\n\n@(IsMandatory=true, IsShow=\"ENABLE_NETFLOW==true\", Description=\"One or Multiple Netflow Records\", DisplayName=\"Netflow Record\", Section=\"Flow Monitor\")\nstruct ITEM {\n  @(IsMandatory=true, DisplayName=\"Record Name\")\n  string RECORD_NAME;\n  @(IsMandatory=true, DisplayName=\"Record Template\")\n  #@(IsMandatory=true, Enum=\"%TEMPLATES.QoS_Cloud\", DisplayName=\"Record Template\")\n  string RECORD_TEMPLATE\n  {\n    defaultValue=netflow_ipv4_record;\n  };\n  @(IsMandatory=false, DisplayName=\"Is Layer2 Record\")\n  boolean LAYER2_RECORD {\n    defaultValue=false;\n  };\n} NETFLOW_RECORD_LIST[];\n\n@(IsMandatory=true, IsShow=\"ENABLE_NETFLOW==true\", Description=\"One or Multiple Netflow Monitors\", DisplayName=\"Netflow Monitor\", Section=\"Flow Monitor\")\nstruct ITEM {\n  @(IsMandatory=true, DisplayName=\"Monitor Name\")\n  string MONITOR_NAME;\n  @(IsMandatory=true, DisplayName=\"Record Name\")\n  string RECORD_NAME;\n  @(IsMandatory=true, DisplayName=\"Exporter1 Name\")\n  string EXPORTER1;\n  @(IsMandatory=false, DisplayName=\"Exporter2 Name\")\n  string EXPORTER2;\n} NETFLOW_MONITOR_LIST[];\n\n@(IsMandatory=false, DisplayName=\"Enable Nexus Cloud\", Description=\"Allow onboarding of this fabric to Nexus Cloud\", Section=\"Nexus Cloud\")\nboolean ALLOW_NXC\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ALLOW_NXC_PREV;\n\n@(IsMandatory=false, IsShow=\"ALLOW_NXC==true\", DisplayName=\"Overwrite Global NxCloud Settings\", Description=\"If enabled, Fabric NxCloud Settings will be used\", Section=\"Nexus Cloud\")\nboolean OVERWRITE_GLOBAL_NXC\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=\"OVERWRITE_GLOBAL_NXC==true\", IsShow=\"OVERWRITE_GLOBAL_NXC==true\", DisplayName=\"Intersight Destination VRF\", Description=\"VRF to be used to reach Nexus Cloud, enter 'management' for management VRF and 'default' for default VRF\", Section=\"Nexus Cloud\")\nstring NXC_DEST_VRF\n{\nminLength = 1;\nmaxLength = 32;\ndefaultValue=management;\n};\n\n@(IsMandatory=\"OVERWRITE_GLOBAL_NXC==true && NXC_DEST_VRF!=management\", IsShow=\"OVERWRITE_GLOBAL_NXC==true && NXC_DEST_VRF!=management\", DisplayName=\"Intersight Source Interface\", Description=\"Source interface for communication to Nexus Cloud, mandatory if Destination VRF is not management, supported interfaces: loopback, port-channel, vlan\", Section=\"Nexus Cloud\")\ninterface NXC_SRC_INTF;\n\n@(IsMandatory=false, IsShow=\"OVERWRITE_GLOBAL_NXC==true\", DisplayName=\"Intersight Proxy Server\", Description=\"IPv4 or IPv6 address, or DNS name of the proxy server\", Section=\"Nexus Cloud\")\nstring NXC_PROXY_SERVER;\n\n@(IsMandatory=\"NXC_PROXY_SERVER!=null\", IsShow=\"NXC_PROXY_SERVER!=null\", DisplayName=\"Proxy Server Port\", Description=\"Proxy port number, default is 8080\", Section=\"Nexus Cloud\")\ninteger NXC_PROXY_PORT\n{\nmin = 1;\nmax = 65535;\ndefaultValue = 8080;\n};\n\n@(IsMandatory=true, Description=\"vPC Delay Restore Time For vPC links in seconds (Min:1, Max:3600)\", DisplayName=\"vPC Delay Restore Time\", Section=\"Hidden\")\ninteger VPC_DELAY_RESTORE_TIME\n{\nmin = 1;\nmax = 3600;\ndefaultValue=60;\n};\n\n#Hidden\n@(IsMandatory=true, IsFabricType=true, DisplayName=\"Fabric Type\", ReadOnly=true, Section=\"Hidden\")\nstring FABRIC_TYPE\n{\ndefaultValue=Switch_Fabric;\n};\n\n@(IsMandatory=false, Section=\"Hidden\")\nstring EXT_FABRIC_TYPE;\n\n@(IsMandatory=false, Description=\"Enable Agnet (developmet purpose only)\", DisplayName=\"Enable Agent\", Section=\"Hidden\")\nboolean ENABLE_AGENT\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, Description=\"Interface to connect to Agent\", DisplayName=\"Agent Interface\", Enum=\"eth0,eth1\", Section=\"Hidden\")\nstring AGENT_INTF\n{\ndefaultValue=eth0;\n};\n\n@(IsMandatory=true,Enum=\"Enable,Disable\", Description=\"Allow First Super Spine Add or Last Super Spine Delete From Topology\", DisplayName=\"Super Spine Force Add Del\", Section=\"Hidden\")\nstring SSPINE_ADD_DEL_DEBUG_FLAG\n{\ndefaultValue=Disable;\n};\n\n@(IsMandatory=false, Enum=\"Enable,Disable\", Description=\"Dont' use until you are aware about it\", DisplayName=\"!!! Only for brf debugging purpose !!!\", Section=\"Hidden\")\nstring BRFIELD_DEBUG_FLAG\n{\ndefaultValue=Disable;\n};\n\n@(IsMandatory=true, DisplayName=\"Active Migration\", Section=\"Hidden\")\nboolean ACTIVE_MIGRATION\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, DisplayName=\"Template Family\", Section=\"Hidden\")\nstring FF\n{\ndefaultValue=Easy_Fabric;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring MSO_SITE_ID;\n@(IsMandatory=false, IsInternal=true)\nstring MSO_CONTROLER_ID;\n@(IsMandatory=false, IsInternal=true)\nstring MSO_SITE_GROUP_NAME;\n@(IsMandatory=false, IsInternal=true)\nstring PREMSO_PARENT_FABRIC;\n@(IsMandatory=false, IsInternal=true)\nstring MSO_CONNECTIVITY_DEPLOYED;\n\n@(IsMandatory=false, Section=\"Hidden\")\nipV4AddressWithSubnet ANYCAST_RP_IP_RANGE_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress DHCP_START_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress DHCP_END_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress MGMT_GW_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\ninteger MGMT_PREFIX_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nstring BOOTSTRAP_MULTISUBNET_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\ninteger MGMT_V6PREFIX_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nstring DHCP_IPV6_ENABLE_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_START_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_END_INTERNAL;\n\n@(IsMandatory=true, IsInternal=true)\nboolean ENABLE_EVPN\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=true, IsInternal=true)\nboolean FEATURE_PTP_INTERNAL\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger SSPINE_COUNT\n{\ndefaultValue=0;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger SPINE_COUNT\n{\ndefaultValue=0;\n};\n\n#All policy templates starts from here.\n@(IsMandatory=true, Enum=\"base_feature_leaf_upg\", Description=\"Feature Configuration for Leaf\", DisplayName=\"base_feature_leaf\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_feature_leaf {\ndefaultValue=base_feature_leaf_upg;\n};\n\n@(IsMandatory=true, Enum=\"base_feature_spine_upg\", Description=\"Feature Configuration for Spine\", DisplayName=\"base_feature_spine\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_feature_spine {\ndefaultValue=base_feature_spine_upg;\n};\n\n@(IsMandatory=true, Enum=\"base_dhcp\", Description=\"DHCP Configuration\", DisplayName=\"base_dhcp\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_dhcp\n{\ndefaultValue=base_dhcp;\n};\n\n@(IsMandatory=true, Enum=\"base_multicast_11_1\", Description=\"Multicast Configuration\", DisplayName=\"base_multicast\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_multicast\n{\ndefaultValue=base_multicast_11_1;\n};\n\n@(IsMandatory=true, Enum=\"anycast_rp\", Description=\"Anycast RP Configuration\", DisplayName=\"anycast_rp\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_anycast_rp\n{\ndefaultValue=anycast_rp;\n};\n\n@(IsMandatory=true, Enum=\"int_fabric_loopback_11_1\", Description=\"Primary Loopback Interface Configuration\", DisplayName=\"loopback_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_loopback_interface\n{\ndefaultValue=int_fabric_loopback_11_1;\n};\n\n@(IsMandatory=true, Enum=\"base_isis_level2\", Description=\"ISIS Network Configuration\", DisplayName=\"base_isis_level2\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_isis\n{\ndefaultValue=base_isis_level2;\n};\n\n@(IsMandatory=true, Enum=\"base_ospf\", Description=\"OSPF Network Configuration\", DisplayName=\"base_ospf\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_ospf\n{\ndefaultValue=base_ospf;\n};\n\n@(IsMandatory=true, Enum=\"base_vpc_domain_11_1\", Description=\"vPC Domain Configuration\", DisplayName=\"base_vpc_domain\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_vpc_domain\n{\ndefaultValue=base_vpc_domain_11_1;\n};\n\n@(IsMandatory=true, Enum=\"int_fabric_vlan_11_1\", Description=\"VLAN Interface Configuration\", DisplayName=\"vlan_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_vlan_interface\n{\ndefaultValue=int_fabric_vlan_11_1;\n};\n\n@(IsMandatory=true, Enum=\"isis_interface\", Description=\"ISIS Interface Configuration\", DisplayName=\"isis_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_isis_interface\n{\ndefaultValue=isis_interface;\n};\n\n@(IsMandatory=true, Enum=\"ospf_interface\", Description=\"OSPF Interface Configuration\", DisplayName=\"ospf_interface_11_1\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_ospf_interface\n{\ndefaultValue=ospf_interface_11_1;\n};\n\n@(IsMandatory=true, Enum=\"pim_interface\", Description=\"PIM Interface Configuration\", DisplayName=\"pim_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_pim_interface\n{\ndefaultValue=pim_interface;\n};\n\n@(IsMandatory=true, Enum=\"route_map\", Description=\"Route-Map Configuration\", DisplayName=\"abstract_route_map\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_route_map\n{\ndefaultValue=route_map;\n};\n\n@(IsMandatory=true, Enum=\"base_bgp\", Description=\"BGP Configuration\", DisplayName=\"base_bgp\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_bgp\n{\ndefaultValue=base_bgp;\n};\n\n@(IsMandatory=true, Enum=\"evpn_bgp_rr\", Description=\"BGP RR Configuration\", DisplayName=\"evpn_bgp_rr\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_bgp_rr\n{\ndefaultValue=evpn_bgp_rr;\n};\n\n@(IsMandatory=true, Enum= \"evpn_bgp_rr_neighbor\", Description=\"BGP Neighbor Configuration\", DisplayName=\"evpn_bgp_rr_neighbor\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_bgp_neighbor\n{\ndefaultValue=evpn_bgp_rr_neighbor;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_leaf\", Description=\"Add Extra Configuration for Leaf\", DisplayName=\"extra_config_leaf\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_leaf\n{\ndefaultValue=extra_config_leaf;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_spine\", Description=\"Add Extra Configuration for Spine\", DisplayName=\"extra_config_spine\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_spine\n{\ndefaultValue=extra_config_spine;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_tor\", Description=\"Add Extra Configuration for ToR\", DisplayName=\"extra_config_tor\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_tor\n{\ndefaultValue=extra_config_tor;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_bootstrap\", Description=\"Add Extra Configuration for Bootstrap\", DisplayName=\"extra_config_bootstrap\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_bootstrap\n{\ndefaultValue=extra_config_bootstrap_11_1;\n};\n\n@(IsMandatory=true, Enum=\"anycast_gateway\", Description=\"Anycast Gateway MAC Configuration\", DisplayName=\"anycast_gateway\", Section=\"Policy Templates\", IsInternal=true)\nstring temp_anycast_gateway\n{\ndefaultValue=anycast_gateway;\n};\n\n@(IsMandatory=true, Enum=\"vpc_domain_mgmt\", Description=\"vPC Keep-alive Configuration using Management VRF\", DisplayName=\"vpc_domain_mgmt\", Section=\"Policy Templates\", IsInternal=true)\nstring temp_vpc_domain_mgmt\n{\ndefaultValue=vpc_domain_mgmt;\n};\n\n@(IsMandatory=true, Enum=\"vpc_peer_link\", Description=\"vPC Peer-Link Configuration\", DisplayName=\"vpc_peer_link\", Section=\"Policy Templates\", IsInternal=true)\nstring temp_vpc_peer_link\n{\ndefaultValue=int_vpc_peer_link_po;\n};\n\n@(IsMandatory=true, Enum=\"int_routed_host\", Description=\"Routed Host Port Configuration\", DisplayName=\"routed_host\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_routed_host\n{\ndefaultValue=int_routed_host;\n};\n\n@(IsMandatory=true, Enum=\"int_trunk_host\", Description=\"trunk Host Port Configuration\", DisplayName=\"trunk_host\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_trunk_host\n{\ndefaultValue=int_trunk_host;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring UPGRADE_FROM_VERSION;\n\n@(IsMandatory=false, IsInternal=true)\nstring TOPDOWN_CONFIG_RM_TRACKING;\n\n\n##\n##template content\n\nfrom com.cisco.dcbu.vinci.rest.services.jython import *\nfrom com.cisco.dcbu.vinci.rest.services.jython import ResourceManagerWrapper as RM\nfrom com.cisco.dcbu.vinci.rest.services.jython import PTIWrapper as PTI\nfrom com.cisco.dcbu.vinci.rest.services.jython import InterfaceManagerWrapper as IM\nfrom com.cisco.dcbu.vinci.rest.services.jython import BackupRestoreWrapper as BRW\nfrom com.cisco.dcbu.vinci.rest.services.jython import ConfigDeployerWrapper as CDW\nfrom com.cisco.dcbu.vinci.rest.services.jython import ElasticServiceWrapper\nfrom com.cisco.dcbu.vinci.rest.services.jython import InterfaceTypeEnum\nfrom com.cisco.dcbu.topdown.dao import CommonDAO\nfrom com.cisco.dcbu.vinci.rest.services.jython import InterfabricConnectionWrapper\nfrom com.cisco.dcbu.tor.service import ToRWrapper\nfrom com.cisco.dcbu.jython.resource import Category\nfrom com.cisco.dcbu.jython.resource import EntityType as ET\nfrom com.cisco.dcbu.easy.util.jython.impl import FabricErrorLogger\n\nfrom topology import *\nfrom utility import *\n\nimport sys, traceback\nimport re\nimport json\nimport copy\n\ndef isValidOspfAreaIdIPString(ipStr):\n    ip = re.findall( r'''^[0-9]+(?:\\.[0-9]+){3}$''', ipStr)\n    isValid = True\n    if len(ip) == 1:\n        # convert string to ints\n        ipInts = map(int, ip[0].split('.'))\n        for ipInt in ipInts:\n            if not ((ipInt >= 0) and (ipInt <= 255)):\n                isValid = False\n                break\n    else:\n        # not a valid IP address string\n        isValid = False\n    Wrapper.print(\"isValidOspfAreaIdIPString: FAB [%s]: OSPF Area Id IP String [%s]  isValid [%r]\" % (FABRIC_NAME, ipStr, isValid))\n    return isValid\n\ndef isValidBrownfieldNetworkFormat(netName):\n    # name format is valid if the following rules are satisfied\n    #   - must contain $$VNI$$\n    #   - must not contain any other $$var$$\n    #   - parts must not have any special chars besides '_' and '-' (Overlay network name restrictions)\n    failureReason = None\n    Wrapper.print(\"isValidBrownfieldNetworkFormat: netName [%s]\" % (netName))\n\n    if (\"$$VNI$$\" not in netName):\n        failureReason = \"Missing mandatory $$VNI$$ keyword\"\n        return failureReason\n\n    specialCharChecker = re.compile(r'[^A-za-z0-9_-]')\n    parts = re.split(r'(\\$\\$[^$]+\\$\\$)', netName)\n    #Wrapper.print(\"isValidBrownfieldNetworkFormat: parts [%s]\" % (parts))\n    for part in parts:\n        if not part or (part == \"\"):\n            continue\n        if ((part.startswith('$$') and (part.endswith('$$')))):\n            #   - must not contain any other $$var$$\n            if ((part != '$$VNI$$') and (part != '$$VLAN_ID$$')):\n                failureReason = (\"Invalid keyword in [%s]\" % part)\n                break\n        else:\n            #   - parts must not have any special chars besides '_' and '-' (Overlay network name restrictions)\n            if specialCharChecker.search(part):\n                failureReason = (\"Invalid charater in [%s]\" % part)\n                break\n\n    return failureReason\n\n# returns True if change is allowed\ndef checkFabricMtuSettings(respObj):\n    retCode = True\n\n    Wrapper.print(\"checkFabricMtuSettings: FAB [%s]: Intra Fabric interface MTU [%s] -> [%s]\" %\n                (FABRIC_NAME, FABRIC_MTU_PREV, FABRIC_MTU))\n    # ensure the MTU value is an even number\n    if (int(FABRIC_MTU) % 2) != 0:\n        # cannot allow this change\n        respObj.addErrorReport(\"fabricInit\", \"Intra Fabric interface MTU [%s] must be an even number.\" % (FABRIC_MTU))\n        respObj.setFailureRetCode()\n        retCode = False\n\n    Wrapper.print(\"checkFabricMtuSettings: FAB [%s]: Layer 2 Host interface MTU [%s] -> [%s]\" %\n                (FABRIC_NAME, L2_HOST_INTF_MTU_PREV, L2_HOST_INTF_MTU))\n    # ensure the MTU value is an even number\n    if (int(L2_HOST_INTF_MTU) % 2) != 0:\n        # cannot allow this change\n        respObj.addErrorReport(\"fabricInit\", \"Layer 2 Host interface MTU [%s] must be an even number.\" % (L2_HOST_INTF_MTU))\n        respObj.setFailureRetCode()\n        retCode = False\n\n    return retCode\n\n# returns True if change is allowed\ndef checkBgpAsChange(respObj):\n    Wrapper.print(\"checkBgpAsChange: FAB [%s]: [%s] -> [%s]\" % (FABRIC_NAME, BGP_AS_PREV, BGP_AS))\n    if (BGP_AS_PREV != BGP_AS):\n        try:\n            getRespObj = FabricWrapper.getParentFabricName(FABRIC_NAME)\n            if getRespObj.isRetCodeSuccess():\n                # It is a member of MSD. Do not allow BGP AS change\n                respObj.addErrorReport(\"fabricInit\",\n                    \"BGP ASN cannot be changed from [%s] to [%s] on a MSD member fabric.\" % (BGP_AS_PREV, BGP_AS))\n                respObj.setFailureRetCode()\n                return False\n        except:\n            Wrapper.print(\"exception, ignore if not member fabric\")\n            pass\n\n        overlayPresent = Util.exe(Helper.isOverlayExist(FABRIC_NAME))\n        if overlayPresent:\n            # cannot allow this change\n            respObj.addErrorReport(\"fabricInit\",\n                \"BGP ASN cannot be changed from [%s] to [%s] with existing overlays.\" % (BGP_AS_PREV, BGP_AS))\n            respObj.setFailureRetCode()\n            return False\n\n        # update the prev value\n        FabricWrapper.update(FABRIC_NAME, \"BGP_AS_PREV\", BGP_AS)\n    return True\n\n# returns True if change is allowed\ndef checkLinkProtocolTagChange(respObj):\n    Wrapper.print(\"checkLinkProtocolTagChange: FAB [%s]: [%s] -> [%s]\" % (FABRIC_NAME, LINK_STATE_ROUTING_TAG_PREV, LINK_STATE_ROUTING_TAG))\n    if (LINK_STATE_ROUTING_TAG_PREV != LINK_STATE_ROUTING_TAG):\n        overlayPresent = Util.exe(Helper.isOverlayExist(FABRIC_NAME))\n        if overlayPresent:\n            # cannot allow this change\n            respObj.addErrorReport(\"fabricInit\",\n                \"Link-State Routing Protocol Tag cannot be changed from [%s] to [%s] with existing overlays.\" %\n                (LINK_STATE_ROUTING_TAG_PREV, LINK_STATE_ROUTING_TAG))\n            respObj.setFailureRetCode()\n            return False\n\n        # update the prev value\n        FabricWrapper.update(FABRIC_NAME, \"LINK_STATE_ROUTING_TAG_PREV\", LINK_STATE_ROUTING_TAG)\n    return True\n\n# returns True if change is allowed\ndef checkOverlayModeChange(respObj):\n    Wrapper.print(\"checkOverlayModeChange: FAB [%s]: [%s] -> [%s]\" % (FABRIC_NAME, OVERLAY_MODE_PREV, OVERLAY_MODE))\n    if (OVERLAY_MODE_PREV != \"\" and OVERLAY_MODE_PREV != OVERLAY_MODE):\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n        overlayConfigPresent = False\n        for deviceSn in devices:\n            if not CommonDAO.areOverlaysPresent(deviceSn):\n                overlayConfigPresent = True\n                break\n\n        if overlayConfigPresent:\n            # cannot allow this change\n            respObj.addErrorReport(\"fabricInit\",\n                \"Overlay Mode cannot be changed from [%s] to [%s] with overlay configurations \"\n                \"already applied on switches.\" % (OVERLAY_MODE_PREV, OVERLAY_MODE))\n            respObj.setFailureRetCode()\n            return False\n\n    # update the prev value\n    FabricWrapper.update(FABRIC_NAME, \"OVERLAY_MODE_PREV\", OVERLAY_MODE)\n    return True\n\ndef macSecSanityCheck(respObj):\n    if ENABLE_MACSEC == \"false\":\n        return True\n\n    foundErr = False\n    if MACSEC_ALGORITHM == \"AES_128_CMAC\" and len(MACSEC_KEY_STRING) != 66:\n        errorMsg = \"MACsec primary key string length must be 66 with AES_128_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck: %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if MACSEC_ALGORITHM == \"AES_256_CMAC\" and len(MACSEC_KEY_STRING) != 130:\n        errorMsg = \"MACsec primary key string length must be 130 with AES_256_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if MACSEC_FALLBACK_ALGORITHM == \"AES_128_CMAC\" and len(MACSEC_FALLBACK_KEY_STRING) != 66:\n        errorMsg = \"MACsec fallback key string length must be 66 with AES_128_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck: %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if MACSEC_FALLBACK_ALGORITHM == \"AES_256_CMAC\" and len(MACSEC_FALLBACK_KEY_STRING) != 130:\n        errorMsg = \"MACsec fallback key string length must be 130 with AES_256_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if foundErr:\n        respObj.setFailureRetCode()\n        return False\n    else:\n        return True\n\ndef checkFabricVpcDomainId(respObj):\n    global ENABLE_FABRIC_VPC_DOMAIN_ID, ENABLE_FABRIC_VPC_DOMAIN_ID_PREV, FABRIC_VPC_DOMAIN_ID, FABRIC_VPC_DOMAIN_ID_PREV\n\n    # check for any changes to the vpc domain id settings\n    vpcDomainEnableSettingChanged = False\n    if (ENABLE_FABRIC_VPC_DOMAIN_ID != ENABLE_FABRIC_VPC_DOMAIN_ID_PREV):\n        vpcDomainEnableSettingChanged = True\n\n    vpcDomainIdSettingChanged = False\n    if ENABLE_FABRIC_VPC_DOMAIN_ID == \"true\":\n        if FABRIC_VPC_DOMAIN_ID != FABRIC_VPC_DOMAIN_ID_PREV:\n            vpcDomainIdSettingChanged = True\n    Wrapper.print(\"checkFabricVpcDomainId: vpc domain Enable [%s] -> [%s] [%r], Domain id [%s] -> [%s] [%r]\" % \n        (ENABLE_FABRIC_VPC_DOMAIN_ID_PREV, ENABLE_FABRIC_VPC_DOMAIN_ID, vpcDomainEnableSettingChanged,\n            FABRIC_VPC_DOMAIN_ID_PREV, FABRIC_VPC_DOMAIN_ID, vpcDomainIdSettingChanged))\n\n    if vpcDomainEnableSettingChanged or vpcDomainIdSettingChanged:\n        # do not allow the change if there are existing VPC pairs\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n        for deviceSn in devices:\n            isVPC = Util.exe(VpcWrapper.isVpc(FABRIC_NAME, deviceSn))\n            if isVPC:\n                if vpcDomainEnableSettingChanged:\n                    errStr = (\"Fabric wide vPC Domain ID Enable setting cannot be changed from [%s] to [%s] with existing vPC pairs.\" %\n                        (ENABLE_FABRIC_VPC_DOMAIN_ID_PREV, ENABLE_FABRIC_VPC_DOMAIN_ID))\n                else:\n                    errStr = (\"Fabric wide vPC Domain ID cannot be changed from [%s] to [%s] with existing vPC pairs.\" %\n                        (FABRIC_VPC_DOMAIN_ID_PREV, FABRIC_VPC_DOMAIN_ID))\n\n                respObj.addErrorReport(\"fabricInit\",errStr)\n                respObj.setFailureRetCode()\n                return False\n\n        # the vpc domain id is ok to change\n        ENABLE_FABRIC_VPC_DOMAIN_ID_PREV = ENABLE_FABRIC_VPC_DOMAIN_ID\n        Util.exe(FabricWrapper.update(FABRIC_NAME, \"ENABLE_FABRIC_VPC_DOMAIN_ID_PREV\", ENABLE_FABRIC_VPC_DOMAIN_ID_PREV))\n        FABRIC_VPC_DOMAIN_ID_PREV = FABRIC_VPC_DOMAIN_ID\n        Util.exe(FabricWrapper.update(FABRIC_NAME, \"FABRIC_VPC_DOMAIN_ID_PREV\", FABRIC_VPC_DOMAIN_ID_PREV))\n    return True\n\ndef putSwitchIntoMgmtModeMigrMode(fabricName, devSerial):\n    formattedName = getFormattedSwitchName(devSerial)\n    Wrapper.print(\"=======ACTION: FAB [%s]. Put switch [%s] into mgmt mode migration mode\" % (fabricName, formattedName))\n    ptis = Util.exe(PTIWrapper.get(devSerial, \"SWITCH\", \"SWITCH\",\"\", \"switch_migration_state\"))\n    for pti in ptis:\n        nvPairs = pti.getNvPairs()\n        if nvPairs:\n            Wrapper.print(\"putSwitchIntoOverlayMigrMode: Switch [%s] Migration [%s] NvPair = [%s]\" % \n                                    (devSerial, formattedName, nvPairs))\n            newNvPairs = copy.deepcopy(nvPairs)\n            newNvPairs[\"OVERLAY\"] = \"true\"\n            Util.exe(PTIWrapper.createOrUpdate(devSerial, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_migration_state\", newNvPairs))\n        break\n\ndef checkInbandMgmtSettings(fabricSettings, respObj):\n    funcName = sys._getframe(0).f_code.co_name\n\n    inbandMgmtEnable = True if (fabricSettings.get(\"INBAND_MGMT\", \"false\") == \"true\") else False\n    inbandMgmtEnablePrev = True if (fabricSettings.get(\"INBAND_MGMT_PREV\", \"false\") == \"true\") else False\n    bootstrapPOAPEnable = fabricSettings.get(\"BOOTSTRAP_ENABLE\", \"false\")\n    bootstrapPOAPEnablePrev = fabricSettings.get(\"BOOTSTRAP_ENABLE_PREV\", \"false\")\n    inbandPOAPEnable = True if (inbandMgmtEnable and bootstrapPOAPEnable == \"true\") else False\n    inbandPOAPEnablePrev = True if (inbandMgmtEnablePrev and bootstrapPOAPEnablePrev == \"true\") else False\n    dhcpEnable = fabricSettings.get(\"DHCP_ENABLE\", \"false\")        \n    tenantDhcpEnable = fabricSettings.get(\"ENABLE_TENANT_DHCP\", \"true\")        \n    underlayIsV6 = fabricSettings.get(\"UNDERLAY_IS_V6\", \"false\")        \n    routingProto = fabricSettings.get(\"LINK_STATE_ROUTING\", \"ospf\")        \n    fabIntfType = fabricSettings.get(\"FABRIC_INTERFACE_TYPE\", \"p2p\")\n\n    Wrapper.print(\"%s: inbandMgmtEnable [%r] inbandMgmtEnablePrev [%r] bootstrapPOAPEnable[%s] bootstrapPOAPEnablePrev[%s] \"\n      \"inbandPOAPEnable [%r] inbandPOAPEnablePrev [%r] DHCP[%s] \"\n      \"v6 [%s] Routing Prococol [%s]\" % (funcName, inbandMgmtEnable, inbandMgmtEnablePrev, bootstrapPOAPEnable, bootstrapPOAPEnablePrev,\n        inbandPOAPEnable, inbandPOAPEnablePrev, dhcpEnable, underlayIsV6, routingProto))\n    \n    # Disallow Inband Management for the following:\n    #  - v6 Underlay\n    #  - not OSPF Underlay Routing Protocol\n    if inbandMgmtEnable and (underlayIsV6 == \"true\" or routingProto != \"ospf\"):\n        respObj.addErrorReport(funcName, \"Inband Management is supported only with IPv4 underlay and routing protocol as \"\n          \"OSPF. Please update Fabric Settings and retry\")\n        respObj.setFailureRetCode()\n        return\n\n    if inbandPOAPEnable:\n        if tenantDhcpEnable != \"true\":\n          #Tenant DHCP knob must be enabled if inband POAP is enabled\n          respObj.addErrorReport(funcName, \"Tenant DHCP cannot be disabled if Inband POAP is enabled\")\n          respObj.setFailureRetCode()\n          return\n\n        if dhcpEnable == \"false\":\n            # check the following for External DHCP Servers:\n            #   - only 3 servers are allowed\n            #   - IPv4 only\n            settingName = \"External DHCP Server IP Addresses\"\n            inbandDhcpServersSettting = fabricSettings.get(\"INBAND_DHCP_SERVERS\", \"\")\n            inbandDhcpServersList = [eachIP.strip() for eachIP in inbandDhcpServersSettting.split(',')]\n            errMsg = None\n            if len(inbandDhcpServersList) > 3:\n                errMsg = \"Please configure a maximum of 3 (three) %s.\" % (settingName)\n            else:              \n                for ip in inbandDhcpServersList:\n                    if \":\" in ip:\n                        # v6 address is not allowed\n                        errMsg = \"%s must be valid IPv4 addresses.\" % (settingName)\n                        break\n\n            if errMsg is not None:\n                respObj.addErrorReport(\"fabricInit:InbandDhcpServers\", errMsg)\n                respObj.setFailureRetCode()\n                return\n\n    if inbandMgmtEnable != inbandMgmtEnablePrev:\n        if inbandMgmtEnable:\n            # make sure the NDFC device management setting is 'Data'\n            ndfcSNMPInfo = json.loads(Util.exe(FabricWrapper.getSNMPTrapInfo()))\n            ndfcDevMgmtMode = ndfcSNMPInfo.get(\"global.oob_network_mode\", \"\").lower()\n            mgmtModeIsData = True if ndfcDevMgmtMode == \"data\" else False\n            if not mgmtModeIsData:\n                respObj.addErrorReport(funcName, \"Inband Management is supported with 'LAN Device Management Connectivity' \"\n                  \"Server Setting set to 'Data' only. Please update the setting and retry the management mode change.\")\n                respObj.setFailureRetCode()\n                return respObj\n\n        supportedSwitchRoles = [\"leaf\", \"spine\", \"border\", \"broder spine\", \"border gateway\", \"border gateway spine\"]\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = filter(None, (topologyDataObj.get(TopologyInfoType.SWITCHES)))  # all devices serial number\n        for devSerial in devices:\n            # make sure the switches are not in migration mode for some other reason\n            ptiList = Util.exe(PTIWrapper.get(devSerial, \"SWITCH\", \"SWITCH\", \"\", \"switch_migration_state\"))\n            for pti in ptiList:\n                # switch already in migration mode.. check further and report erorr as needed\n                if pti.isDeleted():\n                    continue\n                if (pti.getNvPairs().get(\"TARGET_MGMT_MODE\", None) is None):\n                    # switch is in some other migration mode.. report error\n                    respObj.addErrorReport(funcName, \"Switch is already in migration mode. Please complete associated \"\n                      \"action and retry the management mode change.\", devSerial)\n                    respObj.setFailureRetCode()\n                    continue\n\n            if inbandMgmtEnable:\n                # make sure the switch role is supported for Inband Mgmt\n                switchRole = topologyDataObj.getSwitchRole(devSerial)\n                if (switchRole.lower() not in supportedSwitchRoles):\n                    respObj.addErrorReport(funcName, \"Role [%s] is not supported for Inband Management.\" % (switchRole), devSerial)\n                    respObj.setFailureRetCode()\n                    continue\n\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        # do the following checks for the target mgmt mode before putting switches into migration mode\n        # OOB:\n        #   - mgmt0 intent must be present with a valid IP\n        # Inband\n        #   - bgp routing lo intf must be present with a valid IP\n        #\n        # target IP address must be pingable\n        for devSerial in devices:\n            targetMode = (\"Inband\" if inbandMgmtEnable else \"OOB\")\n\n            Wrapper.print(\"%s: Switch [%s] Target Mgmt Mode [%s]\" % (funcName, devSerial, targetMode))\n            newDiscIP = None\n            newDiscIntf = None\n            intfTmplName = None\n            if targetMode == \"OOB\":\n                newDiscIntf = \"mgmt0\"\n                intfTmplName = \"int_mgmt\"\n            else:\n                newDiscIntf = \"loopback\" + fabricSettings.get(\"BGP_LB_ID\", \"0\")\n                intfTmplName = \"int_fabric_loopback_11_1\"\n\n            intfPti = None\n            srchOpt = CtrlPolicySearch()\n            srchOpt.setSerialNumber(devSerial)\n            srchOpt.setEntityName(newDiscIntf)\n            srchOpt.setTemplateName(intfTmplName)\n            srchOpt.setTemplateContentType(\"PYTHON\")\n            intfPtis = Util.exe(PTIWrapper.getPTIs(srchOpt))\n            for pti in intfPtis:\n                if pti.isDeleted():\n                    continue\n                intfPti = pti\n                break\n\n            if intfPti is None:\n                respObj.addErrorReport(getFabErrEntity(funcName, devSerial+\":DiscoveryIPChange\"),\n                               \"Interface policy for interface [%s] not found. \"\n                               \"Please double check and retry Recalculate & Deploy\" % (newDiscIntf), devSerial)\n                respObj.setFailureRetCode()\n                continue\n\n            if targetMode == \"OOB\":\n                #   - make sure the mgmt0 intf intent is present to get the mgmt0 IP address\n                intfFF = intfPti.getNvPairs().get(\"CONF\", None)\n                for line in intfFF.split(Util.newLine()):\n                    stripLine = line.strip()\n                    if stripLine.startswith(\"ip address \"):\n                        parts = stripLine.split(\" \")\n                        newDiscIP = parts[2].split(\"/\")[0]\n                        break\n            else:\n                #   - make sure the lo0 intf intent is present to get the IP address\n                newDiscIP = intfPti.getNvPairs().get(\"IP\", None)\n\n            if newDiscIP is None:\n                respObj.addErrorReport(getFabErrEntity(funcName, devSerial+\":DiscoveryIPChange\"),\n                     \"IP address for interface [%s] not found. \"\n                     \"Please double check and retry changing the 'Inband Management' fabric settings.\" % (newDiscIntf), devSerial)\n                respObj.setFailureRetCode()\n                continue\n\n            # make sure the target IP is pingable\n            # cmd = \"ping -i .5 -c 2 -t 2 -W 2 \" + newDiscIP\n            # Wrapper.print(\"%s: IP rechability check with [%s]\"%(funcName, cmd))\n\n            # response = os.system(cmd)\n            # if response != 0:\n            #     respObj.addErrorReport(getFabErrEntity(funcName, devSerial+\":DiscoveryIPChange\"),\n            #          \"IP address [%s] for interface [%s] is not reachable. \"\n            #          \"Please double check and retry changing the 'Inband Management' fabric settings.\" % (newDiscIP, newDiscIntf), devSerial)\n            #     respObj.setFailureRetCode()\n            #     return respObj\n\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        # pre-conditions are met.. put switches in migration mode to allow the OOB <--> Inband mgmt change\n        for devSerial in devices:\n            ptiList = Util.exe(PTIWrapper.get(devSerial, \"SWITCH\", \"SWITCH\", \"\", \"switch_migration_state\"))\n            for pti in ptiList:\n                PTIWrapper.deleteInstance(pti.getPolicyId());\n            nvPairs = {\"TARGET_MGMT_MODE\" : \"Inband\" if inbandMgmtEnable else \"OOB\"}\n            Util.exe(PTIWrapper.create(devSerial, \"SWITCH\", \"SWITCH\", \"\", 10,\n                                  \"switch_migration_state\", nvPairs, \"Management mode change\"))\n        \ndef preUpgrade(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: preUpgrade\" % (FABRIC_NAME))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        upgFromVer = dictionaryObj.get(\"UPGRADE_FROM\", \"\")\n        Wrapper.print(\"==========preUpgrade: Fabric Name = %s, keys = %d, UPGRADE_FROM = [%s]\" %\n                (FABRIC_NAME, len(dictionaryObj), upgFromVer))\n        dictionaryObj[\"FABRIC_NAME\"] = FABRIC_NAME\n        respObj = Util.exe(PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dictionaryObj, \"preUpgradeExt\"))\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preUpgrade: Success = [%r]\" %\n                (FABRIC_NAME, respObj.isRetCodeSuccess()))\n        return respObj\n\ndef isInbandPoapEnabled(dictObj):\n    inbandMgmt = dictObj.get(\"INBAND_MGMT\", \"false\")\n    bootstrapPOAPEnable = dictObj.get(\"BOOTSTRAP_ENABLE\", \"false\")\n    return (\"true\" if (inbandMgmt == \"true\" and bootstrapPOAPEnable == \"true\") else \"false\")\n\ndef fabricInit(dictionaryObj):\n    global FABRIC_INTERFACE_TYPE, REPLICATION_MODE, FEATURE_PTP, VPC_DOMAIN_ID_RANGE, SITE_ID, BANNER\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n\n    try:\n        Util.exe(actionAllow())\n\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        fabricSettings[\"FABRIC_TYPE\"] = \"Switch_Fabric\"\n\n        inbandMgmt = fabricSettings.get(\"INBAND_MGMT\", \"false\")\n        bootstrapPOAPEnable = fabricSettings.get(\"BOOTSTRAP_ENABLE\", \"false\")\n        bootstrapPOAPEnablePrev = fabricSettings.get(\"BOOTSTRAP_ENABLE_PREV\", \"false\")\n        inbandPOAPEnable = \"true\" if (inbandMgmt == \"true\" and bootstrapPOAPEnable == \"true\") else \"false\"\n\n        checkInbandMgmtSettings(fabricSettings, respObj)\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        failStr = isValidBrownfieldNetworkFormat(BROWNFIELD_NETWORK_NAME_FORMAT)\n        if failStr:\n            respObj.addErrorReport(funcName,\n                \"The network name format [%s] used for Brownfield import is invalid. Reason - %s. Please refer to the documentation for additional information.\" %\n                (BROWNFIELD_NETWORK_NAME_FORMAT, failStr))\n            respObj.setFailureRetCode()\n            return respObj\n\n        # check the fabric wide links extra config\n        errCmd, adjFabricExtraLinkCfg = Util.getAdjustedIntfFreeformConfig(EXTRA_CONF_INTRA_LINKS)\n        if errCmd != \"\":\n            respObj.addErrorReport(funcName,\n                \"The Intra fabric link interface freeform extra configuration must not contain the \\'interface\\' keyword. Please remove the command %s\" %\n                (errCmd))\n            respObj.setFailureRetCode()\n            return respObj\n\n        # validate the OSPF Area ID\n        if OSPF_AREA_ID != \"\":\n            if not Util.isValidOspfAreaIdIPString(OSPF_AREA_ID):\n               respObj.addErrorReport(funcName,\n                \"[%s] - Invalid OSPF Area ID IP String. Please make sure the IP address is valid and contains no white spaces.\" % OSPF_AREA_ID)\n               respObj.setFailureRetCode()\n               return respObj\n\n        # validate ANYCAST_GW_MAC\n        agw_mac = Util.normalizeMac(ANYCAST_GW_MAC)\n        if int(agw_mac[0:2], 16) & 0x01 != 0:\n            respObj.addErrorReport(funcName, \"Anycast Gateway MAC needs to be unicast mac address. \")\n            respObj.setFailureRetCode()\n            return respObj\n\n        pmEnable = fabricSettings.get(\"PM_ENABLE\", \"false\")\n        pmEnablePrev = fabricSettings.get(\"PM_ENABLE_PREV\", \"false\")\n        if pmEnable != pmEnablePrev:\n            turnOnPM = True if pmEnable == \"true\" else False\n            isFeatEnabled = Util.exe(FabricWrapper.isFeatureEnabled(\"pm\"))\n            if isFeatEnabled:\n                FabricWrapper.enOrDisFabricPM(FABRIC_NAME, turnOnPM)\n            else:\n                pmForceUpd = \"false\" if fabricSettings.get(\"PM_FORCE_UPD\", \"true\") == \"true\" else \"true\"\n                FabricWrapper.update(FABRIC_NAME,\"PM_FORCE_UPD\", pmForceUpd)\n                respObj.addErrorReport(funcName, \"Performance Monitoring feature is not started. \"\n                                       \"Please start Performance Monitoring from Feature Management and retry this operation.\")\n                respObj.setFailureRetCode()\n                return respObj\n\n    \t#Validate BGP AS number\n        Util.exe(Helper.isValidAsn(BGP_AS))\n\n        # validate Site ID\n        # This is a non mandatory parameter and input can be the following:\n        #   > empty - in this case, we will set it to the BGP_AS\n        #   > X - if integer, need validaiton to make sure it is within the range\n        #   > X.Y - may or not be the same as BGP AS. Same validation rules as BGP ASN. \n        #           Update the fabric settings with the equivalent decimal value using siteId = (65536 * X) + Y\n        newSiteId = SITE_ID\n        updateSiteId = False\n        if SITE_ID == \"\":\n            Wrapper.print(\"%s: Setting Site ID to BGP_AS [%s]\" % (funcName, BGP_AS))\n            newSiteId = BGP_AS\n\n        match = re.search('''\\.''', newSiteId)\n        if match:\n            # Site ID is in the X.Y format\n            tokens = newSiteId.split('.')\n            if len(tokens) == 2:\n                # make sure the Site ID passes the BGP AS validation rules\n                rObj = Helper.isValidAsn(newSiteId)\n                if rObj.isRetCodeFailure():\n                   respObj.addErrorReport(funcName, \"SITE ID is invalid. Please follow BGP AS number requirements.\")\n                   respObj.setFailureRetCode()\n                   return respObj\n\n                newSiteId = str(int(65536 * int(tokens[0])) + int (tokens[1]))\n                Wrapper.print(\"%s: token1: [%s] token 2: [%s]. Site ID = [%s]\" %(funcName, tokens[0], tokens[1], newSiteId))\n                updateSiteId = True\n        else:\n           match   = re.search('(^[0-9]+$)', newSiteId)\n           if match is None:\n               respObj.addErrorReport(funcName, \"SITE ID is invalid. Valid values: <1-281474976710655>\")\n               respObj.setFailureRetCode()\n               return respObj\n           else:\n               site_id_int = long(newSiteId)\n               if site_id_int < 1 or site_id_int > 281474976710655:\n                   respObj.addErrorReport(funcName, \"SITE ID not valid. Valid values: <1-281474976710655>\")\n                   respObj.setFailureRetCode()\n                   return respObj\n               elif SITE_ID != newSiteId:\n                   updateSiteId = True\n\n        Wrapper.print(\"%s: SITE_ID: [%s] newSiteId [%s] updateSiteId [%r]\" %(funcName, SITE_ID, newSiteId, updateSiteId))\n        if updateSiteId:\n            SITE_ID = newSiteId\n            fabricSettings[\"SITE_ID\"] = SITE_ID\n            #Util.exe(Helper.setFabricSiteId(FABRIC_NAME, newSiteId))\n\n        try:\n            getRespObj = FabricWrapper.getParentFabricName(FABRIC_NAME)\n            if getRespObj.isRetCodeSuccess():\n                parentFabric = getRespObj.getValue()\n                msLoopbackId = Util.exe(FabricWrapper.get(parentFabric, \"MS_LOOPBACK_ID\"))\n                if msLoopbackId == BGP_LB_ID or msLoopbackId == NVE_LB_ID:\n                    errorMsg = (\"Cannot change 'Underlay %s Loopback Id' to %s since \"\n                        \"it conflicts with 'Multi-site Routing Loopback Id' in parent fabric [%s]\"\n                        % (\"Routing\" if msLoopbackId==BGP_LB_ID else \"NVE\", BGP_LB_ID if msLoopbackId==BGP_LB_ID else NVE_LB_ID, parentFabric))\n                    Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                    respObj.addErrorReport(funcName, errorMsg)\n                    respObj.setFailureRetCode()\n                    return respObj\n        except:\n            Wrapper.print(\"exception, ignore if not member fabric\")\n            pass\n\n        # validate BANNER\n        if BANNER.strip():\n            BANNER=BANNER.strip()\n            if len(BANNER) < 3:\n                errorMsg = (\"Banner field needs to be delimiter char followed by non-empty message ending with delimiter \")\n                Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n            if BANNER[0] != BANNER[-1]:\n                errorMsg = (\"Banner field's starting char '%s' and ending char '%s' do not match. Banner field needs to be delimiter char followed by message ending with delimiter\"%(BANNER[0], BANNER[-1]))\n                Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n            if BANNER[0] in BANNER[1:-1]:\n                errorMsg = (\"Banner field using '%s' as delimiter cannot have '%s' inside banner message\" %(BANNER[0], BANNER[0]))\n                Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n        if UNDERLAY_IS_V6 == \"true\":\n            if FABRIC_INTERFACE_TYPE != \"p2p\":\n                fabricSettings[\"FABRIC_INTERFACE_TYPE\"] = \"p2p\"\n                FABRIC_INTERFACE_TYPE = \"p2p\"\n\n            if REPLICATION_MODE != \"Ingress\":\n                fabricSettings[\"REPLICATION_MODE\"] = \"Ingress\"\n                REPLICATION_MODE = \"Ingress\"\n\n            if FEATURE_PTP != \"false\":\n                fabricSettings[\"FEATURE_PTP\"] = \"false\"\n                FEATURE_PTP = \"false\"\n\n        # Initialize IsShow dependent variables to their default values if\n        # they are set to blank by the backend because the IsShow evaluation is False.\n        # Only variables that are identified to show different behavior from 11.3 if\n        # they are left blank are initialized.\n        if USE_LINK_LOCAL == \"\":\n            fabricSettings[\"USE_LINK_LOCAL\"] = \"true\"\n        if ENABLE_DEFAULT_QUEUING_POLICY == \"\":\n            fabricSettings[\"ENABLE_DEFAULT_QUEUING_POLICY\"] = \"false\"\n        if FABRIC_VPC_QOS == \"\":\n            fabricSettings[\"FABRIC_VPC_QOS\"] = \"false\"\n        if GRFIELD_DEBUG_FLAG == \"\":\n            fabricSettings[\"GRFIELD_DEBUG_FLAG\"] = \"Disable\"\n        if MPLS_HANDOFF == \"\":\n            fabricSettings[\"MPLS_HANDOFF\"] = \"false\"\n\n        if FABRIC_INTERFACE_TYPE == \"\":\n            fabricSettings[\"FABRIC_INTERFACE_TYPE\"] = \"p2p\"\n        if SUBNET_TARGET_MASK == \"\":\n            fabricSettings[\"SUBNET_TARGET_MASK\"] = \"30\"\n        if V6_SUBNET_TARGET_MASK == \"\":\n            fabricSettings[\"V6_SUBNET_TARGET_MASK\"] = \"126\"\n        if REPLICATION_MODE == \"\":\n            fabricSettings[\"REPLICATION_MODE\"] = \"Multicast\"\n        if ENABLE_TRM == \"\":\n            fabricSettings[\"ENABLE_TRM\"] = \"false\"\n        if RP_MODE == \"\":\n            fabricSettings[\"RP_MODE\"] = \"asm\"\n        if RP_COUNT == \"\":\n            fabricSettings[\"RP_COUNT\"] = \"2\"\n        if FABRIC_VPC_QOS_POLICY_NAME == \"\":\n            fabricSettings[\"FABRIC_VPC_QOS_POLICY_NAME\"] = \"spine_qos_for_fabric_vpc_peering\"\n        if OSPF_AUTH_ENABLE == \"\":\n           fabricSettings[\"OSPF_AUTH_ENABLE\"] = \"false\"\n        if ISIS_LEVEL == \"\":\n           fabricSettings[\"ISIS_LEVEL\"] = \"level-2\"\n        if ISIS_AUTH_ENABLE == \"\":\n            fabricSettings[\"ISIS_AUTH_ENABLE\"] = \"false\"\n        if BGP_AUTH_ENABLE == \"\":\n            fabricSettings[\"BGP_AUTH_ENABLE\"] = \"false\"\n        if BGP_AUTH_KEY_TYPE == \"\":\n            fabricSettings[\"BGP_AUTH_KEY_TYPE\"] = \"3\"\n        if PIM_HELLO_AUTH_ENABLE == \"\":\n            fabricSettings[\"PIM_HELLO_AUTH_ENABLE\"] = \"false\"\n        if BFD_ENABLE == \"\":\n            fabricSettings[\"BFD_ENABLE\"] = \"false\"\n        if BFD_IBGP_ENABLE == \"\":\n            fabricSettings[\"BFD_IBGP_ENABLE\"] = \"false\"\n        if BFD_OSPF_ENABLE == \"\":\n            fabricSettings[\"BFD_OSPF_ENABLE\"] = \"false\"\n        if BFD_ISIS_ENABLE == \"\":\n            fabricSettings[\"BFD_ISIS_ENABLE\"] = \"false\"\n        if BFD_PIM_ENABLE == \"\":\n            fabricSettings[\"BFD_PIM_ENABLE\"] = \"false\"\n        if BFD_AUTH_ENABLE == \"\":\n            fabricSettings[\"BFD_AUTH_ENABLE\"] = \"false\"\n        if ENABLE_NXAPI_HTTP == \"\":\n            fabricSettings[\"ENABLE_NXAPI_HTTP\"] = \"true\"\n        if NXAPI_HTTPS_PORT == \"\":\n            fabricSettings[\"NXAPI_HTTPS_PORT\"] = \"443\"\n        if NXAPI_HTTP_PORT == \"\":\n            fabricSettings[\"NXAPI_HTTP_PORT\"] = \"80\"\n        if FEATURE_PTP == \"\":\n            fabricSettings[\"FEATURE_PTP\"] = \"false\"\n        if ENABLE_DEFAULT_QUEUING_POLICY == \"\":\n            fabricSettings[\"ENABLE_DEFAULT_QUEUING_POLICY\"] = \"false\"\n        if DEAFULT_QUEUING_POLICY_CLOUDSCALE == \"\":\n            fabricSettings[\"DEAFULT_QUEUING_POLICY_CLOUDSCALE\"] = \"queuing_policy_default_8q_cloudscale\"\n        if DEAFULT_QUEUING_POLICY_R_SERIES == \"\":\n            fabricSettings[\"DEAFULT_QUEUING_POLICY_R_SERIES\"] = \"queuing_policy_default_r_series\"\n        if DEAFULT_QUEUING_POLICY_OTHER == \"\":\n            fabricSettings[\"DEAFULT_QUEUING_POLICY_OTHER\"] = \"queuing_policy_default_other\"\n\n        if STP_ROOT_OPTION == \"\":\n            fabricSettings[\"STP_ROOT_OPTION\"] = \"unmanaged\"\n\n        if AUTO_SYMMETRIC_VRF_LITE == \"\":\n            fabricSettings[\"AUTO_SYMMETRIC_VRF_LITE\"] = \"false\"\n        if AUTO_VRFLITE_IFC_DEFAULT_VRF == \"\":\n            fabricSettings[\"AUTO_VRFLITE_IFC_DEFAULT_VRF\"] = \"false\"\n        if AUTO_SYMMETRIC_DEFAULT_VRF == \"\":\n            fabricSettings[\"AUTO_SYMMETRIC_DEFAULT_VRF\"] = \"false\"\n\n        if DHCP_ENABLE == \"\":\n            fabricSettings[\"DHCP_ENABLE\"] = \"false\"\n        if DHCP_ENABLE == \"true\" and DHCP_IPV6_ENABLE == \"\":\n            fabricSettings[\"DHCP_IPV6_ENABLE\"] = \"DHCPv4\"\n        if ENABLE_AAA == \"\":\n            fabricSettings[\"ENABLE_AAA\"] = \"false\"\n        if VPC_DOMAIN_ID_RANGE == \"\":\n            VPC_DOMAIN_ID_RANGE = \"1-1000\"\n            fabricSettings[\"VPC_DOMAIN_ID_RANGE\"] = VPC_DOMAIN_ID_RANGE\n        if OVERLAY_MODE == \"\":\n            fabricSettings[\"OVERLAY_MODE\"] = \"config-profile\"\n        if HOST_INTF_ADMIN_STATE == \"\":\n            fabricSettings[\"HOST_INTF_ADMIN_STATE\"] = \"true\"\n\n        fabricSettings[\"PM_ENABLE_PREV\"] = pmEnable\n        fabricSettings[\"INBAND_MGMT_PREV\"] = inbandMgmt \n        fabricSettings[\"BOOTSTRAP_ENABLE_PREV\"] = bootstrapPOAPEnable     \n        # show the example if DHCP is enabled later\n        if DHCP_ENABLE != \"true\" and BOOTSTRAP_MULTISUBNET == \"\":\n            fabricSettings[\"BOOTSTRAP_MULTISUBNET\"] = \"#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix\"\n        \n        # update the template names that have changed from 11.x\n        if temp_vpc_peer_link == \"int_vpc_peer_link_po_11_1\":\n            fabricSettings[\"temp_vpc_peer_link\"] = \"int_vpc_peer_link_po\"\n        if abstract_routed_host == \"int_routed_host_11_1\":\n            fabricSettings[\"abstract_routed_host\"] = \"int_routed_host\"\n        if abstract_trunk_host == \"int_trunk_host_11_1\":\n            fabricSettings[\"abstract_trunk_host\"] = \"int_trunk_host\"\n\n        FabricWrapper.update(FABRIC_NAME, fabricSettings)\n\n        if REPLICATION_MODE == \"Multicast\":\n            #Verify that mask length for multicast subnet is between 8 and 30\n            tokens = MULTICAST_GROUP_SUBNET.split(\"/\")\n            if len(tokens) == 2:\n                prefix = int(tokens[1])\n                if prefix < 8 or prefix > 30:\n                    respObj.addErrorReport(funcName,\n                          \"Multicast subnet prefix length supported is 8 - 30: Value: \"+ str(prefix))\n                    respObj.setFailureRetCode()\n                    return respObj\n            else:\n                Wrapper.print(\"fabricInit: MULTICAST_GROUP_SUBNET: Tokens equal:\" + str(len(tokens)))\n                respObj.addErrorReport(funcName, \"Multicast subnet invalid: \" + MULTICAST_GROUP_SUBNET)\n                respObj.setFailureRetCode()\n                return respObj\n\n            respObj = Helper.isValidIPv4MCAddress(MULTICAST_GROUP_SUBNET)\n            if respObj.isRetCodeFailure():\n                return respObj\n            else:\n                Wrapper.print(\"fabricInit: MC group subnet is Valid\")\n\n            if ((ENABLE_TRM == \"true\") and (L3VNI_MCAST_GROUP != \"\")):\n                addr, prefix = MULTICAST_GROUP_SUBNET.split(\"/\")\n                mcastGroupSubnet = Util.getSubnetStringWithPrefix(addr, prefix)\n                mdtAddressSubnet = Util.getSubnetStringWithPrefix(L3VNI_MCAST_GROUP, prefix)\n                if mcastGroupSubnet != mdtAddressSubnet:\n                    errorMsg = (\"Default MDT address for TRM VRFs [%s] must be an address \"\n                                \"within the underlay multicast group subnet [%s]\" %\n                                (L3VNI_MCAST_GROUP, MULTICAST_GROUP_SUBNET))\n                    respObj.addErrorReport(funcName, errorMsg)\n                    return respObj\n            \n            if RP_MODE == \"bidir\":\n                # Verify that mask length for RP subnet for PIM Bidir must be 24\n                tokens = ANYCAST_RP_IP_RANGE.split(\"/\")\n                Wrapper.print(\"fabricInit: ANYCAST_RP_IP_RANGE: Tokens [%d]\" % (len(tokens)))\n                if len(tokens) == 2:\n                    prefix = int(tokens[1])\n                    if prefix != 24:\n                        respObj.addErrorReport(funcName, \"Phantom RP subnet prefix length must be 24: Value: \" + str(prefix))\n                        respObj.setFailureRetCode()\n                        return respObj\n                else:\n                    respObj.addErrorReport(funcName, \"RP subnet invalid: \" + ANYCAST_RP_IP_RANGE)\n                    respObj.setFailureRetCode()\n                    return respObj\n        else:\n            Wrapper.print(\"fabricInit: Not validating MC/RP Subnet as mode is: \" + REPLICATION_MODE)\n\n            if ENABLE_TRM == \"true\":\n                Wrapper.print(\"fabricInit: TRM can not be enabled while Replication Mode is Ingress\")\n                respObj.addErrorReport(funcName, \"TRM can not be enabled while Replication Mode is Ingress\")\n                respObj.setFailureRetCode()\n                return respObj\n\n        dict = getGlobals()\n        dict[\"GLOBALS_SET\"] = False\n        processRespObj(respObj, PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dict, \"sanityCheckLoopbackId\"))\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        Wrapper.print(\"Syntax check on IBGP_PEER_TEMPLATE %s\" % IBGP_PEER_TEMPLATE)\n        if IBGP_PEER_TEMPLATE:\n            bgp_peer_template = IBGP_PEER_TEMPLATE.splitlines()\n            Wrapper.print(\"bgp_peer_template %s\" % bgp_peer_template)\n            remote_as_present, af_evpn_present, af_mvpn_present, errorMsg = False, False, False, \"\"\n\n            errCmd = \"\"\n            for index, cmd in enumerate(bgp_peer_template):\n                if index == 0:\n                    if not cmd.startswith(\"  \") or cmd[2] == \" \":\n                        errorMsg += \"iBGP peer template: bgp peer template command must have 2 leading spaces. Please fix spacing problem: %s. \" % cmd\n                elif not cmd.startswith(\"    \"):\n                    errCmd += (\"[%s] \" % cmd)\n            if errCmd != \"\":\n                errorMsg += \"iBGP peer template: bgp peer template sub-command must have 4 or 6 leading spaces. Please fix spacing problem in the following commands: %s. \" % errCmd\n\n            if not bgp_peer_template[0].strip().startswith('template peer') and not bgp_peer_template[0].strip().startswith('template peer-session'):\n                errorMsg += \"iBGP peer template: peer template needs to start with '  template peer' or '  template peer-session'. \"\n            else:\n                peer_cmd = bgp_peer_template[0].strip().split(\" \")\n                if len(peer_cmd) != 3:\n                    errorMsg += \"iBGP peer template: command '%s' has invalid syntax. \" % bgp_peer_template[0]\n\n            for index, line in enumerate(bgp_peer_template, start=1):\n                if line.strip().startswith('remote-as'):\n                    remote_as_present = True\n                    if not line.startswith(\"    re\"):\n                        errorMsg += \"iBGP peer template: remote-as command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                    as_cmd = line.strip().split(' ')\n                    if len(as_cmd) == 2:\n                        if as_cmd[1] != BGP_AS:\n                            errorMsg += \"iBGP peer template: remote ASN %s does not match fabric BGP ASN %s. \" % (as_cmd[1], BGP_AS)\n                    else:\n                        errorMsg += \"iBGP peer template: '%s' command with invalid syntax. \" % line\n                elif line.strip() == 'address-family l2vpn evpn':\n                    af_evpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                elif line.strip() == 'address-family ipv4 mvpn':\n                    af_mvpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n\n            if not remote_as_present:\n                errorMsg += \"iBGP peer template: missing 'remote-as' command. \"\n            if not af_evpn_present:\n                errorMsg += \"iBGP peer template: missing 'address-family l2vpn evpn' command. \"\n            if ENABLE_TRM == \"true\" and not af_mvpn_present:\n                errorMsg += \"iBGP peer template: missing 'address-family ipv4 mvpn' command. \"\n            if ENABLE_TRM != \"true\" and af_mvpn_present:\n                errorMsg += \"iBGP peer template: 'address-family ipv4 mvpn' present while Tenant Routed Multicast is not enabled. \"\n\n            if errorMsg:\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n        Wrapper.print(\"Syntax check on IBGP_PEER_TEMPLATE_LEAF %s\" % IBGP_PEER_TEMPLATE_LEAF)\n        if IBGP_PEER_TEMPLATE_LEAF:\n            if not IBGP_PEER_TEMPLATE:\n                errorMsg = \"Please fill the iBGP peer template field when Leaf/Border/Border Gateway iBGP peer template is non empty. \"\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n            bgp_peer_template = IBGP_PEER_TEMPLATE_LEAF.splitlines()\n            Wrapper.print(\"leaf bgp_peer_template %s\" % bgp_peer_template)\n            remote_as_present, af_evpn_present, af_mvpn_present, rr_client_present, errorMsg = False, False, False, False, \"\"\n\n            errCmd = \"\"\n            for index, cmd in enumerate(bgp_peer_template):\n                if index == 0:\n                    if not cmd.startswith(\"  \") or cmd[2] == \" \":\n                        errorMsg += \"Leaf iBGP peer template: bgp peer template command must have 2 leading spaces. Please fix spacing problem: %s. \" % cmd\n                elif not cmd.startswith(\"    \"):\n                    errCmd += (\"[%s] \" % cmd)\n            if errCmd != \"\":\n                errorMsg += \"Leaf iBGP peer template: bgp peer template sub-command must have 4 or 6 leading spaces. Please fix spacing problem in the following commands: %s. \" % errCmd\n\n            if not bgp_peer_template[0].strip().startswith('template peer') and not bgp_peer_template[0].strip().startswith('template peer-session'):\n                errorMsg += \"Leaf iBGP peer template: peer template needs to start with '  template peer' or '  template peer-session'. \"\n            else:\n                peer_cmd = bgp_peer_template[0].strip().split(\" \")\n                if len(peer_cmd) != 3:\n                    errorMsg += \"Leaf iBGP peer template: command '%s' has invalid syntax. \" % bgp_peer_template[0]\n\n            for index, line in enumerate(bgp_peer_template, start=1):\n                if line.strip().startswith('route-reflector-client'):\n                    rr_client_present = True\n\n                if line.strip().startswith('remote-as'):\n                    remote_as_present = True\n                    if not line.startswith(\"    r\"):\n                        errorMsg += \"Leaf iBGP peer template: remote-as command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                    as_cmd = line.strip().split(' ')\n                    if len(as_cmd) == 2:\n                        if as_cmd[1] != BGP_AS:\n                            errorMsg += \"Leaf iBGP peer template: remote ASN %s does not match fabric BGP ASN %s. \" % (as_cmd[1], BGP_AS)\n                    else:\n                        errorMsg += \"Leaf iBGP peer template: '%s' command with invalid syntax. \" % line\n                elif line.strip() == 'address-family l2vpn evpn':\n                    af_evpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"Leaf iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                elif line.strip() == 'address-family ipv4 mvpn':\n                    af_mvpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"Leaf iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n\n            if rr_client_present:\n                errorMsg += \"Leaf iBGP peer template should not contain 'route-reflector-client' command. \"\n            if not remote_as_present:\n                errorMsg += \"Leaf iBGP peer template: missing 'remote-as' command. \"\n            if not af_evpn_present:\n                errorMsg += \"Leaf iBGP peer template: missing 'address-family l2vpn evpn' command. \"\n            if ENABLE_TRM == \"true\" and not af_mvpn_present:\n                errorMsg += \"Leaf iBGP peer template: missing 'address-family ipv4 mvpn' command. \"\n            if ENABLE_TRM != \"true\" and af_mvpn_present:\n                errorMsg += \"Leaf iBGP peer template: 'address-family ipv4 mvpn' present while Tenant Routed Multicast is not enabled. \"\n\n            if errorMsg:\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n        if not checkFabricMtuSettings(respObj):\n            return respObj\n\n        if not checkFabricVpcDomainId(respObj):\n            return respObj\n\n        if not checkBgpAsChange(respObj):\n            return respObj\n\n        if not checkLinkProtocolTagChange(respObj):\n            return respObj\n\n        if not checkOverlayModeChange(respObj):\n            return respObj\n\n        if not macSecSanityCheck(respObj):\n            return respObj\n\n        # check loopback resource range\n        if STATIC_UNDERLAY_IP_ALLOC == \"false\":\n            if UNDERLAY_IS_V6 == \"false\":\n                ip0, mask0 = LOOPBACK0_IP_RANGE.split(\"/\")\n                ip1, mask1 = LOOPBACK1_IP_RANGE.split(\"/\")\n                if mask0 == \"32\" or mask1 == \"32\":\n                    errMsg = \"Underlay Routing or VTEP Loopback IP Range Mask has to be smaller than 32. \"\n                    respObj.addErrorReport(funcName, errMsg)\n                    respObj.setFailureRetCode()\n                if MPLS_HANDOFF == \"true\":\n                    ip, mask = MPLS_LOOPBACK_IP_RANGE.split(\"/\")\n                    if mask == \"32\":\n                        errMsg = \"MPLS Loopback IP Range Mask has to be smaller than 32. \"\n                        respObj.addErrorReport(funcName, errMsg)\n                        respObj.setFailureRetCode()\n            else:\n                ip0, mask0 = LOOPBACK0_IPV6_RANGE.split(\"/\")\n                ip1, mask1 = LOOPBACK1_IPV6_RANGE.split(\"/\")\n                if mask0 == \"128\" or mask1 == \"128\":\n                    errMsg = \"Underlay Loopback IPV6 Range Mask has to be smaller than 128.\"\n                    respObj.addErrorReport(funcName, errMsg)\n                    respObj.setFailureRetCode()\n\n            if respObj.isRetCodeFailure():\n                return respObj\n\n        dynamicIPPoolsEnable = True\n        try:\n            if STATIC_UNDERLAY_IP_ALLOC == \"true\":\n                dynamicIPPoolsEnable = False\n        except:\n            pass\n\n        # Initialization of resource manager for Underlay Resources.\n        if dynamicIPPoolsEnable:\n            dictObj = {\"FABRIC_NAME\" : FABRIC_NAME}\n            newRespObj = PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"checkIfDuplicatePools\")\n            Util.processRespObj(respObj, newRespObj)\n            if UNDERLAY_IS_V6 == \"false\":\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET, SUBNET_RANGE, SUBNET_TARGET_MASK))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", PoolType.IP, LOOPBACK0_IP_RANGE))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK1_IP_POOL\", PoolType.IP, LOOPBACK1_IP_RANGE))\n\n                # special processing for Inband POAP and unnumbered fabric\n                if inbandPOAPEnable == \"true\" and FABRIC_INTERFACE_TYPE != \"p2p\":\n                    #   - set RM with the anycast IP for the POAP default GW (the first IP in the range)\n                    lb0NwkAddr = LOOPBACK0_IP_RANGE.split(\"/\")[0]\n                    lb0NwkPrefix = LOOPBACK0_IP_RANGE.split(\"/\")[1]\n\n                    #Pick first address in loopback0 ip range as the default gw for the DHCP subnet scope programming\n                    lb0NwkBytes = lb0NwkAddr.split(\".\")\n                    lb0NwkGwLastByte = int(lb0NwkBytes[3]) + 1\n                    dhcpUnnumGwIp = lb0NwkBytes[0] + \".\" + lb0NwkBytes[1] + \".\" + lb0NwkBytes[2] + \".\" + str(lb0NwkGwLastByte)\n\n                    Wrapper.print(\"%s: FAB [%s]: dhcpUnnumGwIp [%r]\" % (funcName, FABRIC_NAME, dhcpUnnumGwIp))\n                    # reserve this in RM for DHCP code to use\n                    Util.exeRM(RM.set(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", EntityType.FABRIC, \"INBAND_POAP_GW\", dhcpUnnumGwIp))\n\n                ip, mask = ANYCAST_RP_IP_RANGE.split(\"/\") if ANYCAST_RP_IP_RANGE else (\"\",\"\")\n                if mask == \"32\":\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"ANYCAST_RP_IP_POOL\", PoolType.IP))\n                else:\n                    Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"ANYCAST_RP_IP_POOL\", PoolType.IP, ANYCAST_RP_IP_RANGE))\n\n                if MPLS_HANDOFF == \"true\":\n                    Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"MPLS_LOOPBACK_IP_POOL\", PoolType.IP, MPLS_LOOPBACK_IP_RANGE))\n                else:\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"MPLS_LOOPBACK_IP_POOL\", PoolType.IP))\n            else:\n                if USE_LINK_LOCAL == \"false\":\n                    Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET, V6_SUBNET_RANGE, V6_SUBNET_TARGET_MASK))\n                else:\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", PoolType.IP, LOOPBACK0_IPV6_RANGE))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK1_IP_POOL\", PoolType.IP, LOOPBACK1_IPV6_RANGE))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"ROUTER_ID_POOL\", PoolType.IP, ROUTER_ID_RANGE))\n        else:\n            # init IP pools to be empty. The IP addresses are expected to be explicitly set in RM offline\n            Wrapper.print(\"fabricInit: Init Empty Subnet Pool - PoolName.SUBNET\")\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET))\n            Wrapper.print(\"fabricInit: Init Empty IP Pool - LOOPBACK0_IP_POOL\")\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", PoolType.IP))\n            Wrapper.print(\"fabricInit: Init Empty IP Pool - LOOPBACK1_IP_POOL\")\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"LOOPBACK1_IP_POOL\", PoolType.IP))\n            if UNDERLAY_IS_V6 == \"false\":\n                Wrapper.print(\"fabricInit: Init Empty IP Pool - ANYCAST_RP_IP_POOL\")\n                Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"ANYCAST_RP_IP_POOL\", PoolType.IP))\n                if MPLS_HANDOFF == \"true\":\n                    Wrapper.print(\"fabricInit: Init Empty IP Pool - MPLS_LOOPBACK_IP_POOL\")\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"MPLS_LOOPBACK_IP_POOL\", PoolType.IP))\n            else:\n                Wrapper.print(\"fabricInit: Init Empty IP Pool - ROUTER_ID_POOL\")\n                Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"ROUTER_ID_POOL\", PoolType.IP))\n\n        if DCI_SUBNET_RANGE != \"\":\n            Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"DCI subnet pool\",\n                                            PoolType.SUBNET, DCI_SUBNET_RANGE,\n                                            DCI_SUBNET_TARGET_MASK))\n        else:\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"DCI subnet pool\",\n                                             PoolType.SUBNET))\n            Wrapper.print(\"Empty DCI Subnet range, ignore\")\n        # Initialize an empty DCI subnet pool for IPv6\n        Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"IPv6 DCI subnet pool\", PoolType.SUBNET))\n        Wrapper.print(\"Empty IPv6 DCI Subnet range, ignore\")\n\n        # Initialization of resource manager for Overlay and Underlay Resources (port-channel and other IDs).\n        # PC ID pool should be 1-499, 501-4096 once RM get/set is working with range.\n        # 500 is default for underlay - vpc peer link port-channel and vpc id\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"PORT_CHANNEL_ID\", \"501-4000\"))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"FEX_ID\", \"101-199\"))\n\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"VPC_ID\", \"1-100, 200-499\"))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"VPC_DOMAIN_ID\", VPC_DOMAIN_ID_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"VPC_PEER_LINK_VLAN\", VPC_PEER_LINK_VLAN))\n\n        # Loopback pool should be 2-199, 201-1000 once RM get/set is working with range.\n        # 0,1,254,255 reserved for underlay - bgp, nve, border gateway, anycast rp loopbacks\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK_ID\", \"0-1023\"))\n\n        # Initialization of resource manager for Overlay Resources.\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"TOP_DOWN_L3_DOT1Q\", SUBINTERFACE_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"TOP_DOWN_NETWORK_VLAN\", NETWORK_VLAN_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"TOP_DOWN_VRF_VLAN\", VRF_VLAN_RANGE))\n\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"BGP_ASN_ID\", PoolType.ID, BGP_AS))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"L3_VNI\", L3_PARTITION_ID_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"L2_VNI\", L2_SEGMENT_ID_RANGE))\n        Util.exe(RM.addOrUpdateOverlapPool(FABRIC_NAME, \"MCAST_IP_POOL\", PoolType.IP, MULTICAST_GROUP_SUBNET))\n\n        # always have the relevant pool as user may define the policies before enabling PBR flag\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"SERVICE_NETWORK_VLAN\", SERVICE_NETWORK_VLAN_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"ROUTE_MAP_SEQUENCE_NUMBER_POOL\", ROUTE_MAP_SEQUENCE_NUMBER_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"SLA_ID\", SLA_ID_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"OBJECT_TRACKING_NUMBER_POOL\", OBJECT_TRACKING_NUMBER_RANGE))\n\n        # Validate additional settings\n        dict[\"FABRIC_VALIDATION_PARAMS\"] = {\"validateManagebilitySettings\": True,\n                                            \"validateNetflowSettings\" : True,\n                                            \"validatePvlanSettings\": True,\n                                            \"validateNxCloudSettings\": True,\n                                            \"validateLanDeviceConnectivityMode\" : True}\n        dict[\"FABRIC_INIT\"] = True\n        Util.exe(PTI.executePyTemplateMethod(\"fabric_utility_11_1\", dict, \"validateInitFabricSettings\"))\n\n        # validation passes. Update if applicable\n        if ENABLE_PVLAN_PREV != ENABLE_PVLAN:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"ENABLE_PVLAN_PREV\", ENABLE_PVLAN))\n\n        allowNxc = fabricSettings.get(\"ALLOW_NXC\", \"false\")\n        allowNxcPrev = fabricSettings.get(\"ALLOW_NXC_PREV\", \"false\")\n        if allowNxcPrev != allowNxc:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"ALLOW_NXC_PREV\", allowNxc))\n\n        if (AUTO_UNIQUE_VRF_LITE_IP_PREFIX == \"false\" and \n            AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV == \"false\" and\n            PER_VRF_LOOPBACK_AUTO_PROVISION == \"false\" and \n            PER_VRF_LOOPBACK_AUTO_PROVISION_PREV == \"false\" and\n            TOPDOWN_CONFIG_RM_TRACKING != \"completed\"):\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"TOPDOWN_CONFIG_RM_TRACKING\", \"notstarted\"))\n\n        autoVrfLiteUniqIp = fabricSettings.get(\"AUTO_UNIQUE_VRF_LITE_IP_PREFIX\", \"false\")\n        autoVrfLiteUniqIpPrev = fabricSettings.get(\"AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV\", \"false\")\n        if autoVrfLiteUniqIpPrev != autoVrfLiteUniqIp:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV\", autoVrfLiteUniqIp))\n            if TOPDOWN_CONFIG_RM_TRACKING == \"completed\" and autoVrfLiteUniqIp == \"true\":\n                Util.exe(FabricWrapper.update(FABRIC_NAME, \"TOPDOWN_CONFIG_RM_TRACKING\", \"restart\"))\n\n        pervrfLbProv = fabricSettings.get(\"PER_VRF_LOOPBACK_AUTO_PROVISION\", \"false\")\n        pervrfLbProvPrev = fabricSettings.get(\"PER_VRF_LOOPBACK_AUTO_PROVISION_PREV\", \"false\")\n        if pervrfLbProvPrev != pervrfLbProv:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"PER_VRF_LOOPBACK_AUTO_PROVISION_PREV\", pervrfLbProv))\n\n\n        # dhcp initialization for DHCP IPs provided in bootstrap section.\n        dict = getGlobals(dictionaryObj)\n        Util.exe(dhcpInit(dict))\n\n        Util.exe(BRW.CreateBackUpJob(FABRIC_NAME, enableRealTimeBackup, enableScheduledBackup, scheduledTime))\n    except Exception as e:\n        if isinstance(e, respObjError):\n            Util.processRespObj(respObj, e.value)\n        else:\n            Util.handleException(\"Unexpected error creating fabric\", e, respObj)\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" %\n                (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n    return respObj\n\n#initialize DHCP scope in dchp.conf for bootstrapped devices for automatic IP assignments\ndef dhcpInit(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        respObj = PTI.executePyTemplateMethod(\"dhcp_common\", getGlobals(dictionaryObj), \"dhcpInit\")\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" % \\\n                    (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n    return respObj\n\ndef getFabErrEntity(fnName, entityName=None):\n    if entityName:\n        return fnName + \":\" + entityName\n    else:\n        return fnName\n\ndef getStrGlobals():\n    newDict = {}\n    gDict = globals()\n    for key in gDict.keys():\n        if type(gDict[key]) is str:\n            newDict[key] = gDict[key]\n    return newDict\n\ndef actionAllow():\n    Wrapper.print(\"actionAllow: FAB [%s]: FF [%s]\" % (FABRIC_NAME, FF))\n    r = WrappersResp.getRespObj()\n    r.setSuccessRetCode()\n    try:\n        extFabricType = EXT_FABRIC_TYPE\n    except:\n        extFabricType = \"\"\n\n    if FF != \"Easy_Fabric\":\n        fabricType = Util.mapFFToFabricType(FF, extFabricType)\n        article = \"An\" if fabricType[0].lower() in ['a','e','i','o','u'] else \"A\"\n        r.addErrorReport(\"actionAllow\", \"%s %s fabric may not be converted to a Data Center VXLAN EVPN fabric \"\n                         \"as that may cause configuration issues. Please revert the fabric to %s and save.\" %\n                         (article, fabricType, fabricType))\n        r.setFailureRetCode()\n    return r\n\ndef preAdd(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: preAdd: Serial [%s]\" %\n        (FABRIC_NAME, dictionaryObj[\"deviceSerial\"]))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        # need to allocate below new object using wrapper to return response of success/failure to GUI.\n        # by default below API sets retCode to SUCCESS\n        Util.exe(actionAllow())\n\n        Wrapper.print(\"==========preAdd: Fabric Name = %s, keys = %d, Device Serial = %s, Device Model = %s, Preserve Config = %s\" %\n                      (FABRIC_NAME, len(dictionaryObj), dictionaryObj[\"deviceSerial\"],  dictionaryObj[\"deviceModel\"],\n                       dictionaryObj[\"devicePreserveConfig\"]))\n        dict = getGlobals(dictionaryObj)\n        respObj = Util.exe(PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dict, \"preAddExt\"))\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preAdd: Serial [%s]. Success = [%r]\" %\n                (FABRIC_NAME, dictionaryObj[\"deviceSerial\"], respObj.isRetCodeSuccess()))\n        return respObj\n\ndef getGlobals(additionalDict=None):\n    newDict = {}\n    gDict = globals()\n    for key in gDict.keys():\n        if ((type(gDict[key]) is str) or\n            (type(gDict[key]) is dict)):\n            newDict[key] = gDict[key]\n    if additionalDict:\n        newDict.update(additionalDict)\n    return newDict\n\ndef preChangeDiscoveryIP(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    Util.exe(actionAllow())\n    try:\n        dict = getGlobals(dictionaryObj)\n        respObj = PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dict, \"doPreChangeDiscoveryIP\")\n    except Exception as e:\n        msg = (\"Unexpected error during change discovery IP handling\")\n        if isinstance(e, respObjError):\n            respObj.addErrorReport(getFabErrEntity(funcName), msg)\n            respObj.setFailureRetCode()\n            Util.processRespObj(respObj, e.value)\n        else:\n            Util.handleException(msg, e, respObj)\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" % (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n        return respObj\n\ndef postAdd(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: postAdd: Serial [%s] dictionaryObj %s\" %\n            (FABRIC_NAME, dictionaryObj[\"deviceSerial\"], dictionaryObj))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        dict = getGlobals(dictionaryObj)\n        respObj = Util.exe(PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dict, \"postAddExt\"))\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: postAdd: Serial [%s]. Success = [%r]\" %\n                (FABRIC_NAME, dictionaryObj[\"deviceSerial\"], respObj.isRetCodeSuccess()))\n\ndef getIntegerRange(rangeStr):\n    return sum(((list(range(*[int(j) + k for k,j in enumerate(i.split('-'))]))\n                        if '-' in i else [int(i)]) for i in rangeStr.split(',')), [])\n\ndef bootstrapDevice(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s, dictionaryObj %s\" % (FABRIC_NAME, funcName, str(dictionaryObj)))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        Util.exe(actionAllow())\n        dict = getGlobals(dictionaryObj)\n        devices = dictionaryObj[\"bootstrapDevices\"]\n        numDevicesToBootstrap = len(devices)\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        dcnmUser = fabricSettings.get(\"dcnmUser\", \"\")\n        inbandPOAPEnable = isInbandPoapEnabled(fabricSettings)\n        Wrapper.print(\"%s: Fabric [%s]: inbandPOAPEnable [%s] dcnmUser [%s] Num devices [%d]\" % (funcName, \n                        FABRIC_NAME, inbandPOAPEnable, dcnmUser, numDevicesToBootstrap))\n\n        for i in range(numDevicesToBootstrap):\n            Wrapper.print(\"Fabric [%s]: Attempting Bootstrap for Switch [%s] - #%d of %d\" %(FABRIC_NAME,\n                                        devices[i].serialNumber, i+1, numDevicesToBootstrap))\n\n        # Wrapper.print(\"%s: Sending dictionary obj %s for fabric %s\" %(funcName, FABRIC_NAME, str(dict)))\n        newRespObj = PTI.executePyTemplateMethod(\"dhcp_common\", dict, \"bootstrapDevice\")\n        processRespObj(respObj, newRespObj)\n        if inbandPOAPEnable == \"true\":\n            if newRespObj.isRetCodeFailure():\n                # bootstrap for some switches failed... log them here. Fabric errors must already be present from earlier call\n                failedSwitchSerials = newRespObj.getValue()\n                numDevices = len(failedSwitchSerials)\n                i = 0\n                for serial in failedSwitchSerials:\n                    Wrapper.print(\"Fabric [%s]: Bootstrap failed for Switch [%s] - #%d of %d\" % (FABRIC_NAME, serial, ++i, numDevices))\n\n                devicesToContinue = []\n                for i in range(numDevicesToBootstrap):\n                    if devices[i].serialNumber not in failedSwitchSerials:\n                        devicesToContinue.append(copy.deepcopy(devices[i]))\n            else:\n                devicesToContinue = devices\n\n            if len(devicesToContinue):\n                dictionaryObj[\"bootstrapDevices\"] = devicesToContinue\n                # Additional processing for inband POAP\n                #Should call configSave to generate the full startup config of the switch being bootstrapped\n                processRespObj(respObj, configSaveInband(dict))\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" % (FABRIC_NAME, \n                                                            funcName, respObj.isRetCodeSuccess()))\n    return respObj\n\ndef preFabricDelete(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: preFabricDelete\" % (FABRIC_NAME))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    #check switches\n    try:\n        Util.exe(actionAllow())\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)  # all devices serial number\n        devices = filter(None, devices)\n        Wrapper.print(\"PFD: Found %d Switches\" % len(devices))\n        if (len(devices) > 0):\n            respObj.addErrorReport(getFabErrEntity(preFabricDelete.__name__),\n                                   \"Fabric cannot be deleted with switches present. \"\n                                   \"Please check the Switches page to make sure \"\n                                   \"there are no switch entries and retry.\")\n            respObj.setFailureRetCode()\n            return respObj\n        RM.deleteFabricResources(FABRIC_NAME)\n        dictionaryObj[\"FABRIC_NAME\"] = FABRIC_NAME\n        PTI.executePyTemplateMethod(\"dhcp_utility\", dictionaryObj, \"deleteDHCPScopeV6\")\n        PTI.executePyTemplateMethod(\"dhcp_utility\", dictionaryObj, \"deleteDHCPScope\")\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preFabricDelete: Success = [%r]\" %\n                (FABRIC_NAME, respObj.isRetCodeSuccess()))\n                \n#preSwitchDelete - PSD#\ndef preSwitchDelete(dictionaryObj):\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    funcName = sys._getframe(0).f_code.co_name\n    \n    Fabric_name = \"\"\n    try:\n      forceDelete = dictionaryObj.get(\"force\", False)\n      deleteSwitch = True\n      if (\"notDeleteSwitch\" in dictionaryObj):\n          deleteSwitch = False\n          Fabric_name = dictionaryObj[\"FABRIC_NAME\"]\n      else:\n          Fabric_name = FABRIC_NAME\n          Util.exe(actionAllow())\n      Wrapper.print(\"==========ACTION: FAB [%s]: Start: preSwitchDelete. Serial [%s], deleteSwitch [%s]\" %\n                    (Fabric_name, dictionaryObj[\"deviceSerial\"], deleteSwitch))\n\n      sn = dictionaryObj[\"deviceSerial\"]\n      topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(Fabric_name)))\n      isVPC = Util.exe(VpcWrapper.isVpc(Fabric_name, sn))\n      switchRole = topologyDataObj.getSwitchRole(sn)\n      hostName = Util.exe(InventoryWrapper.getHostName(sn))\n      fabricSettings = Util.exe(FabricWrapper.get(Fabric_name)).getNvPairs()\n\n      Wrapper.print(\"%s[%s]: Role [%s] isVPC [%s]\" % (sn, hostName, switchRole, isVPC))\n\n      dictObj = getGlobals(dictionaryObj)\n      dictObj[\"SRNO\"] = sn\n      dictObj[\"FABRIC_NAME\"] = Fabric_name\n      dictObj[\"topologyObj\"] = topologyDataObj\n\n      FF = dictObj.get(\"FF\", \"Easy_Fabric\")\n      if FF == \"Easy_Fabric\":\n          Wrapper.print(\"Easy Fabric template\")\n          \n          # check whether service has been enabled\n          if \"border\" in switchRole or \"leaf\" in switchRole:\n              resp = ElasticServiceWrapper.serviceNetworkAttached(sn, True)\n              if resp.isRetCodeSuccess() and resp.getValue():\n                    respObj = WrappersResp.getRespObj()\n                    respObj.addErrorReport(\"SwitchRemoval\", (\"There are service networks being attached to this switch (or its peer switch). Please detach the service networks and deploy the changes (detach service networks) before removing this switch.\"), sn)\n                    respObj.setFailureRetCode()\n                    return respObj   \n              else:\n                  Wrapper.print(\"%s(): No service network is attached, so proceed to validate the pre-deletion of switch [%s]\" % (funcName, sn))                    \n          if switchRole == \"tor\":\n              if isVPC:\n                  vpcPairSerialKey = Util.exe(VpcWrapper.get(VPCMetaDataType.VPC_PAIR, Fabric_name, sn))\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(vpcPairSerialKey))\n                  unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(vpcPairSerialKey))\n              else:\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(sn))\n                  unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(sn))\n              if pairingSns:\n                  respObj.addErrorReport(getFabErrEntity(funcName, sn),\n                      \"Switch has a leaf-tor pairing. Please remove the pairing before deleting the tor switch from the fabric.\", sn)\n                  respObj.setFailureRetCode()\n                  return respObj\n              if unpairingSns:\n                  respObj.addErrorReport(getFabErrEntity(funcName, sn),\n                      \"Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the tor switch from the fabric.\", sn)\n                  respObj.setFailureRetCode()\n                  return respObj\n          elif switchRole == \"leaf\" and deleteSwitch:\n              if isVPC:\n                  vpcPairSerialKey = Util.exe(VpcWrapper.get(VPCMetaDataType.VPC_PAIR, Fabric_name, sn))\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(vpcPairSerialKey))\n              else:\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(sn))\n              unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(sn))\n              if isVPC and not unpairingSns:\n                  unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(vpcPairSerialKey))\n                  if not unpairingSns:\n                      vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n                      unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(vpcPeerSn))\n              if unpairingSns:\n                  respObj.addErrorReport(getFabErrEntity(funcName, sn),\n                      \"Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the leaf switch from the fabric.\", sn)\n                  respObj.setFailureRetCode()\n                  return respObj\n\n              if pairingSns:\n                  # Delete all tors that are associated with this leaf\n                  Util.exe(cleanupLeafTorAssoc(sn, pairingSns))\n                  vpcPeerProcessedList = []\n                  for torSn in pairingSns:\n                      if torSn in vpcPeerProcessedList:\n                          continue\n                      isTorVpc = Util.exe(VpcWrapper.isVpc(Fabric_name, torSn))\n                      if isTorVpc:\n                          torVpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, torSn))\n                          PTI.createOrUpdate(torSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n                          PTI.createOrUpdate(torVpcPeerSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n                          Wrapper.print(\"PSD: Unpair VPC on torSn [%s]\" % torSn)\n                          Util.exe(VpcWrapper.delete(torSn))\n\n                          Wrapper.print(\"PSD: Delete all PTIs and resource for torVpcPeerSn [%s]\" % torVpcPeerSn)\n                          PTI.delete(torVpcPeerSn)\n                          RM.deleteSwitchResources(torVpcPeerSn)\n                          CDW.clearDeployerHistory(torVpcPeerSn)\n                          InventoryWrapper.removeSwitch(Fabric_name, torVpcPeerSn)\n                          vpcPeerProcessedList.append(torVpcPeerSn)\n\n                      Wrapper.print(\"PSD: Delete all PTIs and resource for torSn [%s]\" % torSn)\n                      PTI.delete(torSn)\n                      RM.deleteSwitchResources(torSn)\n                      CDW.clearDeployerHistory(torSn)\n                      InventoryWrapper.removeSwitch(Fabric_name, torSn)\n\n          SSPINE_ADD_DEL_DEBUG_FLAG = fabricSettings.get(\"SSPINE_ADD_DEL_DEBUG_FLAG\",\"Disable\")\n          if \"super\" in switchRole:\n              Wrapper.print(\"Easy Fabric Super in role %s\"%(switchRole))\n              spinesWithSuperRole = topologyDataObj.get(TopologyInfoType.SPINES_WITH_SUPER_ROLE)\n              spines = topologyDataObj.get(TopologyInfoType.SPINES)\n\n              Wrapper.print(\"Easy Fabric Super role in spines count %s and normal spines count %s\"%(len(spinesWithSuperRole),len(spines)))\n              if len(spinesWithSuperRole) == 1 and len(spines) > 0:\n                  if SSPINE_ADD_DEL_DEBUG_FLAG == \"Disable\":\n                      respObj.addWarnReport(getFabErrEntity(funcName, sn+\":Fabric without super spine role devices\"),\n                                            \"After deletion of this device, fabric doesn't have any more super spine roles \"\n                                            \"and performing Recalculate Config without any super spine device will generate bgp peering between spines and leafs.\", sn)\n                      respObj.setWarningRetCode()\n\n      #Delete all overlays on border switches before IFCs are deleted\n      if \"border\" == switchRole or \"border spine\" == switchRole or \"border super spine\" == switchRole:\n          Util.exe(validateInterfabricDelete(sn, forceDelete))\n          ptiList = Util.exe(PTI.get(sn))\n          Wrapper.print(\"Count is %s\" % (len(ptiList)))\n          count = 0\n          for pti in ptiList:\n               if pti.getSource() == \"OVERLAY\":\n                   PTI.deleteInstance(pti.getPolicyId())\n                   count = count + 1\n          if count > 0:\n              Util.exe(Helper.removeItemsCSM(sn))\n\n      if \"border gateway\" in switchRole:\n          Util.exe(validateInterfabricDelete(sn, forceDelete))\n          ifcPtiList = Util.exe(PTI.get(sn, \"SWITCH\", \"SWITCH\", \"\", \"ifcdelete\"))\n          if len(ifcPtiList) == 0:\n              dictObj[\"force\"] = forceDelete\n              processRespObj(respObj, PTI.executePyTemplateMethod(\"interface_utility\", dictObj, \"isMSDMemberSwitchDelAllowed\"))\n              if respObj.isRetCodeFailure():\n                  return respObj\n              else:\n                  if isVPC:\n                      vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n                      PTI.createOrUpdate(vpcPeerSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"ifcdelete\", {})\n          ptiList = Util.exe(PTI.get(sn))\n          Wrapper.print(\"Count is %s\" % (len(ptiList)))\n          count = 0\n          for pti in ptiList:\n              if pti.getSource() == \"OVERLAY\":\n                  PTI.deleteInstance(pti.getPolicyId())\n                  count = count + 1\n          if count > 0:\n             Util.exe(Helper.removeItemsCSM(sn))\n\n          if isVPC:\n              Wrapper.print(\"PSD: started overlay deletion for VPC config\")\n              vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n              ptiList = Util.exe(PTI.get(vpcPeerSn))\n              Wrapper.print(\"Count is %s\" % (len(ptiList)))\n              count = 0\n              for pti in ptiList:\n                  if pti.getSource() == \"OVERLAY\":\n                      PTI.deleteInstance(pti.getPolicyId())\n                      count = count + 1\n              if count > 0:\n                 Util.exe(Helper.removeItemsCSM(vpcPeerSn))\n              # let the delete template do this\n              # get Source Switch Id for sn\n              # get count of the MS overlay IFCs for sn - snCount\n              # get Source Switch Id for vpcPeerSn\n              # get count of the MS overlay IFCs for vpcPeerSn --- vpcSnCount\n              # remove all overlay PTIs from sn and vpcPeerSn\n              # if snCount == 1 or vpcSnCount == 1:\n              #     if overlays are extended over MS Overlay IFCs:\n              #         Report error\n\n      if deleteSwitch:\n          # check whether service has been enabled\n          if FF == \"Easy_Fabric\" and (\"border\" in switchRole or \"leaf\" in switchRole):\n              ElasticServiceWrapper.deleteServiceNode(sn)\n              Wrapper.print(\"%s(): Finished the service related config deletion for switch [%s].\" % (funcName, sn))\n\n          Util.exe(PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"delFabricIntfConfig\"))\n          Wrapper.print(\"PSD: started for BGP config\")\n          PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"bgpConfigDel\")\n          Wrapper.print(\"PSD: started for RP config\")\n          PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"rpConfigDel\")\n\n      if isVPC:\n          Wrapper.print(\"PSD: started for VPC config\")\n          vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n          PTI.createOrUpdate(sn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n          PTI.createOrUpdate(vpcPeerSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n          #disjoinvpcParing(topologyDataObj, vpcPeerSn, False)\n          Wrapper.print(\"PSD: Unpair VPC\")\n          Util.exe(VpcWrapper.delete(sn))\n\n      Wrapper.print(\"PSD: Delete all PTIs of device and Convert fabric connections to hosts\")\n      PTI.delete(sn)\n      #This is done after PTI delete to ensure Resource for\n      #link subnet after freed up in the end\n      RM.deleteSwitchResources(sn)\n      CDW.clearDeployerHistory(sn)\n\n      if \"super\" in switchRole:\n          spinesWithSuperRole = topologyDataObj.get(TopologyInfoType.SPINES_WITH_SUPER_ROLE)\n          spinesWithSuperRoleCnt = str(len(spinesWithSuperRole) - 1)\n          FabricWrapper.update(Fabric_name, \"SSPINE_COUNT\", spinesWithSuperRoleCnt)\n      elif \"spine\" in switchRole:\n          spines = topologyDataObj.get(TopologyInfoType.SPINES)\n          spinesRoleCnt = str(len(spines) - 1)\n          FabricWrapper.update(Fabric_name, \"SPINE_COUNT\", spinesRoleCnt)\n\n      #If VPC then delete both VPC pair\n      if isVPC and deleteSwitch:\n          InventoryWrapper.removeSwitch(Fabric_name, sn, forceDelete)\n          if \"border gateway\" not in switchRole:\n              #if check and code under it is not needed in 11.5 as not last stage of release\n              #avoiding this case for taking care of vPC BGW Deletion scenarios for the B2B case\n              dictionaryObj.update({\"deviceSerial\":vpcPeerSn})\n              dictionaryObj.update({\"force\":forceDelete})\n              preSwitchDelete(dictionaryObj)\n          InventoryWrapper.removeSwitch(Fabric_name, vpcPeerSn, forceDelete)\n\n      enableMacSec = fabricSettings.get(\"ENABLE_MACSEC\")\n      if enableMacSec == \"true\" and deleteSwitch:\n          devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n          devices = filter(None, devices)\n          devicesLeftCnt = (len(devices) - 2) if isVPC else (len(devices) - 1)\n          if devicesLeftCnt <= 0:\n              jobId = Fabric_name + \"-macsec_oper_status\"\n              reportRespObj = ReportWrapper.getReportJob(jobId)\n              if reportRespObj.isRetCodeSuccess():\n                  Wrapper.print(\"%s(): Delete periodic report for jobId:%s\" % (funcName, jobId))\n                  ReportWrapper.deleteReportJob(jobId)\n\n      if ((not isVPC) and isInbandPoapEnabled(dictObj) == \"true\"): \n          isLocalDhcpEnabled = True if dictObj.get(\"DHCP_ENABLE\", \"false\") == \"true\" else False\n          isNumbered = True if dictObj.get(\"FABRIC_INTERFACE_TYPE\", \"p2p\") == \"p2p\" else False\n          if isLocalDhcpEnabled and isNumbered:\n            # generate all the DHCP scopes and upload to DB\n            Util.exe(PTI.executePyTemplateMethod(\"dhcp_utility\", dictObj, \"dhcpScope\"))     \n\n      return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preSwitchDelete: Serial [%s]. Success = [%r]\" %\n                (Fabric_name, dictionaryObj[\"deviceSerial\"], respObj.isRetCodeSuccess()))\n\ndef configSaveInband(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n\n        #get the whole topology from topology database\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n\n        #Need to pass bootstrapDevices dictionary to configSaveExtnInband\n        dict = getGlobals(dictionaryObj)\n        dict[\"topologyObj\"] = topologyDataObj\n        dict[\"DEVICES\"] = devices\n        #Wrapper.print(\"%s: Updated dictionary is %s\" % (funcName, str(dict)))\n        #Validate fabric setting change\n        Util.exe(PTI.executePyTemplateMethod(\"fabric_utility_11_1\", dict, \"validateFabricSetting\"))\n        \n        processRespObj(respObj, PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dict, \"configSaveExtnInband\"))\n    except Exception as e:\n        if isinstance(e, respObjError):\n            Util.processRespObj(respObj, e.value)\n        else:\n            Util.handleException(\"Unexpected error process inband POAP Bootstrap switch\", e, respObj)\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" %\n                (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n        return respObj\n\ndef configSave(dictionaryObj):\n    global abstract_isis, ISIS_LEVEL, AAA_SERVER_CONF, DNS_SERVER_IP_LIST, NTP_SERVER_IP_LIST, SYSLOG_SERVER_IP_LIST, DNS_SERVER_VRF, NTP_SERVER_VRF, SYSLOG_SEV, SYSLOG_SERVER_VRF\n\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: configSave\" % (FABRIC_NAME))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        Util.exe(actionAllow())\n\n        dcnmUser = dictionaryObj.get(\"dcnmUser\")\n        Util.exe(FabricWrapper.update(FABRIC_NAME, \"dcnmUser\", dcnmUser))\n\n        #get the whole topology from topology database\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n\n        #Valid topology\n        if len(devices) == 0:\n            respObj.addErrorReport(configSave.__name__, \"Fabric %s cannot be deployed without any switches\" % FABRIC_NAME)\n            respObj.setFailureRetCode()\n            return respObj\n\n        # handle a few ISIS specific things for the DCNM 11.0 or 11.1 upgrade\n        if LINK_STATE_ROUTING == 'is-is':\n            # get current fabric settings\n            fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n\n            # Handle inline upgrade from 11.0 or 11.1\n            cur_abstract_isis = fabricSettings['abstract_isis']\n            if cur_abstract_isis == \"base_isis\":\n                Wrapper.print(\"++++++++ configSave: abstract policies have 11_0/1 value, set to 11_2\")\n                # Even though the fabric is operating at level-1 we will set the 'abstract_isis' variable\n                # to 'base_isis_level2'\n                # this vatriable is not used anymore and kept only for backward compatibility\n                abstract_isis = \"base_isis_level2\"\n                Util.exe(FabricWrapper.update(FABRIC_NAME, \"abstract_isis\", abstract_isis))\n\n            # check the presence of the ISIS_LEVEL fabric variable\n            if not ('ISIS_LEVEL' in fabricSettings):\n                Wrapper.print(\"++++++++ configSave: ISIS_LEVEL not found in fabric settings\")\n                # variable does not exist (upgrade case).. set it to 'level-1' since earlier DCNM supported level-1 only\n                ISIS_LEVEL = \"level-1\"\n                Util.exe(FabricWrapper.update(FABRIC_NAME, \"ISIS_LEVEL\", ISIS_LEVEL))\n\n        gVarDictObj = getStrGlobals()\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        upgradeFromVersion = fabricSettings.get(\"UPGRADE_FROM_VERSION\", \"\")\n        isUpgrade = (upgradeFromVersion != \"\")\n        if isUpgrade and upgradeFromVersion in [\"11.5.4\", \"12.1.1e\", \"12.1.2e\", \"12.1.2p\"]:\n            gVarDictObj.update({\"topologyObj\": topologyDataObj})\n            gVarDictObj[\"upgradeFromVersion\"] = upgradeFromVersion\n            gVarDictObj[\"fabricType\"] = \"Switch_Fabric\"\n            gVarDictObj[\"fabricName\"] = FABRIC_NAME\n            FabricWrapper.sendProgress(FABRIC_NAME, \"configSave\", 6, \"One time policies update after upgrade\")\n            Wrapper.print(\"$$$$$$$$$$$$ START PTI REGEN UPGRADE HANDLING [%s] for Fabric [%s] and upgradeFromVersion [%s] $$$$$$$$$\"%\n                          (datetime.datetime.time(datetime.datetime.now()), FABRIC_NAME, upgradeFromVersion))\n            processRespObj(respObj, PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", gVarDictObj, \"handleUpgradeInRecalc\"))\n            if respObj.isRetCodeFailure():\n                return respObj\n            FabricErrorLogger.clear(FABRIC_NAME, Category.Fabric, ET.Fabric, FABRIC_NAME+\":Upgrade\")\n            FabricWrapper.update(FABRIC_NAME, \"UPGRADE_FROM_VERSION\", \"\")\n            FabricWrapper.sendProgress(FABRIC_NAME, \"configSave\", 9, \"Policies update completed\")\n            Wrapper.print(\"$$$$$$$$$$$$ COMPLETED PTI REGEN UPGRADE HANDLING [%s] for Fabric [%s] and upgradeFromVersion [%s] $$$$$$$$$\"%\n                          (datetime.datetime.time(datetime.datetime.now()), FABRIC_NAME, upgradeFromVersion))\n\n        gVarDictObj.update({\"BRFIELD_DEBUG_FLAG\": BRFIELD_DEBUG_FLAG})\n        gVarDictObj.update({\"topologyObj\": topologyDataObj})\n        gVarDictObj.update({\"dcnmUser\": dcnmUser})\n        processRespObj(respObj, PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", gVarDictObj, \"handleUpgradeOrBrownfield\"))\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        if LINK_STATE_ROUTING == \"is-is\":\n            # the ISIS_LEVEL setting could have been updated in handleUpgradeOrBrownfield.. update the variable so that\n            # subsequent code will get the updated value\n            try:\n                ISIS_LEVEL = str(Util.exe(FabricWrapper.get(FABRIC_NAME, \"ISIS_LEVEL\")))\n                Wrapper.print(\"[%s]: configSave: ISIS_LEVEL set to [%s]\" % (FABRIC_NAME, ISIS_LEVEL))\n            finally:\n                pass\n\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        if \"DNS_SERVER_IP_LIST\" in fabricSettings:\n            DNS_SERVER_IP_LIST = str(fabricSettings[\"DNS_SERVER_IP_LIST\"])\n        if \"NTP_SERVER_IP_LIST\" in fabricSettings:\n            NTP_SERVER_IP_LIST = str(fabricSettings[\"NTP_SERVER_IP_LIST\"])\n        if \"SYSLOG_SERVER_IP_LIST\" in fabricSettings:\n            SYSLOG_SERVER_IP_LIST = str(fabricSettings[\"SYSLOG_SERVER_IP_LIST\"])\n        if \"DNS_SERVER_VRF\" in fabricSettings:\n            DNS_SERVER_VRF = str(fabricSettings[\"DNS_SERVER_VRF\"])\n        if \"NTP_SERVER_VRF\" in fabricSettings:\n            NTP_SERVER_VRF = str(fabricSettings[\"NTP_SERVER_VRF\"])\n        if \"SYSLOG_SEV\" in fabricSettings:\n            SYSLOG_SEV = str(fabricSettings[\"SYSLOG_SEV\"])\n        if \"SYSLOG_SERVER_VRF\" in fabricSettings:\n            SYSLOG_SERVER_VRF = str(fabricSettings[\"SYSLOG_SERVER_VRF\"])\n                 \n        #Validate fabric setting change\n        dictObj = getStrGlobals()\n        dictObj.update({\"DEVICES\": devices})\n        dictObj.update({\"topologyObj\": topologyDataObj})\n        Util.exe(PTI.executePyTemplateMethod(\"fabric_utility_11_1\", dictObj, \"validateFabricSetting\"))\n\n        dict = getGlobals()\n        dict[\"topologyObj\"] = topologyDataObj\n        processRespObj(respObj, PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dict, \"configSaveExtn\"))\n        Util.exe(Util.topDownRmTrackingRqrd(FABRIC_NAME, devices))\n        Wrapper.print(\"configSave: after calling configSaveExtn\")\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: configSave: Success = [%r]\" %\n                (FABRIC_NAME, respObj.isRetCodeSuccess()))\n\ndef processRespObj(respObj, newResp):\n    Wrapper.print(\"processRespObj: respObj isSuccess [%r] newResp isSuccess [%r]\" % (respObj.isRetCodeSuccess(), newResp.isRetCodeSuccess()))\n    errs = newResp.getErrorList()\n    if (errs != None):\n        if not respObj.isRetCodeFailure():\n            # since there is a valid error list.. we assume the retcode is a non-success error code\n            respObj.setRetCode(newResp.getRetCode())\n        list = respObj.getErrorList()\n        if (list != None):\n            Wrapper.print(\"processRespObj: Found %d error entries. Adding %d more\" % (len(list), len(errs)))\n        else:\n            Wrapper.print(\"processRespObj: Adding %d entries\" % len(errs))\n            list = []\n\n        for err in errs:\n            list.append(err)\n        respObj.setErrorList(list)\n    if newResp.isResolve() == True:\n        respObj.setResolve(newResp.isResolve())\n        respObj.setResolveId(newResp.getResolveId())\n        resolvePayload = {}\n        respObj.setResolvePayload(newResp.getResolvePayload())\n        \n    Wrapper.print(\"processRespObj: After respObj isSuccess [%r]\" % (respObj.isRetCodeSuccess()))\n\ndef getFormattedSwitchName(serialNum):\n    formattedStr = serialNum\n    hostName = InventoryWrapper.getHostNameString(serialNum)\n    if hostName:\n        formattedStr += (\"/\" + hostName)\n    return formattedStr\n\ndef cleanupLeafTorAssoc(leafSn, pairingSns):\n    try:\n        funcName = sys._getframe(0).f_code.co_name\n        Wrapper.print(\"%s(): leafSn:[%s] pairingSns:%s\" % (funcName, leafSn, pairingSns))\n\n        vpcPeerProcessedList = []\n        for torSn in pairingSns:\n            if torSn in vpcPeerProcessedList:\n                continue\n            leafVpcPeerSn = torVpcPeerSn = torVpcPairSerialKey = \"\"\n            isTorVpc = Util.exe(VpcWrapper.isVpc(FABRIC_NAME, torSn))\n            if isTorVpc:\n                torVpcPairSerialKey = Util.exe(VpcWrapper.get(VPCMetaDataType.VPC_PAIR, FABRIC_NAME, torSn))\n                serials = torVpcPairSerialKey.split(Helper.DELIMITER)\n                torVpcPeerSn = serials[0] if serials[1] == torSn else serials[1]\n                leafSns = Util.exe(ToRWrapper.getTorAssociation(torVpcPairSerialKey))\n                vpcPeerProcessedList.append(torVpcPeerSn)\n            else:\n                leafSns = Util.exe(ToRWrapper.getTorAssociation(torSn))\n\n            if not leafSns:\n                Wrapper.print(\"%s(): No leaf-tor pairing found for the tor\" % torSn)\n                continue\n\n            if len(leafSns) == 2:\n                leafVpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, FABRIC_NAME, leafSn))\n\n            Wrapper.print(\"%s(): Calling deleteLeafToR() leafSn %s leafVpcPeerSn %s torSn %s torVpcPeerSn %s\" %\n                          (funcName, leafSn, leafVpcPeerSn, torSn, torVpcPeerSn))\n            Util.exe(ToRWrapper.deleteLeafToR(leafSn, leafVpcPeerSn, torSn, torVpcPeerSn))\n\n        respObj = WrappersResp.getRespObj()\n        respObj.setSuccessRetCode()\n        return respObj\n\n    except respObjError as e:\n        return e.value\n\ndef validateInterfabricDelete(serial_number, forceDelete):\n    Wrapper.print(\"==========ACTION: Serial Number [%s] : Start: validateInterfabricDelete with forceDelete [%s]\" % (serial_number, forceDelete))\n    try:\n        respObj = WrappersResp.getRespObj()\n        respObj.setSuccessRetCode()\n\n        wResp = InterfabricConnectionWrapper.listInterfabrics(serial_number)\n        if wResp.isRetCodeSuccess():\n            Wrapper.print(\"validateInterfabricDelete: Incoming IFC links to: [%s]\" % (serial_number))\n            interfabric_list = wResp.getValue()\n        else:\n            Wrapper.print(\"validateInterfabricDelete: Error hit in get Incoming IFC links for [%s]: \" %(serial_number))\n            return wResp\n        \n        if forceDelete:\n            for ifc in interfabric_list:\n                Wrapper.print(\"validateInterfabricDelete: IFC links for [%s]: ifc [%s]\" %(serial_number, ifc))\n                srcSn = ifc[\"source_switch_sn\"]\n                dstSn = ifc[\"dest_switch_sn\"]\n                Util.exe(Util.deleteExtensions(srcSn, dstSn))\n\n        for ifc in interfabric_list:\n            if ifc[\"extension_type\"] == \"VRF_LITE\" or ifc[\"extension_type\"] == \"VXLAN_MPLS_OVERLAY\":\n                Wrapper.print(\"validateInterfabricDelete: Processing IFC ID %s\" %(ifc[\"interfabricId\"]))\n                extension_id = int(ifc[\"interfabricId\"])\n                ifc_extension_exists = Util.exe(InterfabricConnectionWrapper.checkIFCExtensions(extension_id))\n\n                if ifc_extension_exists:\n                    srcSwitchStr = getFormattedSwitchName(ifc[\"source_switch_sn\"])\n                    destSwitchStr = getFormattedSwitchName(ifc[\"dest_switch_sn\"])\n\n                    errorMsg = (\"Failed to delete switch. Overlays are extended for interfabric link [%s] [%s]<-->[%s] [%s]\"\n                                %(srcSwitchStr, ifc[\"source_if_name\"], destSwitchStr, ifc[\"dest_if_name\"]))\n                    respObj.addErrorReport((\"InterFabricLink\"), errorMsg, serial_number)\n                    respObj.setFailureRetCode()\n                    return respObj\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n\n    finally:\n        Wrapper.print(\"==========ACTION: SN [%s]: Finish: validateInterfabricDelete: Success = [%r]\" % \\\n                (serial_number, respObj.isRetCodeSuccess()))\n##\n#\n",
    "newContent": "##template properties\nname =Easy_Fabric;\ndescription = Fabric for a VXLAN EVPN deployment with Nexus 9000 and 3000 switches.;\ntags =Data Center VXLAN EVPN;\nuserDefined = true;\nsupportedPlatforms = All;\ntemplateType = FABRIC;\ntemplateSubType = NA;\ncontentType = PYTHON;\nimplements = ;\ndependencies = ;\npublished = false;\nimports = ;\n##\n##template variables\n\n#    Copyright (c) 2018-2023 by Cisco Systems, Inc.\n#    All rights reserved.\n#General\n@(IsMandatory=true, IsFabricName=true, DisplayName=\"Fabric Name\", Description=\"Please provide the fabric name to create it (Max Size 32)\")\nstring FABRIC_NAME{\n  minLength = 1;\n  maxLength = 32;\n};\n\n@(IsMandatory=true, IsAsn=true, Description=\"1-4294967295 | 1-65535[.0-65535]<br/>It is a good practice to have a unique ASN for each Fabric.\", DisplayName=\"BGP ASN\")\nstring BGP_AS{\nminLength=1;\nmaxLength=11;\nregularExpr=^(((\\+)?[1-9]{1}[0-9]{0,8}|(\\+)?[1-3]{1}[0-9]{1,9}|(\\+)?[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])(\\.([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]|0))?)$;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring BGP_AS_PREV;\n\n@(IsMandatory=false, DisplayName=\"Enable IPv6 Underlay\", Description=\"If not enabled, IPv4 underlay is used\")\nboolean UNDERLAY_IS_V6\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==true\", DisplayName=\"Enable IPv6 Link-Local Address\",\nDescription=\"If not enabled, Spine-Leaf interfaces will use global IPv6 addresses\")\nboolean USE_LINK_LOCAL\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=true, Enum=\"p2p,unnumbered\", IsShow=\"UNDERLAY_IS_V6!=true\", DisplayName=\"Fabric Interface Numbering\", Description=\"Numbered(Point-to-Point) or Unnumbered\")\nstring FABRIC_INTERFACE_TYPE\n{\ndefaultValue=p2p;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false\", Enum=\"30,31\", Description=\"Mask for Underlay Subnet IP Range\", DisplayName=\"Underlay Subnet IP Mask\")\ninteger SUBNET_TARGET_MASK\n{\nmin = 30;\nmax = 31;\ndefaultValue=30;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && USE_LINK_LOCAL==false\", Enum=\"126,127\", Description=\"Mask for Underlay Subnet IPv6 Range\", DisplayName=\"Underlay Subnet IPv6 Mask\")\ninteger V6_SUBNET_TARGET_MASK\n{\nmin = 126;\nmax = 127;\ndefaultValue=126;\n};\n\n@(IsMandatory=true, Enum=\"ospf,is-is\", DisplayName=\"Underlay Routing Protocol\", Description=\"Used for Spine-Leaf Connectivity\")\nstring LINK_STATE_ROUTING\n{\ndefaultValue=ospf;\n};\n\n@(IsMandatory=true, Enum=\"2,4\", Description=\"Number of spines acting as Route-Reflectors\", DisplayName=\"Route-Reflectors\")\ninteger RR_COUNT\n{\ndefaultValue=2;\n};\n@(IsMandatory=true, IsAnycastGatewayMac=true, Description=\"Shared MAC address for all leafs (xxxx.xxxx.xxxx)\", DisplayName=\"Anycast Gateway MAC\")\nmacAddress ANYCAST_GW_MAC\n{\ndefaultValue=2020.0000.00aa;\n};\n\n@(IsMandatory=false, NoConfigChg=true, DisplayName=\"Enable Performance Monitoring\")\nboolean PM_ENABLE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean PM_ENABLE_PREV\n{\ndefaultValue=false;\n};\n\n#Multicast Replication\n@(IsMandatory=true, Enum=\"Multicast,Ingress\", IsReplicationMode=true, IsShow=\"UNDERLAY_IS_V6!=true\", Description=\"Replication Mode for BUM Traffic\", DisplayName=\"Replication Mode\", Section=\"Replication\")\nstring REPLICATION_MODE\n{\ndefaultValue=Multicast;\n};\n\n@(IsMandatory=true, IsMulticastGroupSubnet=true,\nIsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Description=\"Multicast pool prefix between 8 to 30. A multicast group IP<br/>from this pool is used for BUM traffic for each overlay network.\", DisplayName=\"Multicast Group Subnet\", Section=\"Replication\")\nipV4AddressWithSubnet MULTICAST_GROUP_SUBNET\n{\ndefaultValue=239.1.1.0/25;\n};\n\n@(IsMandatory=false, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Description=\"For Overlay Multicast Support In VXLAN Fabrics\", DisplayName=\"Enable Tenant Routed Multicast (TRM)\", Section=\"Replication\")\nboolean ENABLE_TRM\n{\ndefaultValue=false;\n};\n\n\n@(IsMandatory=true, IsMcastUnderlay=true,\nIsShow=\"REPLICATION_MODE==Multicast && ENABLE_TRM==true && UNDERLAY_IS_V6!=true\", DisplayName=\"Default MDT Address for TRM VRFs\", Description=\"Default Underlay Multicast group IP assigned for every overlay VRF.\", Section=\"Replication\")\nipV4Address L3VNI_MCAST_GROUP\n{\ndefaultValue=239.1.1.0;\n};\n\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Enum=\"2,4\", Description=\"Number of spines acting as Rendezvous-Point (RP)\", DisplayName=\"Rendezvous-Points\", Section=\"Replication\")\ninteger RP_COUNT\n{\ndefaultValue=2;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Enum=\"asm,bidir\", Description=\"Multicast RP Mode\", DisplayName=\"RP Mode\", Section=\"Replication\")\nstring RP_MODE\n{\ndefaultValue=asm;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6!=true\", Description=\"(Min:0, Max:1023)\", DisplayName=\"Underlay RP Loopback Id\", Section=\"Replication\")\ninteger RP_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=254;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && UNDERLAY_IS_V6!=true\", Description=\"Used for Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Primary <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID1{\nmin=0;\nmax=1023;\ndefaultValue=2;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && UNDERLAY_IS_V6!=true\", Description=\"Used for Fallback Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Backup <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID2{\nmin=0;\nmax=1023;\ndefaultValue=3;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && RP_COUNT==4 && UNDERLAY_IS_V6!=true\", Description=\"Used for second Fallback Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Second Backup <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID3{\nmin=0;\nmax=1023;\ndefaultValue=4;\n};\n\n@(IsMandatory=true, IsShow=\"REPLICATION_MODE==Multicast && RP_MODE==bidir && RP_COUNT==4 && UNDERLAY_IS_V6!=true\", Description=\"Used for third Fallback Bidir-PIM Phantom RP <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay Third Backup <br/>RP Loopback Id\", Section=\"Replication\")\ninteger PHANTOM_RP_LB_ID4{\nmin=0;\nmax=1023;\ndefaultValue=5;\n};\n\n#vPC\n@(IsMandatory=true, Description=\"VLAN range for vPC Peer Link SVI (Min:2, Max:4094)\", DisplayName=\"vPC Peer Link VLAN Range\", Section=\"vPC\")\nintegerRange VPC_PEER_LINK_VLAN\n{\nmin=2;\nmax=4094;\ndefaultValue=3600;\n};\n\n@(IsMandatory=false, DisplayName=\"Make vPC Peer Link VLAN as Native VLAN\", Section=\"vPC\")\nboolean ENABLE_VPC_PEER_LINK_NATIVE_VLAN\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, Enum=\"loopback,management\", Description=\"Use vPC Peer Keep Alive with Loopback or Management\", DisplayName=\"vPC Peer Keep Alive option\", Section=\"vPC\")\nstring VPC_PEER_KEEP_ALIVE_OPTION\n{\ndefaultValue=management;\n};\n\n@(IsMandatory=true, Description=\"(Min:240, Max:3600)\", DisplayName=\"vPC Auto Recovery Time <br/>(In Seconds)\", Section=\"vPC\")\ninteger VPC_AUTO_RECOVERY_TIME\n{\nmin = 240;\nmax = 3600;\ndefaultValue=360;\n};\n\n@(IsMandatory=true, Description=\"(Min:1, Max:3600)\", DisplayName=\"vPC Delay Restore Time <br/>(In Seconds)\", Section=\"vPC\")\ninteger VPC_DELAY_RESTORE\n{\nmin = 1;\nmax = 3600;\ndefaultValue=150;\n};\n\n@(IsMandatory=false, Description=\"(Min:1, Max:4096)\", DisplayName=\"vPC Peer Link Port Channel ID\", Section=\"vPC\")\nintegerRange VPC_PEER_LINK_PO\n{\nmin=1;\nmax=4096;\ndefaultValue=500;\n};\n\n@(IsMandatory=false, Description=\"Enable IPv6 ND synchronization between vPC peers\", DisplayName=\"vPC IPv6 ND Synchronize\", Section=\"vPC\")\nboolean VPC_ENABLE_IPv6_ND_SYNC\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, Description=\"For Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes\", DisplayName=\"vPC advertise-pip\", Section=\"vPC\")\nboolean ADVERTISE_PIP_BGP\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"ADVERTISE_PIP_BGP!=true\", Description=\"Enable advertise-pip on vPC borders and border gateways only. Applicable only when vPC advertise-pip is not enabled\", DisplayName=\"vPC advertise-pip on Border only\", Section=\"vPC\")\nboolean ADVERTISE_PIP_ON_BORDER\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, Description=\"(Not Recommended) \", DisplayName=\"Enable the same vPC Domain Id <br/>for all vPC Pairs\", Section=\"vPC\")\nboolean ENABLE_FABRIC_VPC_DOMAIN_ID\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ENABLE_FABRIC_VPC_DOMAIN_ID_PREV;\n\n@(IsMandatory=true, IsShow=\"ENABLE_FABRIC_VPC_DOMAIN_ID==true\", Description=\"vPC Domain Id to be used on all vPC pairs\", DisplayName=\"vPC Domain Id\", Section=\"vPC\")\ninteger FABRIC_VPC_DOMAIN_ID\n{\nmin = 1;\nmax = 1000;\ndefaultValue=1;\n};\n\n@(IsMandatory=false, DisplayName=\"Internal Fabric Wide vPC Domain Id\", IsInternal=true)\ninteger FABRIC_VPC_DOMAIN_ID_PREV\n{\nmin = 1;\nmax = 1000;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_FABRIC_VPC_DOMAIN_ID==false\", Description=\"vPC Domain id range to use for new pairings\", DisplayName=\"vPC Domain Id Range\", Section=\"vPC\")\nintegerRange VPC_DOMAIN_ID_RANGE\n{\nmin=1;\nmax=1000;\ndefaultValue=1-1000;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==false\", Description=\"Qos on spines for guaranteed delivery of vPC Fabric Peering communication\", DisplayName=\"Enable Qos for Fabric vPC-Peering\", Section=\"vPC\")\nboolean FABRIC_VPC_QOS\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"FABRIC_VPC_QOS==true\", Description=\"Qos Policy name should be same on all spines\", DisplayName=\"Qos Policy Name\", Section=\"vPC\")\nstring FABRIC_VPC_QOS_POLICY_NAME\n{\nminLength = 1;\nmaxLength = 40;\ndefaultValue=spine_qos_for_fabric_vpc_peering;\n};\n\n#Protocols\n\n@(IsMandatory=true, Description=\"(Min:0, Max:1023)\", DisplayName=\"Underlay Routing Loopback Id\", Section=\"Protocols\")\ninteger BGP_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=0;\n};\n\n@(IsMandatory=true, Description=\"(Min:0, Max:1023)\", DisplayName=\"Underlay VTEP Loopback Id\", Section=\"Protocols\")\ninteger NVE_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=1;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true\", Description=\"Used for vPC Peering in VXLANv6 Fabrics (Min:0, Max:1023)\", DisplayName=\"Underlay Anycast Loopback Id\", Section=\"Protocols\")\ninteger ANYCAST_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=10;\n};\n\n@(IsMandatory=true, DisplayName=\"Underlay Routing Protocol Tag\", Description=\"Underlay Routing Process Tag\", Section=\"Protocols\")\nstring LINK_STATE_ROUTING_TAG\n{\nminLength = 1;\nmaxLength = 20;\ndefaultValue=UNDERLAY;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring LINK_STATE_ROUTING_TAG_PREV;\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==ospf\", DisplayName=\"OSPF Area Id\", Description=\"OSPF Area Id in IP address format\", Section=\"Protocols\")\nstring OSPF_AREA_ID\n{\nminLength = 1;\nmaxLength = 15;\ndefaultValue=0.0.0.0;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==ospf && UNDERLAY_IS_V6==false\", DisplayName=\"Enable OSPF Authentication\", Section=\"Protocols\")\nboolean OSPF_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==ospf && OSPF_AUTH_ENABLE==true\", DisplayName=\"OSPF Authentication Key ID\", Description=\"(Min:0, Max:255)\", Section=\"Protocols\")\ninteger OSPF_AUTH_KEY_ID\n{\nmin = 0;\nmax = 255;\ndefaultValue = 127;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==ospf && OSPF_AUTH_ENABLE==true\", DisplayName=\"OSPF Authentication Key\", Description=\"3DES Encrypted\", Section=\"Protocols\")\nstring OSPF_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 256;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is\", Enum=\"level-1,level-2\", DisplayName=\"IS-IS Level\", Description=\"Supported IS types: level-1, level-2\", Section=\"Protocols\")\nstring ISIS_LEVEL\n{\ndefaultValue=level-2;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==is-is\", DisplayName=\"Enable IS-IS Network Point-to-Point\", Description=\"This will enable network point-to-point on fabric interfaces which are numbered\", Section=\"Protocols\")\nboolean ISIS_P2P_ENABLE\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==is-is && UNDERLAY_IS_V6==false\", DisplayName=\"Enable IS-IS Authentication\", Section=\"Protocols\")\nboolean ISIS_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\", DisplayName=\"IS-IS Authentication Keychain Name\", Section=\"Protocols\")\nstring ISIS_AUTH_KEYCHAIN_NAME\n{\nminLength = 1;\nmaxLength = 63;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\", DisplayName=\"IS-IS Authentication Key ID\", Description=\"(Min:0, Max:65535)\", Section=\"Protocols\")\ninteger ISIS_AUTH_KEYCHAIN_KEY_ID\n{\nmin = 0;\nmax = 65535;\ndefaultValue = 127;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_AUTH_ENABLE==true\", DisplayName=\"IS-IS Authentication Key\", Description=\"Cisco Type 7 Encrypted\", Section=\"Protocols\")\nstring ISIS_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 255;\n};\n\n@(IsMandatory=false, IsShow=\"LINK_STATE_ROUTING==is-is\", DisplayName=\"Set IS-IS Overload Bit\", Description=\"When enabled, set the overload bit for an elapsed time after a reload\", Section=\"Protocols\")\nboolean ISIS_OVERLOAD_ENABLE\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=true, IsShow=\"LINK_STATE_ROUTING==is-is && ISIS_OVERLOAD_ENABLE==true\", DisplayName=\"IS-IS Overload Bit Elapsed Time\", Description=\"Clear the overload bit after an elapsed time in seconds\", Section=\"Protocols\")\ninteger ISIS_OVERLOAD_ELAPSE_TIME\n{\nmin = 5;\nmax = 86400;\ndefaultValue=60;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", DisplayName=\"Enable BGP Authentication\", Section=\"Protocols\")\nboolean BGP_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, Enum=\"3,7\", IsShow=\"BGP_AUTH_ENABLE==true\", DisplayName=\"BGP Authentication Key <br/>Encryption Type\", Description=\"BGP Key Encryption Type: 3 - 3DES, 7 - Cisco\", Section=\"Protocols\")\nstring BGP_AUTH_KEY_TYPE {\ndefaultValue=3;\n};\n\n@(IsMandatory=true, IsShow=\"BGP_AUTH_ENABLE==true\", DisplayName=\"BGP Authentication Key\", Description=\"Encrypted BGP Authentication Key based on type\", Section=\"Protocols\")\nstring BGP_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 256;\n};\n\n@(IsMandatory=false, IsShow=\"REPLICATION_MODE==Multicast && UNDERLAY_IS_V6==false\", DisplayName=\"Enable PIM Hello Authentication\", Description=\"Valid for IPv4 Underlay only\", Section=\"Protocols\")\nboolean PIM_HELLO_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"PIM_HELLO_AUTH_ENABLE==true\", DisplayName=\"PIM Hello Authentication Key\", Description=\"3DES Encrypted\", Section=\"Protocols\")\nstring PIM_HELLO_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 256;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", DisplayName=\"Enable BFD\", Description=\"Valid for IPv4 Underlay only\", Section=\"Protocols\")\nboolean BFD_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true\", DisplayName=\"Enable BFD For iBGP\", Section=\"Protocols\")\nboolean BFD_IBGP_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && LINK_STATE_ROUTING==ospf\", DisplayName=\"Enable BFD For OSPF\", Section=\"Protocols\")\nboolean BFD_OSPF_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && LINK_STATE_ROUTING==is-is\", DisplayName=\"Enable BFD For ISIS\", Section=\"Protocols\")\nboolean BFD_ISIS_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && REPLICATION_MODE==Multicast\", DisplayName=\"Enable BFD For PIM\", Section=\"Protocols\")\nboolean BFD_PIM_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false && FABRIC_INTERFACE_TYPE==p2p && BFD_ENABLE==true\", DisplayName=\"Enable BFD Authentication\", Description=\"Valid for P2P Interfaces only\", Section=\"Protocols\")\nboolean BFD_AUTH_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && FABRIC_INTERFACE_TYPE==p2p && BFD_AUTH_ENABLE==true\", DisplayName=\"BFD Authentication Key ID\", Section=\"Protocols\")\ninteger BFD_AUTH_KEY_ID\n{\nmin = 1;\nmax = 255;\ndefaultValue = 100;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && BFD_ENABLE==true && FABRIC_INTERFACE_TYPE==p2p && BFD_AUTH_ENABLE==true\", DisplayName=\"BFD Authentication Key\", Description=\"Encrypted SHA1 secret value\", Section=\"Protocols\")\nstring BFD_AUTH_KEY\n{\nminLength = 1;\nmaxLength = 40;\n};\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"iBGP Peer-Template Config\", Description=\"Speficies the iBGP Peer-Template config used for RR and<br/>spines with border role. \", Warning=\"Speficies the config used for RR and<br/> spines with border or border gateway role. <br/> This field should begin with<br/>'  template peer' or '  template peer-session'. <br/> This must have 2 leading spaces. <br/>Note ! All configs should <br/>strictly match show run output, <br/>with respect to case and newlines. <br/>Any mismatches will yield <br/>unexpected diffs during deploy.\", Section=\"Protocols\")\nstring IBGP_PEER_TEMPLATE;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Leaf/Border/Border Gateway<br/>iBGP Peer-Template Config \", Description=\"Specifies the config used for leaf, border or<br/> border gateway.<br/>If this field is empty, the peer template defined in<br/>iBGP Peer-Template Config is used on all BGP enabled devices<br/>(RRs,leafs, border or border gateway roles.\", Warning=\"Specifies the config used for leaf, border or<br/> border gateway.<br/>If this field is empty, the peer template defined in<br/>iBGP Peer-Template Config is used on all BGP<br/>enabled devices (RRs, leafs,<br/> border or border gateway roles).<br/>This field should begin with<br/>'  template peer' or '  template peer-session'.<br/> This must have 2 leading spaces. <br/>Note ! All configs should <br/>strictly match 'show run' output, <br/>with respect to case and newlines. <br/>Any mismatches will yield <br/>unexpected diffs during deploy.\", Section=\"Protocols\")\nstring IBGP_PEER_TEMPLATE_LEAF;\n\n#Advanced\n@(IsMandatory=true, IsVrfTemplate=true, Enum=\"%TEMPLATES.vrf\", Description=\"Default Overlay VRF Template For Leafs\", DisplayName=\"VRF Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring default_vrf\n{\ndefaultValue=Default_VRF_Universal;\n};\n\n@(IsMandatory=true, IsNetworkTemplate=true, Enum=\"%TEMPLATES.network\", Description=\"Default Overlay Network Template For Leafs\", DisplayName=\"Network Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring default_network\n{\ndefaultValue=Default_Network_Universal;\n};\n\n@(IsMandatory=true, IsVrfExtensionTemplate=true, Enum=\"%TEMPLATES.vrfExtension\", Description=\"Default Overlay VRF Template For Borders\", DisplayName=\"VRF Extension Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring vrf_extension_template\n{\ndefaultValue=Default_VRF_Extension_Universal;\n};\n\n@(IsMandatory=true, IsNetworkExtensionTemplate=true, Enum=\"%TEMPLATES.networkExtension\", Description=\"Default Overlay Network Template For Borders\", DisplayName=\"Network Extension Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring network_extension_template\n{\ndefaultValue=Default_Network_Extension_Universal;\n};\n\n@(IsMandatory=false, DisplayName=\"Overlay Mode\", Description=\"VRF/Network configuration using config-profile or CLI\", Section=\"Advanced\")\nenum OVERLAY_MODE\n{\nvalidValues=config-profile,cli;\ndefaultValue=cli;\n};\n\n@(IsMandatory=false, IsInternal=true)\nenum OVERLAY_MODE_PREV\n{\nvalidValues=config-profile,cli;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Private VLAN (PVLAN)\", Description=\"Enable PVLAN on switches except spines and super spines\", Section=\"Advanced\")\nboolean ENABLE_PVLAN {\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ENABLE_PVLAN_PREV;\n\n@(IsMandatory=\"ENABLE_PVLAN==true\", IsShow=\"ENABLE_PVLAN==true\", IsPvlanSecNetworkTemplate=true, IsPvlanSecNetworkExtTemplate=true, Enum=\"%TEMPLATES.pvlanSecNetwork\", Description=\"Default PVLAN Secondary Network Template\", DisplayName=\"PVLAN Secondary Network Template\", AlwaysSetDefault=true, Section=\"Advanced\")\nstring default_pvlan_sec_network\n{\ndefaultValue=Pvlan_Secondary_Network;\n};\n\n@(IsMandatory=false, IsSiteId=true,AutoPopulate=\"BGP_AS\", Description=\"For EVPN Multi-Site Support (Min:1, Max: 281474976710655). <br/>Defaults to Fabric ASN\", DisplayName=\"Site Id\", Section=\"Advanced\")\nstring SITE_ID\n{\nminLength=1;\nmaxLength=15;\nregularExpr=^(((\\+)?[1-9]{1}[0-9]{0,13}|(\\+)?[1]{1}[0-9]{1,14}|(\\+)?[2]{1}([0-7]{1}[0-9]{13}|[8]{1}([0-0]{1}[0-9]{12}|[1]{1}([0-3]{1}[0-9]{11}|[4]{1}([0-6]{1}[0-9]{10}|[7]{1}([0-3]{1}[0-9]{9}|[4]{1}([0-8]{1}[0-9]{8}|[9]{1}([0-6]{1}[0-9]{7}|[7]{1}([0-5]{1}[0-9]{6}|[6]{1}([0-6]{1}[0-9]{5}|[7]{1}([0-0]{1}[0-9]{4}|[1]{1}([0]{0}[0-9]{3}|[0]{1}([0-5]{1}[0-9]{2}|[6]{1}([0-4]{1}[0-9]{1}|[5]{1}[0-5]{1}))))))))))))))|([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])(\\.([1-5]\\d{4}|[1-9]\\d{0,3}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]|0))?)$;\n};\n\n\n\n@(IsMandatory=true, IsMTU=true, Description=\"(Min:576, Max:9216). Must be an even number\", DisplayName=\"Intra Fabric Interface MTU\", Section=\"Advanced\")\ninteger FABRIC_MTU\n{\nmin = 576;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger FABRIC_MTU_PREV\n{\nmin = 576;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=true, IsMTU=true, Description=\"(Min:1500, Max:9216). Must be an even number\", DisplayName=\"Layer 2 Host Interface MTU\", Section=\"Advanced\")\ninteger L2_HOST_INTF_MTU\n{\nmin = 1500;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger L2_HOST_INTF_MTU_PREV\n{\nmin = 1500;\nmax = 9216;\ndefaultValue=9216;\n};\n\n@(IsMandatory=false, DisplayName=\"Unshut Host Interfaces by Default\", Section=\"Advanced\")\nboolean HOST_INTF_ADMIN_STATE {\ndefaultValue=true;\n};\n\n@(IsMandatory=true, Enum=\"ps-redundant,combined,insrc-redundant\", Description=\"Default Power Supply Mode For The Fabric\", DisplayName=\"Power Supply Mode\", Section=\"Advanced\")\nstring POWER_REDUNDANCY_MODE\n{\ndefaultValue=ps-redundant;\n};\n\n@(IsMandatory=true, Enum=\"dense,lenient,moderate,strict,manual\", Description=\"Fabric Wide CoPP Policy. Customized CoPP policy should be <br/> provided when 'manual' is selected\", DisplayName=\"CoPP Profile\", Section=\"Advanced\")\nstring COPP_POLICY\n{\ndefaultValue=strict;\n};\n\n@(IsMandatory=false, Description=\"NVE Source Inteface HoldDown Time (Min:1, Max:1500) in seconds\", DisplayName=\"VTEP HoldDown Time\", Section=\"Advanced\")\ninteger HD_TIME{\nmin = 1;\nmax = 1500;\ndefaultValue=180;\n};\n\n@(IsMandatory=false, DisplayName=\"Brownfield Overlay Network Name <br/>Format\", Description=\"Generated network name should be < 64 characters\", Section=\"Advanced\")\nstring BROWNFIELD_NETWORK_NAME_FORMAT\n{\nminLength = 1;\nmaxLength = 80;\ndefaultValue=Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$;\n};\n\n@(IsMandatory=false, DisplayName=\"Skip Overlay Network Interface Attachments\", Description=\"Enable to skip overlay network interface attachments for Brownfield and Host Port Resync cases\", Section=\"Advanced\")\nboolean BROWNFIELD_SKIP_OVERLAY_NETWORK_ATTACHMENTS\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable CDP for Bootstrapped Switch\", Description=\"Enable CDP on management interface\", Section=\"Advanced\")\nboolean CDP_ENABLE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable VXLAN OAM\", Section=\"Advanced\", Description=\"Enable the Next Generation (NG) OAM feature for all switches in the fabric to aid in trouble-shooting VXLAN EVPN fabrics\")\nboolean ENABLE_NGOAM\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Tenant DHCP\", Section=\"Advanced\")\nboolean ENABLE_TENANT_DHCP\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable NX-API\", Description=\"Enable HTTPS NX-API\", Section=\"Advanced\")\nboolean ENABLE_NXAPI\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_NXAPI==true\", DisplayName=\"NX-API HTTPS Port Number\", Section=\"Advanced\")\ninteger NXAPI_HTTPS_PORT\n{\nmin = 1;\nmax = 65535;\ndefaultValue=443;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_NXAPI==true\", DisplayName=\"Enable HTTP NX-API\", Section=\"Advanced\")\nboolean ENABLE_NXAPI_HTTP\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"ENABLE_NXAPI_HTTP==true\", DisplayName=\"NX-API HTTP Port Number\", Section=\"Advanced\")\ninteger NXAPI_HTTP_PORT\n{\nmin = 1;\nmax = 65535;\ndefaultValue=80;\n};\n\n@(IsMandatory=false, DisplayName=\"Elastic Services Re-direction (ESR) Options\", Description=\"Policy-Based Routing (PBR) or Enhanced PBR (ePBR)\", NoConfigChg=true, Section=\"Advanced\")\nenum ESR_OPTION {\n  validValues=ePBR,PBR;\n  defaultValue=PBR;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Policy-Based Routing (PBR)/Enhanced PBR (ePBR)\", Description=\"When ESR option is ePBR, enable ePBR will enable pbr, sla sender and epbr features on the switch\", Section=\"Advanced\")\nboolean ENABLE_PBR {\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable Strict Config Compliance\", Section=\"Advanced\", Description=\"Enable bi-directional compliance checks to flag additional configs in the running config that are not in the intent/expected config\")\nboolean STRICT_CC_MODE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, Description=\"Enable only, when IP Authorization is enabled in the AAA Server\", DisplayName=\"Enable AAA IP Authorization\", Section=\"Advanced\")\nboolean AAA_REMOTE_IP_ENABLED\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable NDFC as Trap Host\", Section=\"Advanced\", Description=\"Configure NDFC as a receiver for SNMP traps\")\nboolean SNMP_SERVER_HOST_TRAP\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, DisplayName=\"Anycast Border Gateway advertise-pip\", Section=\"Advanced\", Description=\"To advertise Anycast Border Gateway PIP as VTEP. Effective on MSD fabric 'Recalculate Config'\")\nboolean ANYCAST_BGW_ADVERTISE_PIP\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsFreezeMode=true, DisplayName=\"Disable all deployments in this fabric\", Section=\"Hidden\")\nboolean DEPLOYMENT_FREEZE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true,Enum=\"Enable,Disable\", IsShow=\"AAA_REMOTE_IP_ENABLED==false\", Description=\"Enable to clean switch configuration without reload when PreserveConfig=no\", DisplayName=\"Greenfield Cleanup Option\", Section=\"Advanced\")\nstring GRFIELD_DEBUG_FLAG\n{\ndefaultValue=Disable;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6!=true\", DisplayName=\"Enable Precision Time Protocol (PTP)\", Section=\"Advanced\")\nboolean FEATURE_PTP {\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"FEATURE_PTP==true\", Description=\"(Min:0, Max:1023)\", DisplayName=\"PTP Source Loopback Id\", Section=\"Advanced\")\ninteger PTP_LB_ID\n{\nmin = 0;\nmax = 1023;\ndefaultValue=0;\n};\n\n@(IsMandatory=true, IsShow=\"FEATURE_PTP==true\", Description=\"Multiple Independent PTP Clocking Subdomains <br/>on a Single Network (Min:0, Max:127)\", DisplayName=\"PTP Domain Id\", Section=\"Advanced\")\ninteger PTP_DOMAIN_ID\n{\nmin = 0;\nmax = 127;\ndefaultValue=0;\n};\n\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", DisplayName=\"Enable MPLS Handoff\", Section=\"Advanced\")\nboolean MPLS_HANDOFF\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"MPLS_HANDOFF==true && UNDERLAY_IS_V6==false\", Description=\"Used for VXLAN to MPLS SR/LDP Handoff <br/>(Min:0, Max:1023)\", DisplayName=\"Underlay MPLS Loopback Id\", Section=\"Advanced\")\ninteger MPLS_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=101;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable TCAM Allocation\", Description=\"TCAM commands are automatically generated for VxLAN and vPC Fabric Peering when Enabled\", Section=\"Advanced\")\nboolean TCAM_ALLOCATION{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsShow=\"FABRIC_VPC_QOS==false\", DisplayName=\"Enable Default Queuing Policies\", Section=\"Advanced\")\nboolean ENABLE_DEFAULT_QUEUING_POLICY{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==true\", Enum=\"%TEMPLATES.QoS_Cloud\", AlwaysSetDefault=true, DisplayName=\"N9K Cloud Scale Platform <br/>Queuing Policy\", Description=\"Queuing Policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX <br/>series switches in the fabric\", Section=\"Advanced\")\nstring DEAFULT_QUEUING_POLICY_CLOUDSCALE\n{\ndefaultValue=queuing_policy_default_8q_cloudscale;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==true\", Enum=\"%TEMPLATES.QoS_R_Series\", AlwaysSetDefault=true, DisplayName=\"N9K R-Series Platform <br/>Queuing Policy\", Description=\"Queuing Policy for all R-Series <br/>switches in the fabric\", Section=\"Advanced\")\nstring DEAFULT_QUEUING_POLICY_R_SERIES\n{\ndefaultValue=queuing_policy_default_r_series;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_DEFAULT_QUEUING_POLICY==true\", Enum=\"%TEMPLATES.QoS_Other\", AlwaysSetDefault=true, DisplayName=\"Other N9K Platform <br/>Queuing Policy\", Description=\"Queuing Policy for all other <br/>switches in the fabric\", Section=\"Advanced\")\nstring DEAFULT_QUEUING_POLICY_OTHER\n{\ndefaultValue=queuing_policy_default_other;\n};\n\n@(IsMandatory=false, DisplayName=\"Enable MACsec\", Description=\"Enable MACsec in the fabric\", Section=\"Advanced\")\nboolean ENABLE_MACSEC {\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Primary Key String\", Description=\"Cisco Type 7 Encrypted Octet String\", Section=\"Advanced\")\nstring MACSEC_KEY_STRING {\nminLength = 1;\nmaxLength = 130;\nregularExpr=^[a-fA-F0-9]+$;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Primary Cryptographic <br/>Algorithm\", Description=\"AES_128_CMAC or AES_256_CMAC\", Section=\"Advanced\")\nenum MACSEC_ALGORITHM {\nvalidValues=AES_128_CMAC,AES_256_CMAC;\ndefaultValue=AES_128_CMAC;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Fallback Key String\", Description=\"Cisco Type 7 Encrypted Octet String\", Section=\"Advanced\")\nstring MACSEC_FALLBACK_KEY_STRING {\nminLength = 1;\nmaxLength = 130;\nregularExpr=^[a-fA-F0-9]+$;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Fallback Cryptographic <br/>Algorithm\", Description=\"AES_128_CMAC or AES_256_CMAC\", Section=\"Advanced\")\nenum MACSEC_FALLBACK_ALGORITHM {\nvalidValues=AES_128_CMAC,AES_256_CMAC;\ndefaultValue=AES_128_CMAC;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Cipher Suite\", Description=\"Configure Cipher Suite\", Section=\"Advanced\")\nenum MACSEC_CIPHER_SUITE {\nvalidValues=GCM-AES-128,GCM-AES-256,GCM-AES-XPN-128,GCM-AES-XPN-256;\ndefaultValue=GCM-AES-XPN-256;\n};\n\n@(IsMandatory=true, IsShow=\"ENABLE_MACSEC==true\", DisplayName=\"MACsec Status Report Timer\", Description=\"MACsec Operational Status periodic report timer in minutes\", Section=\"Advanced\")\ninteger MACSEC_REPORT_TIMER {\nmin = 5;\nmax = 60;\ndefaultValue=5;\n};\n\n@(IsMandatory=false, Enum=\"rpvst+,mst,unmanaged\", DisplayName=\"Spanning Tree Root Bridge Protocol\", Description=\"Which protocol to use for configuring root bridge? rpvst+: Rapid Per-VLAN Spanning Tree, mst: Multiple Spanning Tree, unmanaged (default): STP Root not managed by NDFC\", Section=\"Advanced\")\nstring STP_ROOT_OPTION\n{\ndefaultValue=unmanaged;\n};\n\n@(IsMandatory=true, IsShow=\"STP_ROOT_OPTION==rpvst+\", DisplayName=\"Spanning Tree VLAN Range\", Description=\"Vlan range, Example: 1,3-5,7,9-11, Default is 1-3967\", Section=\"Advanced\")\nintegerRange STP_VLAN_RANGE\n{\nmin=1;\nmax=4092;\ndefaultValue=1-3967;\n};\n\n@(IsMandatory=true, IsShow=\"STP_ROOT_OPTION==mst\", DisplayName=\"MST Instance Range\", Description=\"MST instance range, Example: 0-3,5,7-9, Default is 0\", Section=\"Advanced\")\nintegerRange MST_INSTANCE_RANGE\n{\nmin=0;\nmax=4094;\ndefaultValue=0;\n};\n\n@(IsMandatory=true, IsShow=\"STP_ROOT_OPTION==rpvst+||STP_ROOT_OPTION==mst\", DisplayName=\"Spanning Tree Bridge Priority\", Description=\"Bridge priority for the spanning tree in increments of 4096\", Section=\"Advanced\")\nenum STP_BRIDGE_PRIORITY\n{\nvalidValues=0,4096,8192,12288,16384,20480,24576,28672,32768,36864,40960,45056,49152,53248,57344,61440;\ndefaultValue=0;\n};\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Leaf Freeform Config\", Description=\"Additional CLIs For All Leafs As Captured From Show Running Configuration\", Section=\"Advanced\")\nstring EXTRA_CONF_LEAF;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Spine Freeform Config\", Description=\"Additional CLIs For All Spines As Captured From Show Running Configuration\", Section=\"Advanced\")\nstring EXTRA_CONF_SPINE;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"ToR Freeform Config\", Description=\"Additional CLIs For All ToRs As Captured From Show Running Configuration\", Section=\"Advanced\")\nstring EXTRA_CONF_TOR;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Intra-fabric Links Additional Config\", Description=\"Additional CLIs For All Intra-Fabric Links\", Section=\"Advanced\")\nstring EXTRA_CONF_INTRA_LINKS;\n\n#Resources\n@(IsMandatory=false, Description=\"Checking this will disable Dynamic Underlay IP Address Allocations\", DisplayName=\"Manual Underlay IP Address <br/>Allocation\", Section=\"Resources\")\nboolean STATIC_UNDERLAY_IP_ALLOC\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback0 IP Address Range\", DisplayName=\"Underlay Routing Loopback IP <br/>Range\", Section=\"Resources\")\nipV4AddressWithSubnet LOOPBACK0_IP_RANGE\n{\ndefaultValue=10.2.0.0/22;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback1 IP Address Range\", DisplayName=\"Underlay VTEP Loopback IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet LOOPBACK1_IP_RANGE\n{\ndefaultValue=10.3.0.0/22;\n};\n\n@(IsMandatory=true, IsShow=\"($$STATIC_UNDERLAY_IP_ALLOC$$=='false' && $$UNDERLAY_IS_V6$$=='false' && $$REPLICATION_MODE$$=='Multicast') || ($$STATIC_UNDERLAY_IP_ALLOC$$=='true' && $$UNDERLAY_IS_V6$$=='false' && $$REPLICATION_MODE$$=='Multicast' && $$RP_MODE$$=='bidir')\", Description=\"Anycast or Phantom RP IP Address Range\", DisplayName=\"Underlay RP Loopback IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet ANYCAST_RP_IP_RANGE\n{\ndefaultValue=10.254.254.0/24;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Address range to assign Numbered and Peer Link SVI IPs\", DisplayName=\"Underlay Subnet IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet SUBNET_RANGE\n{\ndefaultValue=10.4.0.0/16;\n};\n\n@(IsMandatory=true, IsShow=\"MPLS_HANDOFF==true && UNDERLAY_IS_V6==false && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Used for VXLAN to MPLS SR/LDP Handoff\", DisplayName=\"Underlay MPLS Loopback IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet MPLS_LOOPBACK_IP_RANGE\n{\ndefaultValue=10.101.0.0/25;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback0 IPv6 Address Range\", DisplayName=\"Underlay Routing Loopback IPv6 <br/>Range\", Section=\"Resources\")\nipV6AddressWithSubnet LOOPBACK0_IPV6_RANGE\n{\ndefaultValue=fd00::a02:0/119;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\", Description=\"Typically Loopback1 and Anycast Loopback IPv6 Address Range\", DisplayName=\"Underlay VTEP Loopback IPv6 <br/>Range\", Section=\"Resources\")\nipV6AddressWithSubnet LOOPBACK1_IPV6_RANGE\n{\ndefaultValue=fd00::a03:0/118;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false && USE_LINK_LOCAL==false\", Description=\"IPv6 Address range to assign Numbered and Peer Link SVI IPs\", DisplayName=\"Underlay Subnet IPv6 Range\", Section=\"Resources\")\nipV6AddressWithSubnet V6_SUBNET_RANGE\n{\ndefaultValue=fd00::a04:0/112;\n};\n\n@(IsMandatory=true, IsShow=\"UNDERLAY_IS_V6==true && STATIC_UNDERLAY_IP_ALLOC==false\", DisplayName=\"BGP Router ID Range for IPv6 Underlay\", Section=\"Resources\")\nipV4AddressWithSubnet ROUTER_ID_RANGE\n{\ndefaultValue=10.2.0.0/23;\n};\n\n@(IsMandatory=true, IsL2VniRange=true, Description=\"Overlay Network Identifier Range (Min:1, Max:16777214)\", DisplayName=\"Layer 2 VXLAN VNI Range\", Section=\"Resources\")\nintegerRange L2_SEGMENT_ID_RANGE\n{\nmin=1;\nmax=16777214;\ndefaultValue=30000-49000;\n};\n\n@(IsMandatory=true, IsL3VniRange=true, Description=\"Overlay VRF Identifier Range (Min:1, Max:16777214)\", DisplayName=\"Layer 3 VXLAN VNI Range\", Section=\"Resources\")\nintegerRange L3_PARTITION_ID_RANGE\n{\nmin=1;\nmax=16777214;\ndefaultValue=50000-59000;\n};\n\n@(IsMandatory=true, IsNetworkVlanRange=true, Description=\"Per Switch Overlay Network VLAN Range (Min:2, Max:4094)\", DisplayName=\"Network VLAN Range\", Section=\"Resources\")\nintegerRange NETWORK_VLAN_RANGE\n{\nmin=2;\nmax=4094;\ndefaultValue=2300-2999;\n};\n\n@(IsMandatory=true, IsVrfVlanRange=true, Description=\"Per Switch Overlay VRF VLAN Range (Min:2, Max:4094)\", DisplayName=\"VRF VLAN Range\", Section=\"Resources\")\nintegerRange VRF_VLAN_RANGE\n{\nmin=2;\nmax=4094;\ndefaultValue=2000-2299;\n};\n\n@(IsMandatory=true, IsDot1qIdRange=true, Description=\"Per Border Dot1q Range For VRF Lite Connectivity (Min:2, Max:4093)\", DisplayName=\"Subinterface Dot1q Range\", Section=\"Resources\")\nintegerRange SUBINTERFACE_RANGE\n{\nmin=2;\nmax=4093;\ndefaultValue=2-511;\n};\n\n@(IsMandatory=true, Enum=\"Manual,Back2Back&ToExternal\", Description=\"VRF Lite Inter-Fabric Connection Deployment Options. If 'Back2Back&ToExternal' is selected, VRF Lite IFCs are auto created between border devices of two Easy Fabrics, and between border devices in Easy Fabric and edge routers in External Fabric. The IP address is taken from the 'VRF Lite Subnet IP Range' pool.\", DisplayName=\"VRF Lite Deployment\", Section=\"Resources\")\nstring VRF_LITE_AUTOCONFIG\n{\ndefaultValue=Manual;\n};\n\n@(IsMandatory=false, IsShow=\"VRF_LITE_AUTOCONFIG!=Manual\", DisplayName=\"Auto Deploy for Peer\", Description=\"Whether to auto generate VRF LITE sub-interface and BGP peering configuration on managed neighbor devices. If set, auto created VRF Lite IFC links will have 'Auto Deploy for Peer' enabled.\", Section=\"Resources\")\nboolean AUTO_SYMMETRIC_VRF_LITE\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"VRF_LITE_AUTOCONFIG!=Manual\", DisplayName=\"Auto Deploy Default VRF\", Description=\"Whether to auto generate Default VRF interface and BGP peering configuration on VRF LITE IFC auto deployment. If set, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF' enabled.\", Section=\"Resources\")\nboolean AUTO_VRFLITE_IFC_DEFAULT_VRF\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsShow=\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\", DisplayName=\"Auto Deploy Default VRF for Peer\", Description=\"Whether to auto generate Default VRF interface and BGP peering configuration on managed neighbor devices. If set, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF for Peer' enabled.\", Section=\"Resources\")\nboolean AUTO_SYMMETRIC_DEFAULT_VRF\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\", IsShow=\"AUTO_VRFLITE_IFC_DEFAULT_VRF==true\", DisplayName=\"Redistribute BGP Route-map Name\", Description=\"Route Map used to redistribute BGP routes to IGP in default vrf in auto created VRF Lite IFC links\", Section=\"Resources\")\nstring DEFAULT_VRF_REDIS_BGP_RMAP\n{\ndefaultValue=extcon-rmap-filter;\n};\n\n@(IsMandatory=true, Description=\"Address range to assign P2P Interfabric Connections\", DisplayName=\"VRF Lite Subnet IP Range\", Section=\"Resources\")\nipV4AddressWithSubnet DCI_SUBNET_RANGE\n{\ndefaultValue=10.33.0.0/16;\n};\n\n@(IsMandatory=true,  Description=\"(Min:8, Max:31)\", DisplayName=\"VRF Lite Subnet Mask\", Section=\"Resources\")\ninteger DCI_SUBNET_TARGET_MASK\n{\nmin = 8;\nmax = 31;\ndefaultValue=30;\n};\n\n@(IsMandatory=false, DisplayName=\"Auto Allocation of Unique IP on VRF Extension over VRF Lite IFC\", Description=\"When enabled, IP prefix allocated to the VRF LITE IFC is not reused on VRF extension over VRF LITE IFC. Instead, unique IP Subnet is allocated for each VRF extension over VRF LITE IFC.\", Section=\"Resources\")\nboolean AUTO_UNIQUE_VRF_LITE_IP_PREFIX\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true, Section=\"Resources\")\nboolean AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, DisplayName=\"Per VRF Per VTEP Loopback Auto-Provisioning\", Description=\"Auto provision a loopback on a VTEP on VRF attachment\", Section=\"Resources\")\nboolean PER_VRF_LOOPBACK_AUTO_PROVISION\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true, Section=\"Resources\")\nboolean PER_VRF_LOOPBACK_AUTO_PROVISION_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, IsShow=\"PER_VRF_LOOPBACK_AUTO_PROVISION==true\", DisplayName=\"Per VRF Per VTEP IP Pool for Loopbacks\", Description=\"Prefix pool to assign IP addresses to loopbacks on VTEPs on a per VRF basis\", Section=\"Resources\")\nipV4AddressWithSubnet PER_VRF_LOOPBACK_IP_RANGE\n{\ndefaultValue=10.5.0.0/22;\n};\n\n@(IsMandatory=false, DisplayName=\"Service Level Agreement (SLA) ID Range\", Description=\"Per switch SLA ID Range (Min:1, Max: 2147483647)\", Section=\"Resources\")\nintegerRange SLA_ID_RANGE\n{\nmin=1;\nmax=2147483647;\ndefaultValue=10000-19999;\n};\n\n@(IsMandatory=false, DisplayName=\"Tracked Object ID Range\", Description=\"Per switch tracked object ID Range (Min:1, Max: 512)\", Section=\"Resources\")\nintegerRange OBJECT_TRACKING_NUMBER_RANGE\n{\nmin=1;\nmax=512;\ndefaultValue=100-299;\n};\n\n@(IsMandatory=true, Description=\"Per Switch Overlay Service Network VLAN Range (Min:2, Max:4094)\", DisplayName=\"Service Network VLAN Range\", Section=\"Resources\")\nintegerRange SERVICE_NETWORK_VLAN_RANGE\n{\nmin=2;\nmax=4094;\ndefaultValue=3000-3199;\n};\n\n@(IsMandatory=true, Description=\"(Min:1, Max:65534)\", DisplayName=\"Route Map Sequence Number Range\", Section=\"Resources\")\nintegerRange ROUTE_MAP_SEQUENCE_NUMBER_RANGE\n{\nmin=1;\nmax=65534;\ndefaultValue=1-65534;\n};\n\n@(IsMandatory=false, DisplayName=\"Inband Management\", IsShow=\"LINK_STATE_ROUTING==ospf && UNDERLAY_IS_V6==false\", Description=\"Manage switches with only Inband connectivity\", Section=\"Manageability\")\nboolean INBAND_MGMT\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean INBAND_MGMT_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, Description=\"Comma separated list of IP Addresses(v4/v6)\", DisplayName=\"DNS Server IPs\", Section=\"Manageability\")\nipAddressList DNS_SERVER_IP_LIST;\n\n@(IsMandatory=\"DNS_SERVER_IP_LIST!=null\", IsShow=\"DNS_SERVER_IP_LIST!=null\", Description=\"One VRF for all DNS servers or a comma separated<br/>list of VRFs, one per DNS server\", DisplayName=\"DNS Server VRFs\", Section=\"Manageability\")\nstring[] DNS_SERVER_VRF {\n     \n};\n\n@(IsMandatory=false, Description=\"Comma separated list of IP Addresses(v4/v6)\", DisplayName=\"NTP Server IPs\", Section=\"Manageability\")\nipAddressList NTP_SERVER_IP_LIST;\n\n@(IsMandatory=\"NTP_SERVER_IP_LIST!=null\", IsShow=\"NTP_SERVER_IP_LIST!=null\", Description=\"One VRF for all NTP servers or a comma separated<br/>list of VRFs, one per NTP server\", DisplayName=\"NTP Server VRFs\", Section=\"Manageability\")\nstring[] NTP_SERVER_VRF {\n   \n};\n\n@(IsMandatory=false, Description=\"Comma separated list of IP Addresses(v4/v6)\", DisplayName=\"Syslog Server IPs\", Section=\"Manageability\")\nipAddressList SYSLOG_SERVER_IP_LIST;\n\n@(IsMandatory=\"SYSLOG_SERVER_IP_LIST!=null\", IsShow=\"SYSLOG_SERVER_IP_LIST!=null\", Description=\"Comma separated list of Syslog severity values,<br/>one per Syslog server (Min:0, Max:7)\", DisplayName=\"Syslog Server Severity\", Section=\"Manageability\")\nstring[] SYSLOG_SEV {\n    \n};\n\n@(IsMandatory=\"SYSLOG_SERVER_IP_LIST!=null\", IsShow=\"SYSLOG_SERVER_IP_LIST!=null\", Description=\"One VRF for all Syslog servers or a comma separated<br/>list of VRFs, one per Syslog server\", DisplayName=\"Syslog Server VRFs\", Section=\"Manageability\")\nstring[] SYSLOG_SERVER_VRF {\n  \n};\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"AAA Freeform Config\", Description=\"AAA Configurations\", Section=\"Manageability\")\nstring AAA_SERVER_CONF;\n\n@(IsMandatory=false, IsMultiLineString=true, DisplayName=\"Banner\", Description=\"Message of the Day (motd) banner. Delimiter char (very first char is delimiter char) followed by message ending with delimiter\", Section=\"Manageability\")\nstring BANNER;\n\n@(IsMandatory=false, NoConfigChg=true, IsDhcpFlag=true, Description=\"Automatic IP Assignment For POAP\", DisplayName=\"Enable Bootstrap\", Section=\"Bootstrap\")\nboolean BOOTSTRAP_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true, Section=\"Bootstrap\")\nboolean BOOTSTRAP_ENABLE_PREV\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"BOOTSTRAP_ENABLE==true\", Description=\"Automatic IP Assignment For POAP From Local DHCP Server\", DisplayName=\"Enable Local DHCP Server\", Section=\"Bootstrap\")\nboolean DHCP_ENABLE{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, NoConfigChg=true, Enum=\"DHCPv4,DHCPv6\", IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", DisplayName=\"DHCP Version\", Section=\"Bootstrap\")\nstring DHCP_IPV6_ENABLE\n{\ndefaultValue=DHCPv4;\n};\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", Description=\"Start Address For Switch POAP\", DisplayName=\"DHCP Scope Start Address\", Section=\"Bootstrap\")\nipAddress DHCP_START;\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", Description=\"End Address For Switch POAP\", DisplayName=\"DHCP Scope End Address\", Section=\"Bootstrap\")\nipAddress DHCP_END;\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", Description=\"Default Gateway For Management VRF On The Switch\", DisplayName=\"Switch Mgmt Default Gateway\", Section=\"Bootstrap\")\nipAddress MGMT_GW;\n\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true && DHCP_IPV6_ENABLE==DHCPv4\", Description=\"(Min:8, Max:30)\", DisplayName=\"Switch Mgmt IP Subnet Prefix\", Section=\"Bootstrap\")\ninteger MGMT_PREFIX\n{\nmin = 8;\nmax = 30;\ndefaultValue=24;\n};\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true && DHCP_IPV6_ENABLE==DHCPv6\", Description=\"(Min:64, Max:126)\", DisplayName=\"Switch Mgmt IPv6 Subnet Prefix\", Section=\"Bootstrap\")\ninteger MGMT_V6PREFIX\n{\nmin = 64;\nmax = 126;\ndefaultValue=64;\n};\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"DHCP_ENABLE==true && BOOTSTRAP_ENABLE==true\", IsMultiLineString=true, DisplayName=\"DHCPv4 Multi Subnet Scope\",  Description=\"lines with # prefix are ignored here\", Warning=\"Enter One Subnet Scope per line. <br/> Start_IP, End_IP, Gateway, Prefix <br/> e.g. <br>10.6.0.2, 10.6.0.9, 10.6.0.1, 24 <br>10.7.0.2, 10.7.0.9, 10.7.0.1, 24\", Section=\"Bootstrap\")\nstring BOOTSTRAP_MULTISUBNET\n{\ndefaultValue=#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix;\n};\n\n@(IsMandatory=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", DisplayName=\"Seed Switch Fabric Interfaces\", Description=\"Core-facing Interface list on Seed Switch (e.g. e1/1-30,e1/32)\", Section=\"Bootstrap\")\ninterfaceRange SEED_SWITCH_CORE_INTERFACES;\n\n@(IsMandatory=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true\", DisplayName=\"Spine Switch Fabric Interfaces\", Description=\"Core-facing Interface list on all Spines (e.g. e1/1-30,e1/32)\", Section=\"Bootstrap\")\ninterfaceRange SPINE_SWITCH_CORE_INTERFACES;\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==false\", Description=\"Comma separated list of IPv4 Addresses (Max 3)\", DisplayName=\"External DHCP Server IP Addresses\", Section=\"Bootstrap\")\nipAddressList INBAND_DHCP_SERVERS;\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\", DisplayName=\"Bootstrap Seed Switch Loopback Interface ID\", Section=\"Bootstrap\")\ninteger UNNUM_BOOTSTRAP_LB_ID{\nmin=0;\nmax=1023;\ndefaultValue=253;\n};\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\", Description=\"Must be a subset of IGP/BGP Loopback Prefix Pool\", DisplayName=\"Switch Loopback DHCP Scope <br/> Start Address\", Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_START;\n\n@(IsMandatory=true, IsShow=\"BOOTSTRAP_ENABLE==true && INBAND_MGMT==true && DHCP_ENABLE==true && FABRIC_INTERFACE_TYPE==unnumbered\", Description=\"Must be a subset of IGP/BGP Loopback Prefix Pool\", DisplayName=\"Switch Loopback DHCP Scope <br/> End Address\", Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_END;\n\n@(IsMandatory=false, NoConfigChg=true, IsShow=\"BOOTSTRAP_ENABLE==true\", Description=\"Include AAA configs from Manageability tab during device bootup\", DisplayName=\"Enable AAA Config\", Section=\"Bootstrap\")\nboolean ENABLE_AAA{\ndefaultValue = false;\n};\n\n@(IsMandatory=false, IsShow=\"BOOTSTRAP_ENABLE==true\", IsMultiLineString=true, DisplayName=\"Bootstrap Freeform Config\", Description=\"Additional CLIs required during device bootup/login e.g. AAA/Radius\", Section=\"Bootstrap\")\nstring BOOTSTRAP_CONF;\n\n#Configuration Backup settings\n@(IsMandatory=false, NoConfigChg=true, Description=\"Backup hourly only if there is any config deployment since last backup\", DisplayName=\"Hourly Fabric Backup\", Section=\"Configuration Backup\")\nboolean enableRealTimeBackup;\n@(IsMandatory=false, NoConfigChg=true, Description=\"Backup at the specified time\", DisplayName=\"Scheduled Fabric Backup\", Section=\"Configuration Backup\")\nboolean enableScheduledBackup;\n@(IsMandatory=true, NoConfigChg=true, IsShow=\"enableScheduledBackup==true\", Description=\"Time (UTC) in 24hr format. (00:00 to 23:59)\", DisplayName=\"Scheduled Time\", Section=\"Configuration Backup\")\nstring scheduledTime\n{\n    regularExpr=^([01]\\d|2[0-3]):([0-5]\\d)$;\n\n};\n\n# netflow is not supported for VXLANv6\n@(IsMandatory=false, IsShow=\"UNDERLAY_IS_V6==false\", Description=\"Enable Netflow on VTEPs\", DisplayName=\"Enable Netflow\", Section=\"Flow Monitor\")\nboolean ENABLE_NETFLOW\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ENABLE_NETFLOW_PREV;\n\n@(IsMandatory=true, IsShow=\"ENABLE_NETFLOW==true\", Description=\"One or Multiple Netflow Exporters\", DisplayName=\"Netflow Exporter\", Section=\"Flow Monitor\")\nstruct ITEM {\n  @(IsMandatory=true, DisplayName=\"Exporter Name\")\n  string EXPORTER_NAME;\n  @(IsMandatory=true, DisplayName=\"IP\")\n  ipV4Address IP;\n  @(IsMandatory=false, DisplayName=\"VRF\")\n  string VRF;\n  @(IsMandatory=true, DisplayName=\"Source Interface\")\n  interface SRC_IF_NAME;\n  @(IsMandatory=true, DisplayName=\"UDP Port\")\n  integer UDP_PORT {\n    min = 1;\n    max = 65535;\n  };\n} NETFLOW_EXPORTER_LIST[];\n\n@(IsMandatory=true, IsShow=\"ENABLE_NETFLOW==true\", Description=\"One or Multiple Netflow Records\", DisplayName=\"Netflow Record\", Section=\"Flow Monitor\")\nstruct ITEM {\n  @(IsMandatory=true, DisplayName=\"Record Name\")\n  string RECORD_NAME;\n  @(IsMandatory=true, DisplayName=\"Record Template\")\n  #@(IsMandatory=true, Enum=\"%TEMPLATES.QoS_Cloud\", DisplayName=\"Record Template\")\n  string RECORD_TEMPLATE\n  {\n    defaultValue=netflow_ipv4_record;\n  };\n  @(IsMandatory=false, DisplayName=\"Is Layer2 Record\")\n  boolean LAYER2_RECORD {\n    defaultValue=false;\n  };\n} NETFLOW_RECORD_LIST[];\n\n@(IsMandatory=true, IsShow=\"ENABLE_NETFLOW==true\", Description=\"One or Multiple Netflow Monitors\", DisplayName=\"Netflow Monitor\", Section=\"Flow Monitor\")\nstruct ITEM {\n  @(IsMandatory=true, DisplayName=\"Monitor Name\")\n  string MONITOR_NAME;\n  @(IsMandatory=true, DisplayName=\"Record Name\")\n  string RECORD_NAME;\n  @(IsMandatory=true, DisplayName=\"Exporter1 Name\")\n  string EXPORTER1;\n  @(IsMandatory=false, DisplayName=\"Exporter2 Name\")\n  string EXPORTER2;\n} NETFLOW_MONITOR_LIST[];\n\n@(IsMandatory=false, DisplayName=\"Enable Nexus Cloud\", Description=\"Allow onboarding of this fabric to Nexus Cloud\", Section=\"Nexus Cloud\")\nboolean ALLOW_NXC\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=false, IsInternal=true)\nboolean ALLOW_NXC_PREV;\n\n@(IsMandatory=false, IsShow=\"ALLOW_NXC==true\", DisplayName=\"Overwrite Global NxCloud Settings\", Description=\"If enabled, Fabric NxCloud Settings will be used\", Section=\"Nexus Cloud\")\nboolean OVERWRITE_GLOBAL_NXC\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=\"OVERWRITE_GLOBAL_NXC==true\", IsShow=\"OVERWRITE_GLOBAL_NXC==true\", DisplayName=\"Intersight Destination VRF\", Description=\"VRF to be used to reach Nexus Cloud, enter 'management' for management VRF and 'default' for default VRF\", Section=\"Nexus Cloud\")\nstring NXC_DEST_VRF\n{\nminLength = 1;\nmaxLength = 32;\ndefaultValue=management;\n};\n\n@(IsMandatory=\"OVERWRITE_GLOBAL_NXC==true && NXC_DEST_VRF!=management\", IsShow=\"OVERWRITE_GLOBAL_NXC==true && NXC_DEST_VRF!=management\", DisplayName=\"Intersight Source Interface\", Description=\"Source interface for communication to Nexus Cloud, mandatory if Destination VRF is not management, supported interfaces: loopback, port-channel, vlan\", Section=\"Nexus Cloud\")\ninterface NXC_SRC_INTF;\n\n@(IsMandatory=false, IsShow=\"OVERWRITE_GLOBAL_NXC==true\", DisplayName=\"Intersight Proxy Server\", Description=\"IPv4 or IPv6 address, or DNS name of the proxy server\", Section=\"Nexus Cloud\")\nstring NXC_PROXY_SERVER;\n\n@(IsMandatory=\"NXC_PROXY_SERVER!=null\", IsShow=\"NXC_PROXY_SERVER!=null\", DisplayName=\"Proxy Server Port\", Description=\"Proxy port number, default is 8080\", Section=\"Nexus Cloud\")\ninteger NXC_PROXY_PORT\n{\nmin = 1;\nmax = 65535;\ndefaultValue = 8080;\n};\n\n@(IsMandatory=true, Description=\"vPC Delay Restore Time For vPC links in seconds (Min:1, Max:3600)\", DisplayName=\"vPC Delay Restore Time\", Section=\"Hidden\")\ninteger VPC_DELAY_RESTORE_TIME\n{\nmin = 1;\nmax = 3600;\ndefaultValue=60;\n};\n\n#Hidden\n@(IsMandatory=true, IsFabricType=true, DisplayName=\"Fabric Type\", ReadOnly=true, Section=\"Hidden\")\nstring FABRIC_TYPE\n{\ndefaultValue=Switch_Fabric;\n};\n\n@(IsMandatory=false, Section=\"Hidden\")\nstring EXT_FABRIC_TYPE;\n\n@(IsMandatory=false, Description=\"Enable Agnet (developmet purpose only)\", DisplayName=\"Enable Agent\", Section=\"Hidden\")\nboolean ENABLE_AGENT\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, Description=\"Interface to connect to Agent\", DisplayName=\"Agent Interface\", Enum=\"eth0,eth1\", Section=\"Hidden\")\nstring AGENT_INTF\n{\ndefaultValue=eth0;\n};\n\n@(IsMandatory=true,Enum=\"Enable,Disable\", Description=\"Allow First Super Spine Add or Last Super Spine Delete From Topology\", DisplayName=\"Super Spine Force Add Del\", Section=\"Hidden\")\nstring SSPINE_ADD_DEL_DEBUG_FLAG\n{\ndefaultValue=Disable;\n};\n\n@(IsMandatory=false, Enum=\"Enable,Disable\", Description=\"Dont' use until you are aware about it\", DisplayName=\"!!! Only for brf debugging purpose !!!\", Section=\"Hidden\")\nstring BRFIELD_DEBUG_FLAG\n{\ndefaultValue=Disable;\n};\n\n@(IsMandatory=true, DisplayName=\"Active Migration\", Section=\"Hidden\")\nboolean ACTIVE_MIGRATION\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=true, DisplayName=\"Template Family\", Section=\"Hidden\")\nstring FF\n{\ndefaultValue=Easy_Fabric;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring MSO_SITE_ID;\n@(IsMandatory=false, IsInternal=true)\nstring MSO_CONTROLER_ID;\n@(IsMandatory=false, IsInternal=true)\nstring MSO_SITE_GROUP_NAME;\n@(IsMandatory=false, IsInternal=true)\nstring PREMSO_PARENT_FABRIC;\n@(IsMandatory=false, IsInternal=true)\nstring MSO_CONNECTIVITY_DEPLOYED;\n\n@(IsMandatory=false, Section=\"Hidden\")\nipV4AddressWithSubnet ANYCAST_RP_IP_RANGE_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress DHCP_START_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress DHCP_END_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress MGMT_GW_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\ninteger MGMT_PREFIX_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nstring BOOTSTRAP_MULTISUBNET_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\ninteger MGMT_V6PREFIX_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nstring DHCP_IPV6_ENABLE_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_START_INTERNAL;\n\n@(IsMandatory=false, NoConfigChg=true, IsInternal=true, Section=\"Bootstrap\")\nipAddress UNNUM_DHCP_END_INTERNAL;\n\n@(IsMandatory=true, IsInternal=true)\nboolean ENABLE_EVPN\n{\ndefaultValue=true;\n};\n\n@(IsMandatory=true, IsInternal=true)\nboolean FEATURE_PTP_INTERNAL\n{\ndefaultValue=false;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger SSPINE_COUNT\n{\ndefaultValue=0;\n};\n\n@(IsMandatory=false, IsInternal=true)\ninteger SPINE_COUNT\n{\ndefaultValue=0;\n};\n\n#All policy templates starts from here.\n@(IsMandatory=true, Enum=\"base_feature_leaf_upg\", Description=\"Feature Configuration for Leaf\", DisplayName=\"base_feature_leaf\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_feature_leaf {\ndefaultValue=base_feature_leaf_upg;\n};\n\n@(IsMandatory=true, Enum=\"base_feature_spine_upg\", Description=\"Feature Configuration for Spine\", DisplayName=\"base_feature_spine\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_feature_spine {\ndefaultValue=base_feature_spine_upg;\n};\n\n@(IsMandatory=true, Enum=\"base_dhcp\", Description=\"DHCP Configuration\", DisplayName=\"base_dhcp\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_dhcp\n{\ndefaultValue=base_dhcp;\n};\n\n@(IsMandatory=true, Enum=\"base_multicast_11_1\", Description=\"Multicast Configuration\", DisplayName=\"base_multicast\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_multicast\n{\ndefaultValue=base_multicast_11_1;\n};\n\n@(IsMandatory=true, Enum=\"anycast_rp\", Description=\"Anycast RP Configuration\", DisplayName=\"anycast_rp\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_anycast_rp\n{\ndefaultValue=anycast_rp;\n};\n\n@(IsMandatory=true, Enum=\"int_fabric_loopback_11_1\", Description=\"Primary Loopback Interface Configuration\", DisplayName=\"loopback_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_loopback_interface\n{\ndefaultValue=int_fabric_loopback_11_1;\n};\n\n@(IsMandatory=true, Enum=\"base_isis_level2\", Description=\"ISIS Network Configuration\", DisplayName=\"base_isis_level2\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_isis\n{\ndefaultValue=base_isis_level2;\n};\n\n@(IsMandatory=true, Enum=\"base_ospf\", Description=\"OSPF Network Configuration\", DisplayName=\"base_ospf\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_ospf\n{\ndefaultValue=base_ospf;\n};\n\n@(IsMandatory=true, Enum=\"base_vpc_domain_11_1\", Description=\"vPC Domain Configuration\", DisplayName=\"base_vpc_domain\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_vpc_domain\n{\ndefaultValue=base_vpc_domain_11_1;\n};\n\n@(IsMandatory=true, Enum=\"int_fabric_vlan_11_1\", Description=\"VLAN Interface Configuration\", DisplayName=\"vlan_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_vlan_interface\n{\ndefaultValue=int_fabric_vlan_11_1;\n};\n\n@(IsMandatory=true, Enum=\"isis_interface\", Description=\"ISIS Interface Configuration\", DisplayName=\"isis_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_isis_interface\n{\ndefaultValue=isis_interface;\n};\n\n@(IsMandatory=true, Enum=\"ospf_interface\", Description=\"OSPF Interface Configuration\", DisplayName=\"ospf_interface_11_1\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_ospf_interface\n{\ndefaultValue=ospf_interface_11_1;\n};\n\n@(IsMandatory=true, Enum=\"pim_interface\", Description=\"PIM Interface Configuration\", DisplayName=\"pim_interface\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_pim_interface\n{\ndefaultValue=pim_interface;\n};\n\n@(IsMandatory=true, Enum=\"route_map\", Description=\"Route-Map Configuration\", DisplayName=\"abstract_route_map\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_route_map\n{\ndefaultValue=route_map;\n};\n\n@(IsMandatory=true, Enum=\"base_bgp\", Description=\"BGP Configuration\", DisplayName=\"base_bgp\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_bgp\n{\ndefaultValue=base_bgp;\n};\n\n@(IsMandatory=true, Enum=\"evpn_bgp_rr\", Description=\"BGP RR Configuration\", DisplayName=\"evpn_bgp_rr\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_bgp_rr\n{\ndefaultValue=evpn_bgp_rr;\n};\n\n@(IsMandatory=true, Enum= \"evpn_bgp_rr_neighbor\", Description=\"BGP Neighbor Configuration\", DisplayName=\"evpn_bgp_rr_neighbor\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_bgp_neighbor\n{\ndefaultValue=evpn_bgp_rr_neighbor;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_leaf\", Description=\"Add Extra Configuration for Leaf\", DisplayName=\"extra_config_leaf\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_leaf\n{\ndefaultValue=extra_config_leaf;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_spine\", Description=\"Add Extra Configuration for Spine\", DisplayName=\"extra_config_spine\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_spine\n{\ndefaultValue=extra_config_spine;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_tor\", Description=\"Add Extra Configuration for ToR\", DisplayName=\"extra_config_tor\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_tor\n{\ndefaultValue=extra_config_tor;\n};\n\n@(IsMandatory=true, Enum= \"extra_config_bootstrap\", Description=\"Add Extra Configuration for Bootstrap\", DisplayName=\"extra_config_bootstrap\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_extra_config_bootstrap\n{\ndefaultValue=extra_config_bootstrap_11_1;\n};\n\n@(IsMandatory=true, Enum=\"anycast_gateway\", Description=\"Anycast Gateway MAC Configuration\", DisplayName=\"anycast_gateway\", Section=\"Policy Templates\", IsInternal=true)\nstring temp_anycast_gateway\n{\ndefaultValue=anycast_gateway;\n};\n\n@(IsMandatory=true, Enum=\"vpc_domain_mgmt\", Description=\"vPC Keep-alive Configuration using Management VRF\", DisplayName=\"vpc_domain_mgmt\", Section=\"Policy Templates\", IsInternal=true)\nstring temp_vpc_domain_mgmt\n{\ndefaultValue=vpc_domain_mgmt;\n};\n\n@(IsMandatory=true, Enum=\"vpc_peer_link\", Description=\"vPC Peer-Link Configuration\", DisplayName=\"vpc_peer_link\", Section=\"Policy Templates\", IsInternal=true)\nstring temp_vpc_peer_link\n{\ndefaultValue=int_vpc_peer_link_po;\n};\n\n@(IsMandatory=true, Enum=\"int_routed_host\", Description=\"Routed Host Port Configuration\", DisplayName=\"routed_host\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_routed_host\n{\ndefaultValue=int_routed_host;\n};\n\n@(IsMandatory=true, Enum=\"int_trunk_host\", Description=\"trunk Host Port Configuration\", DisplayName=\"trunk_host\", Section=\"Policy Templates\", IsInternal=true)\nstring abstract_trunk_host\n{\ndefaultValue=int_trunk_host;\n};\n\n@(IsMandatory=false, IsInternal=true)\nstring UPGRADE_FROM_VERSION;\n\n@(IsMandatory=false, IsInternal=true)\nstring TOPDOWN_CONFIG_RM_TRACKING;\n\n\n##\n##template content\n\nfrom com.cisco.dcbu.vinci.rest.services.jython import *\nfrom com.cisco.dcbu.vinci.rest.services.jython import ResourceManagerWrapper as RM\nfrom com.cisco.dcbu.vinci.rest.services.jython import PTIWrapper as PTI\nfrom com.cisco.dcbu.vinci.rest.services.jython import InterfaceManagerWrapper as IM\nfrom com.cisco.dcbu.vinci.rest.services.jython import BackupRestoreWrapper as BRW\nfrom com.cisco.dcbu.vinci.rest.services.jython import ConfigDeployerWrapper as CDW\nfrom com.cisco.dcbu.vinci.rest.services.jython import ElasticServiceWrapper\nfrom com.cisco.dcbu.vinci.rest.services.jython import InterfaceTypeEnum\nfrom com.cisco.dcbu.topdown.dao import CommonDAO\nfrom com.cisco.dcbu.vinci.rest.services.jython import InterfabricConnectionWrapper\nfrom com.cisco.dcbu.tor.service import ToRWrapper\nfrom com.cisco.dcbu.jython.resource import Category\nfrom com.cisco.dcbu.jython.resource import EntityType as ET\nfrom com.cisco.dcbu.easy.util.jython.impl import FabricErrorLogger\n\nfrom topology import *\nfrom utility import *\n\nimport sys, traceback\nimport re\nimport json\nimport copy\n\ndef isValidOspfAreaIdIPString(ipStr):\n    ip = re.findall( r'''^[0-9]+(?:\\.[0-9]+){3}$''', ipStr)\n    isValid = True\n    if len(ip) == 1:\n        # convert string to ints\n        ipInts = map(int, ip[0].split('.'))\n        for ipInt in ipInts:\n            if not ((ipInt >= 0) and (ipInt <= 255)):\n                isValid = False\n                break\n    else:\n        # not a valid IP address string\n        isValid = False\n    Wrapper.print(\"isValidOspfAreaIdIPString: FAB [%s]: OSPF Area Id IP String [%s]  isValid [%r]\" % (FABRIC_NAME, ipStr, isValid))\n    return isValid\n\ndef isValidBrownfieldNetworkFormat(netName):\n    # name format is valid if the following rules are satisfied\n    #   - must contain $$VNI$$\n    #   - must not contain any other $$var$$\n    #   - parts must not have any special chars besides '_' and '-' (Overlay network name restrictions)\n    failureReason = None\n    Wrapper.print(\"isValidBrownfieldNetworkFormat: netName [%s]\" % (netName))\n\n    if (\"$$VNI$$\" not in netName):\n        failureReason = \"Missing mandatory $$VNI$$ keyword\"\n        return failureReason\n\n    specialCharChecker = re.compile(r'[^A-za-z0-9_-]')\n    parts = re.split(r'(\\$\\$[^$]+\\$\\$)', netName)\n    #Wrapper.print(\"isValidBrownfieldNetworkFormat: parts [%s]\" % (parts))\n    for part in parts:\n        if not part or (part == \"\"):\n            continue\n        if ((part.startswith('$$') and (part.endswith('$$')))):\n            #   - must not contain any other $$var$$\n            if ((part != '$$VNI$$') and (part != '$$VLAN_ID$$')):\n                failureReason = (\"Invalid keyword in [%s]\" % part)\n                break\n        else:\n            #   - parts must not have any special chars besides '_' and '-' (Overlay network name restrictions)\n            if specialCharChecker.search(part):\n                failureReason = (\"Invalid charater in [%s]\" % part)\n                break\n\n    return failureReason\n\n# returns True if change is allowed\ndef checkFabricMtuSettings(respObj):\n    retCode = True\n\n    Wrapper.print(\"checkFabricMtuSettings: FAB [%s]: Intra Fabric interface MTU [%s] -> [%s]\" %\n                (FABRIC_NAME, FABRIC_MTU_PREV, FABRIC_MTU))\n    # ensure the MTU value is an even number\n    if (int(FABRIC_MTU) % 2) != 0:\n        # cannot allow this change\n        respObj.addErrorReport(\"fabricInit\", \"Intra Fabric interface MTU [%s] must be an even number.\" % (FABRIC_MTU))\n        respObj.setFailureRetCode()\n        retCode = False\n\n    Wrapper.print(\"checkFabricMtuSettings: FAB [%s]: Layer 2 Host interface MTU [%s] -> [%s]\" %\n                (FABRIC_NAME, L2_HOST_INTF_MTU_PREV, L2_HOST_INTF_MTU))\n    # ensure the MTU value is an even number\n    if (int(L2_HOST_INTF_MTU) % 2) != 0:\n        # cannot allow this change\n        respObj.addErrorReport(\"fabricInit\", \"Layer 2 Host interface MTU [%s] must be an even number.\" % (L2_HOST_INTF_MTU))\n        respObj.setFailureRetCode()\n        retCode = False\n\n    return retCode\n\n# returns True if change is allowed\ndef checkBgpAsChange(respObj):\n    Wrapper.print(\"checkBgpAsChange: FAB [%s]: [%s] -> [%s]\" % (FABRIC_NAME, BGP_AS_PREV, BGP_AS))\n    if (BGP_AS_PREV != BGP_AS):\n        try:\n            getRespObj = FabricWrapper.getParentFabricName(FABRIC_NAME)\n            if getRespObj.isRetCodeSuccess():\n                # It is a member of MSD. Do not allow BGP AS change\n                respObj.addErrorReport(\"fabricInit\",\n                    \"BGP ASN cannot be changed from [%s] to [%s] on a MSD member fabric.\" % (BGP_AS_PREV, BGP_AS))\n                respObj.setFailureRetCode()\n                return False\n        except:\n            Wrapper.print(\"exception, ignore if not member fabric\")\n            pass\n\n        overlayPresent = Util.exe(Helper.isOverlayExist(FABRIC_NAME))\n        if overlayPresent:\n            # cannot allow this change\n            respObj.addErrorReport(\"fabricInit\",\n                \"BGP ASN cannot be changed from [%s] to [%s] with existing overlays.\" % (BGP_AS_PREV, BGP_AS))\n            respObj.setFailureRetCode()\n            return False\n\n        # update the prev value\n        FabricWrapper.update(FABRIC_NAME, \"BGP_AS_PREV\", BGP_AS)\n    return True\n\n# returns True if change is allowed\ndef checkLinkProtocolTagChange(respObj):\n    Wrapper.print(\"checkLinkProtocolTagChange: FAB [%s]: [%s] -> [%s]\" % (FABRIC_NAME, LINK_STATE_ROUTING_TAG_PREV, LINK_STATE_ROUTING_TAG))\n    if (LINK_STATE_ROUTING_TAG_PREV != LINK_STATE_ROUTING_TAG):\n        overlayPresent = Util.exe(Helper.isOverlayExist(FABRIC_NAME))\n        if overlayPresent:\n            # cannot allow this change\n            respObj.addErrorReport(\"fabricInit\",\n                \"Link-State Routing Protocol Tag cannot be changed from [%s] to [%s] with existing overlays.\" %\n                (LINK_STATE_ROUTING_TAG_PREV, LINK_STATE_ROUTING_TAG))\n            respObj.setFailureRetCode()\n            return False\n\n        # update the prev value\n        FabricWrapper.update(FABRIC_NAME, \"LINK_STATE_ROUTING_TAG_PREV\", LINK_STATE_ROUTING_TAG)\n    return True\n\n# returns True if change is allowed\ndef checkOverlayModeChange(respObj):\n    Wrapper.print(\"checkOverlayModeChange: FAB [%s]: [%s] -> [%s]\" % (FABRIC_NAME, OVERLAY_MODE_PREV, OVERLAY_MODE))\n    if (OVERLAY_MODE_PREV != \"\" and OVERLAY_MODE_PREV != OVERLAY_MODE):\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n        overlayConfigPresent = False\n        for deviceSn in devices:\n            if not CommonDAO.areOverlaysPresent(deviceSn):\n                overlayConfigPresent = True\n                break\n\n        if overlayConfigPresent:\n            # cannot allow this change\n            respObj.addErrorReport(\"fabricInit\",\n                \"Overlay Mode cannot be changed from [%s] to [%s] with overlay configurations \"\n                \"already applied on switches.\" % (OVERLAY_MODE_PREV, OVERLAY_MODE))\n            respObj.setFailureRetCode()\n            return False\n\n    # update the prev value\n    FabricWrapper.update(FABRIC_NAME, \"OVERLAY_MODE_PREV\", OVERLAY_MODE)\n    return True\n\ndef macSecSanityCheck(respObj):\n    if ENABLE_MACSEC == \"false\":\n        return True\n\n    foundErr = False\n    if MACSEC_ALGORITHM == \"AES_128_CMAC\" and len(MACSEC_KEY_STRING) != 66:\n        errorMsg = \"MACsec primary key string length must be 66 with AES_128_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck: %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if MACSEC_ALGORITHM == \"AES_256_CMAC\" and len(MACSEC_KEY_STRING) != 130:\n        errorMsg = \"MACsec primary key string length must be 130 with AES_256_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if MACSEC_FALLBACK_ALGORITHM == \"AES_128_CMAC\" and len(MACSEC_FALLBACK_KEY_STRING) != 66:\n        errorMsg = \"MACsec fallback key string length must be 66 with AES_128_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck: %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if MACSEC_FALLBACK_ALGORITHM == \"AES_256_CMAC\" and len(MACSEC_FALLBACK_KEY_STRING) != 130:\n        errorMsg = \"MACsec fallback key string length must be 130 with AES_256_CMAC.\"\n        Wrapper.print(\"macSecSanityCheck %s %s\" % (FABRIC_NAME, errorMsg))\n        respObj.addErrorReport(\"macSecSanityCheck\", errorMsg)\n        foundErr = True\n\n    if foundErr:\n        respObj.setFailureRetCode()\n        return False\n    else:\n        return True\n\ndef checkFabricVpcDomainId(respObj):\n    global ENABLE_FABRIC_VPC_DOMAIN_ID, ENABLE_FABRIC_VPC_DOMAIN_ID_PREV, FABRIC_VPC_DOMAIN_ID, FABRIC_VPC_DOMAIN_ID_PREV\n\n    # check for any changes to the vpc domain id settings\n    vpcDomainEnableSettingChanged = False\n    if (ENABLE_FABRIC_VPC_DOMAIN_ID != ENABLE_FABRIC_VPC_DOMAIN_ID_PREV):\n        vpcDomainEnableSettingChanged = True\n\n    vpcDomainIdSettingChanged = False\n    if ENABLE_FABRIC_VPC_DOMAIN_ID == \"true\":\n        if FABRIC_VPC_DOMAIN_ID != FABRIC_VPC_DOMAIN_ID_PREV:\n            vpcDomainIdSettingChanged = True\n    Wrapper.print(\"checkFabricVpcDomainId: vpc domain Enable [%s] -> [%s] [%r], Domain id [%s] -> [%s] [%r]\" % \n        (ENABLE_FABRIC_VPC_DOMAIN_ID_PREV, ENABLE_FABRIC_VPC_DOMAIN_ID, vpcDomainEnableSettingChanged,\n            FABRIC_VPC_DOMAIN_ID_PREV, FABRIC_VPC_DOMAIN_ID, vpcDomainIdSettingChanged))\n\n    if vpcDomainEnableSettingChanged or vpcDomainIdSettingChanged:\n        # do not allow the change if there are existing VPC pairs\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n        for deviceSn in devices:\n            isVPC = Util.exe(VpcWrapper.isVpc(FABRIC_NAME, deviceSn))\n            if isVPC:\n                if vpcDomainEnableSettingChanged:\n                    errStr = (\"Fabric wide vPC Domain ID Enable setting cannot be changed from [%s] to [%s] with existing vPC pairs.\" %\n                        (ENABLE_FABRIC_VPC_DOMAIN_ID_PREV, ENABLE_FABRIC_VPC_DOMAIN_ID))\n                else:\n                    errStr = (\"Fabric wide vPC Domain ID cannot be changed from [%s] to [%s] with existing vPC pairs.\" %\n                        (FABRIC_VPC_DOMAIN_ID_PREV, FABRIC_VPC_DOMAIN_ID))\n\n                respObj.addErrorReport(\"fabricInit\",errStr)\n                respObj.setFailureRetCode()\n                return False\n\n        # the vpc domain id is ok to change\n        ENABLE_FABRIC_VPC_DOMAIN_ID_PREV = ENABLE_FABRIC_VPC_DOMAIN_ID\n        Util.exe(FabricWrapper.update(FABRIC_NAME, \"ENABLE_FABRIC_VPC_DOMAIN_ID_PREV\", ENABLE_FABRIC_VPC_DOMAIN_ID_PREV))\n        FABRIC_VPC_DOMAIN_ID_PREV = FABRIC_VPC_DOMAIN_ID\n        Util.exe(FabricWrapper.update(FABRIC_NAME, \"FABRIC_VPC_DOMAIN_ID_PREV\", FABRIC_VPC_DOMAIN_ID_PREV))\n    return True\n\ndef putSwitchIntoMgmtModeMigrMode(fabricName, devSerial):\n    formattedName = getFormattedSwitchName(devSerial)\n    Wrapper.print(\"=======ACTION: FAB [%s]. Put switch [%s] into mgmt mode migration mode\" % (fabricName, formattedName))\n    ptis = Util.exe(PTIWrapper.get(devSerial, \"SWITCH\", \"SWITCH\",\"\", \"switch_migration_state\"))\n    for pti in ptis:\n        nvPairs = pti.getNvPairs()\n        if nvPairs:\n            Wrapper.print(\"putSwitchIntoOverlayMigrMode: Switch [%s] Migration [%s] NvPair = [%s]\" % \n                                    (devSerial, formattedName, nvPairs))\n            newNvPairs = copy.deepcopy(nvPairs)\n            newNvPairs[\"OVERLAY\"] = \"true\"\n            Util.exe(PTIWrapper.createOrUpdate(devSerial, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_migration_state\", newNvPairs))\n        break\n\ndef checkInbandMgmtSettings(fabricSettings, respObj):\n    funcName = sys._getframe(0).f_code.co_name\n\n    inbandMgmtEnable = True if (fabricSettings.get(\"INBAND_MGMT\", \"false\") == \"true\") else False\n    inbandMgmtEnablePrev = True if (fabricSettings.get(\"INBAND_MGMT_PREV\", \"false\") == \"true\") else False\n    bootstrapPOAPEnable = fabricSettings.get(\"BOOTSTRAP_ENABLE\", \"false\")\n    bootstrapPOAPEnablePrev = fabricSettings.get(\"BOOTSTRAP_ENABLE_PREV\", \"false\")\n    inbandPOAPEnable = True if (inbandMgmtEnable and bootstrapPOAPEnable == \"true\") else False\n    inbandPOAPEnablePrev = True if (inbandMgmtEnablePrev and bootstrapPOAPEnablePrev == \"true\") else False\n    dhcpEnable = fabricSettings.get(\"DHCP_ENABLE\", \"false\")        \n    tenantDhcpEnable = fabricSettings.get(\"ENABLE_TENANT_DHCP\", \"true\")        \n    underlayIsV6 = fabricSettings.get(\"UNDERLAY_IS_V6\", \"false\")        \n    routingProto = fabricSettings.get(\"LINK_STATE_ROUTING\", \"ospf\")        \n    fabIntfType = fabricSettings.get(\"FABRIC_INTERFACE_TYPE\", \"p2p\")\n\n    Wrapper.print(\"%s: inbandMgmtEnable [%r] inbandMgmtEnablePrev [%r] bootstrapPOAPEnable[%s] bootstrapPOAPEnablePrev[%s] \"\n      \"inbandPOAPEnable [%r] inbandPOAPEnablePrev [%r] DHCP[%s] \"\n      \"v6 [%s] Routing Prococol [%s]\" % (funcName, inbandMgmtEnable, inbandMgmtEnablePrev, bootstrapPOAPEnable, bootstrapPOAPEnablePrev,\n        inbandPOAPEnable, inbandPOAPEnablePrev, dhcpEnable, underlayIsV6, routingProto))\n    \n    # Disallow Inband Management for the following:\n    #  - v6 Underlay\n    #  - not OSPF Underlay Routing Protocol\n    if inbandMgmtEnable and (underlayIsV6 == \"true\" or routingProto != \"ospf\"):\n        respObj.addErrorReport(funcName, \"Inband Management is supported only with IPv4 underlay and routing protocol as \"\n          \"OSPF. Please update Fabric Settings and retry\")\n        respObj.setFailureRetCode()\n        return\n\n    if inbandPOAPEnable:\n        if tenantDhcpEnable != \"true\":\n          #Tenant DHCP knob must be enabled if inband POAP is enabled\n          respObj.addErrorReport(funcName, \"Tenant DHCP cannot be disabled if Inband POAP is enabled\")\n          respObj.setFailureRetCode()\n          return\n\n        if dhcpEnable == \"false\":\n            # check the following for External DHCP Servers:\n            #   - only 3 servers are allowed\n            #   - IPv4 only\n            settingName = \"External DHCP Server IP Addresses\"\n            inbandDhcpServersSettting = fabricSettings.get(\"INBAND_DHCP_SERVERS\", \"\")\n            inbandDhcpServersList = [eachIP.strip() for eachIP in inbandDhcpServersSettting.split(',')]\n            errMsg = None\n            if len(inbandDhcpServersList) > 3:\n                errMsg = \"Please configure a maximum of 3 (three) %s.\" % (settingName)\n            else:              \n                for ip in inbandDhcpServersList:\n                    if \":\" in ip:\n                        # v6 address is not allowed\n                        errMsg = \"%s must be valid IPv4 addresses.\" % (settingName)\n                        break\n\n            if errMsg is not None:\n                respObj.addErrorReport(\"fabricInit:InbandDhcpServers\", errMsg)\n                respObj.setFailureRetCode()\n                return\n\n    if inbandMgmtEnable != inbandMgmtEnablePrev:\n        if inbandMgmtEnable:\n            # make sure the NDFC device management setting is 'Data'\n            ndfcSNMPInfo = json.loads(Util.exe(FabricWrapper.getSNMPTrapInfo()))\n            ndfcDevMgmtMode = ndfcSNMPInfo.get(\"global.oob_network_mode\", \"\").lower()\n            mgmtModeIsData = True if ndfcDevMgmtMode == \"data\" else False\n            if not mgmtModeIsData:\n                respObj.addErrorReport(funcName, \"Inband Management is supported with 'LAN Device Management Connectivity' \"\n                  \"Server Setting set to 'Data' only. Please update the setting and retry the management mode change.\")\n                respObj.setFailureRetCode()\n                return respObj\n\n        supportedSwitchRoles = [\"leaf\", \"spine\", \"border\", \"broder spine\", \"border gateway\", \"border gateway spine\"]\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = filter(None, (topologyDataObj.get(TopologyInfoType.SWITCHES)))  # all devices serial number\n        for devSerial in devices:\n            # make sure the switches are not in migration mode for some other reason\n            ptiList = Util.exe(PTIWrapper.get(devSerial, \"SWITCH\", \"SWITCH\", \"\", \"switch_migration_state\"))\n            for pti in ptiList:\n                # switch already in migration mode.. check further and report erorr as needed\n                if pti.isDeleted():\n                    continue\n                if (pti.getNvPairs().get(\"TARGET_MGMT_MODE\", None) is None):\n                    # switch is in some other migration mode.. report error\n                    respObj.addErrorReport(funcName, \"Switch is already in migration mode. Please complete associated \"\n                      \"action and retry the management mode change.\", devSerial)\n                    respObj.setFailureRetCode()\n                    continue\n\n            if inbandMgmtEnable:\n                # make sure the switch role is supported for Inband Mgmt\n                switchRole = topologyDataObj.getSwitchRole(devSerial)\n                if (switchRole.lower() not in supportedSwitchRoles):\n                    respObj.addErrorReport(funcName, \"Role [%s] is not supported for Inband Management.\" % (switchRole), devSerial)\n                    respObj.setFailureRetCode()\n                    continue\n\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        # do the following checks for the target mgmt mode before putting switches into migration mode\n        # OOB:\n        #   - mgmt0 intent must be present with a valid IP\n        # Inband\n        #   - bgp routing lo intf must be present with a valid IP\n        #\n        # target IP address must be pingable\n        for devSerial in devices:\n            targetMode = (\"Inband\" if inbandMgmtEnable else \"OOB\")\n\n            Wrapper.print(\"%s: Switch [%s] Target Mgmt Mode [%s]\" % (funcName, devSerial, targetMode))\n            newDiscIP = None\n            newDiscIntf = None\n            intfTmplName = None\n            if targetMode == \"OOB\":\n                newDiscIntf = \"mgmt0\"\n                intfTmplName = \"int_mgmt\"\n            else:\n                newDiscIntf = \"loopback\" + fabricSettings.get(\"BGP_LB_ID\", \"0\")\n                intfTmplName = \"int_fabric_loopback_11_1\"\n\n            intfPti = None\n            srchOpt = CtrlPolicySearch()\n            srchOpt.setSerialNumber(devSerial)\n            srchOpt.setEntityName(newDiscIntf)\n            srchOpt.setTemplateName(intfTmplName)\n            srchOpt.setTemplateContentType(\"PYTHON\")\n            intfPtis = Util.exe(PTIWrapper.getPTIs(srchOpt))\n            for pti in intfPtis:\n                if pti.isDeleted():\n                    continue\n                intfPti = pti\n                break\n\n            if intfPti is None:\n                respObj.addErrorReport(getFabErrEntity(funcName, devSerial+\":DiscoveryIPChange\"),\n                               \"Interface policy for interface [%s] not found. \"\n                               \"Please double check and retry Recalculate & Deploy\" % (newDiscIntf), devSerial)\n                respObj.setFailureRetCode()\n                continue\n\n            if targetMode == \"OOB\":\n                #   - make sure the mgmt0 intf intent is present to get the mgmt0 IP address\n                intfFF = intfPti.getNvPairs().get(\"CONF\", None)\n                for line in intfFF.split(Util.newLine()):\n                    stripLine = line.strip()\n                    if stripLine.startswith(\"ip address \"):\n                        parts = stripLine.split(\" \")\n                        newDiscIP = parts[2].split(\"/\")[0]\n                        break\n            else:\n                #   - make sure the lo0 intf intent is present to get the IP address\n                newDiscIP = intfPti.getNvPairs().get(\"IP\", None)\n\n            if newDiscIP is None:\n                respObj.addErrorReport(getFabErrEntity(funcName, devSerial+\":DiscoveryIPChange\"),\n                     \"IP address for interface [%s] not found. \"\n                     \"Please double check and retry changing the 'Inband Management' fabric settings.\" % (newDiscIntf), devSerial)\n                respObj.setFailureRetCode()\n                continue\n\n            # make sure the target IP is pingable\n            # cmd = \"ping -i .5 -c 2 -t 2 -W 2 \" + newDiscIP\n            # Wrapper.print(\"%s: IP rechability check with [%s]\"%(funcName, cmd))\n\n            # response = os.system(cmd)\n            # if response != 0:\n            #     respObj.addErrorReport(getFabErrEntity(funcName, devSerial+\":DiscoveryIPChange\"),\n            #          \"IP address [%s] for interface [%s] is not reachable. \"\n            #          \"Please double check and retry changing the 'Inband Management' fabric settings.\" % (newDiscIP, newDiscIntf), devSerial)\n            #     respObj.setFailureRetCode()\n            #     return respObj\n\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        # pre-conditions are met.. put switches in migration mode to allow the OOB <--> Inband mgmt change\n        for devSerial in devices:\n            ptiList = Util.exe(PTIWrapper.get(devSerial, \"SWITCH\", \"SWITCH\", \"\", \"switch_migration_state\"))\n            for pti in ptiList:\n                PTIWrapper.deleteInstance(pti.getPolicyId());\n            nvPairs = {\"TARGET_MGMT_MODE\" : \"Inband\" if inbandMgmtEnable else \"OOB\"}\n            Util.exe(PTIWrapper.create(devSerial, \"SWITCH\", \"SWITCH\", \"\", 10,\n                                  \"switch_migration_state\", nvPairs, \"Management mode change\"))\n        \ndef preUpgrade(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: preUpgrade\" % (FABRIC_NAME))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        upgFromVer = dictionaryObj.get(\"UPGRADE_FROM\", \"\")\n        Wrapper.print(\"==========preUpgrade: Fabric Name = %s, keys = %d, UPGRADE_FROM = [%s]\" %\n                (FABRIC_NAME, len(dictionaryObj), upgFromVer))\n        dictionaryObj[\"FABRIC_NAME\"] = FABRIC_NAME\n        respObj = Util.exe(PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dictionaryObj, \"preUpgradeExt\"))\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preUpgrade: Success = [%r]\" %\n                (FABRIC_NAME, respObj.isRetCodeSuccess()))\n        return respObj\n\ndef isInbandPoapEnabled(dictObj):\n    inbandMgmt = dictObj.get(\"INBAND_MGMT\", \"false\")\n    bootstrapPOAPEnable = dictObj.get(\"BOOTSTRAP_ENABLE\", \"false\")\n    return (\"true\" if (inbandMgmt == \"true\" and bootstrapPOAPEnable == \"true\") else \"false\")\n\ndef fabricInit(dictionaryObj):\n    global FABRIC_INTERFACE_TYPE, REPLICATION_MODE, FEATURE_PTP, VPC_DOMAIN_ID_RANGE, SITE_ID, BANNER\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n\n    try:\n        Util.exe(actionAllow())\n\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        fabricSettings[\"FABRIC_TYPE\"] = \"Switch_Fabric\"\n\n        inbandMgmt = fabricSettings.get(\"INBAND_MGMT\", \"false\")\n        bootstrapPOAPEnable = fabricSettings.get(\"BOOTSTRAP_ENABLE\", \"false\")\n        bootstrapPOAPEnablePrev = fabricSettings.get(\"BOOTSTRAP_ENABLE_PREV\", \"false\")\n        inbandPOAPEnable = \"true\" if (inbandMgmt == \"true\" and bootstrapPOAPEnable == \"true\") else \"false\"\n\n        checkInbandMgmtSettings(fabricSettings, respObj)\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        failStr = isValidBrownfieldNetworkFormat(BROWNFIELD_NETWORK_NAME_FORMAT)\n        if failStr:\n            respObj.addErrorReport(funcName,\n                \"The network name format [%s] used for Brownfield import is invalid. Reason - %s. Please refer to the documentation for additional information.\" %\n                (BROWNFIELD_NETWORK_NAME_FORMAT, failStr))\n            respObj.setFailureRetCode()\n            return respObj\n\n        # check the fabric wide links extra config\n        errCmd, adjFabricExtraLinkCfg = Util.getAdjustedIntfFreeformConfig(EXTRA_CONF_INTRA_LINKS)\n        if errCmd != \"\":\n            respObj.addErrorReport(funcName,\n                \"The Intra fabric link interface freeform extra configuration must not contain the \\'interface\\' keyword. Please remove the command %s\" %\n                (errCmd))\n            respObj.setFailureRetCode()\n            return respObj\n\n        # validate the OSPF Area ID\n        if OSPF_AREA_ID != \"\":\n            if not Util.isValidOspfAreaIdIPString(OSPF_AREA_ID):\n               respObj.addErrorReport(funcName,\n                \"[%s] - Invalid OSPF Area ID IP String. Please make sure the IP address is valid and contains no white spaces.\" % OSPF_AREA_ID)\n               respObj.setFailureRetCode()\n               return respObj\n\n        # validate ANYCAST_GW_MAC\n        agw_mac = Util.normalizeMac(ANYCAST_GW_MAC)\n        if int(agw_mac[0:2], 16) & 0x01 != 0:\n            respObj.addErrorReport(funcName, \"Anycast Gateway MAC needs to be unicast mac address. \")\n            respObj.setFailureRetCode()\n            return respObj\n\n        pmEnable = fabricSettings.get(\"PM_ENABLE\", \"false\")\n        pmEnablePrev = fabricSettings.get(\"PM_ENABLE_PREV\", \"false\")\n        if pmEnable != pmEnablePrev:\n            turnOnPM = True if pmEnable == \"true\" else False\n            isFeatEnabled = Util.exe(FabricWrapper.isFeatureEnabled(\"pm\"))\n            if isFeatEnabled:\n                FabricWrapper.enOrDisFabricPM(FABRIC_NAME, turnOnPM)\n            else:\n                pmForceUpd = \"false\" if fabricSettings.get(\"PM_FORCE_UPD\", \"true\") == \"true\" else \"true\"\n                FabricWrapper.update(FABRIC_NAME,\"PM_FORCE_UPD\", pmForceUpd)\n                respObj.addErrorReport(funcName, \"Performance Monitoring feature is not started. \"\n                                       \"Please start Performance Monitoring from Feature Management and retry this operation.\")\n                respObj.setFailureRetCode()\n                return respObj\n\n    \t#Validate BGP AS number\n        Util.exe(Helper.isValidAsn(BGP_AS))\n\n        # validate Site ID\n        # This is a non mandatory parameter and input can be the following:\n        #   > empty - in this case, we will set it to the BGP_AS\n        #   > X - if integer, need validaiton to make sure it is within the range\n        #   > X.Y - may or not be the same as BGP AS. Same validation rules as BGP ASN. \n        #           Update the fabric settings with the equivalent decimal value using siteId = (65536 * X) + Y\n        newSiteId = SITE_ID\n        updateSiteId = False\n        if SITE_ID == \"\":\n            Wrapper.print(\"%s: Setting Site ID to BGP_AS [%s]\" % (funcName, BGP_AS))\n            newSiteId = BGP_AS\n\n        match = re.search('''\\.''', newSiteId)\n        if match:\n            # Site ID is in the X.Y format\n            tokens = newSiteId.split('.')\n            if len(tokens) == 2:\n                # make sure the Site ID passes the BGP AS validation rules\n                rObj = Helper.isValidAsn(newSiteId)\n                if rObj.isRetCodeFailure():\n                   respObj.addErrorReport(funcName, \"SITE ID is invalid. Please follow BGP AS number requirements.\")\n                   respObj.setFailureRetCode()\n                   return respObj\n\n                newSiteId = str(int(65536 * int(tokens[0])) + int (tokens[1]))\n                Wrapper.print(\"%s: token1: [%s] token 2: [%s]. Site ID = [%s]\" %(funcName, tokens[0], tokens[1], newSiteId))\n                updateSiteId = True\n        else:\n           match   = re.search('(^[0-9]+$)', newSiteId)\n           if match is None:\n               respObj.addErrorReport(funcName, \"SITE ID is invalid. Valid values: <1-281474976710655>\")\n               respObj.setFailureRetCode()\n               return respObj\n           else:\n               site_id_int = long(newSiteId)\n               if site_id_int < 1 or site_id_int > 281474976710655:\n                   respObj.addErrorReport(funcName, \"SITE ID not valid. Valid values: <1-281474976710655>\")\n                   respObj.setFailureRetCode()\n                   return respObj\n               elif SITE_ID != newSiteId:\n                   updateSiteId = True\n\n        Wrapper.print(\"%s: SITE_ID: [%s] newSiteId [%s] updateSiteId [%r]\" %(funcName, SITE_ID, newSiteId, updateSiteId))\n        if updateSiteId:\n            SITE_ID = newSiteId\n            fabricSettings[\"SITE_ID\"] = SITE_ID\n            #Util.exe(Helper.setFabricSiteId(FABRIC_NAME, newSiteId))\n\n        try:\n            getRespObj = FabricWrapper.getParentFabricName(FABRIC_NAME)\n            if getRespObj.isRetCodeSuccess():\n                parentFabric = getRespObj.getValue()\n                msLoopbackId = Util.exe(FabricWrapper.get(parentFabric, \"MS_LOOPBACK_ID\"))\n                if msLoopbackId == BGP_LB_ID or msLoopbackId == NVE_LB_ID:\n                    errorMsg = (\"Cannot change 'Underlay %s Loopback Id' to %s since \"\n                        \"it conflicts with 'Multi-site Routing Loopback Id' in parent fabric [%s]\"\n                        % (\"Routing\" if msLoopbackId==BGP_LB_ID else \"NVE\", BGP_LB_ID if msLoopbackId==BGP_LB_ID else NVE_LB_ID, parentFabric))\n                    Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                    respObj.addErrorReport(funcName, errorMsg)\n                    respObj.setFailureRetCode()\n                    return respObj\n        except:\n            Wrapper.print(\"exception, ignore if not member fabric\")\n            pass\n\n        # validate BANNER\n        if BANNER.strip():\n            BANNER=BANNER.strip()\n            if len(BANNER) < 3:\n                errorMsg = (\"Banner field needs to be delimiter char followed by non-empty message ending with delimiter \")\n                Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n            if BANNER[0] != BANNER[-1]:\n                errorMsg = (\"Banner field's starting char '%s' and ending char '%s' do not match. Banner field needs to be delimiter char followed by message ending with delimiter\"%(BANNER[0], BANNER[-1]))\n                Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n            if BANNER[0] in BANNER[1:-1]:\n                errorMsg = (\"Banner field using '%s' as delimiter cannot have '%s' inside banner message\" %(BANNER[0], BANNER[0]))\n                Wrapper.print(\"%s: %s\" % (funcName, errorMsg))\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n        if UNDERLAY_IS_V6 == \"true\":\n            if FABRIC_INTERFACE_TYPE != \"p2p\":\n                fabricSettings[\"FABRIC_INTERFACE_TYPE\"] = \"p2p\"\n                FABRIC_INTERFACE_TYPE = \"p2p\"\n\n            if REPLICATION_MODE != \"Ingress\":\n                fabricSettings[\"REPLICATION_MODE\"] = \"Ingress\"\n                REPLICATION_MODE = \"Ingress\"\n\n            if FEATURE_PTP != \"false\":\n                fabricSettings[\"FEATURE_PTP\"] = \"false\"\n                FEATURE_PTP = \"false\"\n\n        # Initialize IsShow dependent variables to their default values if\n        # they are set to blank by the backend because the IsShow evaluation is False.\n        # Only variables that are identified to show different behavior from 11.3 if\n        # they are left blank are initialized.\n        if USE_LINK_LOCAL == \"\":\n            fabricSettings[\"USE_LINK_LOCAL\"] = \"true\"\n        if ENABLE_DEFAULT_QUEUING_POLICY == \"\":\n            fabricSettings[\"ENABLE_DEFAULT_QUEUING_POLICY\"] = \"false\"\n        if FABRIC_VPC_QOS == \"\":\n            fabricSettings[\"FABRIC_VPC_QOS\"] = \"false\"\n        if GRFIELD_DEBUG_FLAG == \"\":\n            fabricSettings[\"GRFIELD_DEBUG_FLAG\"] = \"Disable\"\n        if MPLS_HANDOFF == \"\":\n            fabricSettings[\"MPLS_HANDOFF\"] = \"false\"\n\n        if FABRIC_INTERFACE_TYPE == \"\":\n            fabricSettings[\"FABRIC_INTERFACE_TYPE\"] = \"p2p\"\n        if SUBNET_TARGET_MASK == \"\":\n            fabricSettings[\"SUBNET_TARGET_MASK\"] = \"30\"\n        if V6_SUBNET_TARGET_MASK == \"\":\n            fabricSettings[\"V6_SUBNET_TARGET_MASK\"] = \"126\"\n        if REPLICATION_MODE == \"\":\n            fabricSettings[\"REPLICATION_MODE\"] = \"Multicast\"\n        if ENABLE_TRM == \"\":\n            fabricSettings[\"ENABLE_TRM\"] = \"false\"\n        if RP_MODE == \"\":\n            fabricSettings[\"RP_MODE\"] = \"asm\"\n        if RP_COUNT == \"\":\n            fabricSettings[\"RP_COUNT\"] = \"2\"\n        if FABRIC_VPC_QOS_POLICY_NAME == \"\":\n            fabricSettings[\"FABRIC_VPC_QOS_POLICY_NAME\"] = \"spine_qos_for_fabric_vpc_peering\"\n        if OSPF_AUTH_ENABLE == \"\":\n           fabricSettings[\"OSPF_AUTH_ENABLE\"] = \"false\"\n        if ISIS_LEVEL == \"\":\n           fabricSettings[\"ISIS_LEVEL\"] = \"level-2\"\n        if ISIS_AUTH_ENABLE == \"\":\n            fabricSettings[\"ISIS_AUTH_ENABLE\"] = \"false\"\n        if BGP_AUTH_ENABLE == \"\":\n            fabricSettings[\"BGP_AUTH_ENABLE\"] = \"false\"\n        if BGP_AUTH_KEY_TYPE == \"\":\n            fabricSettings[\"BGP_AUTH_KEY_TYPE\"] = \"3\"\n        if PIM_HELLO_AUTH_ENABLE == \"\":\n            fabricSettings[\"PIM_HELLO_AUTH_ENABLE\"] = \"false\"\n        if BFD_ENABLE == \"\":\n            fabricSettings[\"BFD_ENABLE\"] = \"false\"\n        if BFD_IBGP_ENABLE == \"\":\n            fabricSettings[\"BFD_IBGP_ENABLE\"] = \"false\"\n        if BFD_OSPF_ENABLE == \"\":\n            fabricSettings[\"BFD_OSPF_ENABLE\"] = \"false\"\n        if BFD_ISIS_ENABLE == \"\":\n            fabricSettings[\"BFD_ISIS_ENABLE\"] = \"false\"\n        if BFD_PIM_ENABLE == \"\":\n            fabricSettings[\"BFD_PIM_ENABLE\"] = \"false\"\n        if BFD_AUTH_ENABLE == \"\":\n            fabricSettings[\"BFD_AUTH_ENABLE\"] = \"false\"\n        if ENABLE_NXAPI_HTTP == \"\":\n            fabricSettings[\"ENABLE_NXAPI_HTTP\"] = \"true\"\n        if NXAPI_HTTPS_PORT == \"\":\n            fabricSettings[\"NXAPI_HTTPS_PORT\"] = \"443\"\n        if NXAPI_HTTP_PORT == \"\":\n            fabricSettings[\"NXAPI_HTTP_PORT\"] = \"80\"\n        if FEATURE_PTP == \"\":\n            fabricSettings[\"FEATURE_PTP\"] = \"false\"\n        if ENABLE_DEFAULT_QUEUING_POLICY == \"\":\n            fabricSettings[\"ENABLE_DEFAULT_QUEUING_POLICY\"] = \"false\"\n        if DEAFULT_QUEUING_POLICY_CLOUDSCALE == \"\":\n            fabricSettings[\"DEAFULT_QUEUING_POLICY_CLOUDSCALE\"] = \"queuing_policy_default_8q_cloudscale\"\n        if DEAFULT_QUEUING_POLICY_R_SERIES == \"\":\n            fabricSettings[\"DEAFULT_QUEUING_POLICY_R_SERIES\"] = \"queuing_policy_default_r_series\"\n        if DEAFULT_QUEUING_POLICY_OTHER == \"\":\n            fabricSettings[\"DEAFULT_QUEUING_POLICY_OTHER\"] = \"queuing_policy_default_other\"\n\n        if STP_ROOT_OPTION == \"\":\n            fabricSettings[\"STP_ROOT_OPTION\"] = \"unmanaged\"\n\n        if AUTO_SYMMETRIC_VRF_LITE == \"\":\n            fabricSettings[\"AUTO_SYMMETRIC_VRF_LITE\"] = \"false\"\n        if AUTO_VRFLITE_IFC_DEFAULT_VRF == \"\":\n            fabricSettings[\"AUTO_VRFLITE_IFC_DEFAULT_VRF\"] = \"false\"\n        if AUTO_SYMMETRIC_DEFAULT_VRF == \"\":\n            fabricSettings[\"AUTO_SYMMETRIC_DEFAULT_VRF\"] = \"false\"\n\n        if DHCP_ENABLE == \"\":\n            fabricSettings[\"DHCP_ENABLE\"] = \"false\"\n        if DHCP_ENABLE == \"true\" and DHCP_IPV6_ENABLE == \"\":\n            fabricSettings[\"DHCP_IPV6_ENABLE\"] = \"DHCPv4\"\n        if ENABLE_AAA == \"\":\n            fabricSettings[\"ENABLE_AAA\"] = \"false\"\n        if VPC_DOMAIN_ID_RANGE == \"\":\n            VPC_DOMAIN_ID_RANGE = \"1-1000\"\n            fabricSettings[\"VPC_DOMAIN_ID_RANGE\"] = VPC_DOMAIN_ID_RANGE\n        if OVERLAY_MODE == \"\":\n            fabricSettings[\"OVERLAY_MODE\"] = \"config-profile\"\n        if HOST_INTF_ADMIN_STATE == \"\":\n            fabricSettings[\"HOST_INTF_ADMIN_STATE\"] = \"true\"\n\n        fabricSettings[\"PM_ENABLE_PREV\"] = pmEnable\n        fabricSettings[\"INBAND_MGMT_PREV\"] = inbandMgmt \n        fabricSettings[\"BOOTSTRAP_ENABLE_PREV\"] = bootstrapPOAPEnable     \n        # show the example if DHCP is enabled later\n        if DHCP_ENABLE != \"true\" and BOOTSTRAP_MULTISUBNET == \"\":\n            fabricSettings[\"BOOTSTRAP_MULTISUBNET\"] = \"#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix\"\n        \n        # update the template names that have changed from 11.x\n        if temp_vpc_peer_link == \"int_vpc_peer_link_po_11_1\":\n            fabricSettings[\"temp_vpc_peer_link\"] = \"int_vpc_peer_link_po\"\n        if abstract_routed_host == \"int_routed_host_11_1\":\n            fabricSettings[\"abstract_routed_host\"] = \"int_routed_host\"\n        if abstract_trunk_host == \"int_trunk_host_11_1\":\n            fabricSettings[\"abstract_trunk_host\"] = \"int_trunk_host\"\n\n        FabricWrapper.update(FABRIC_NAME, fabricSettings)\n\n        if REPLICATION_MODE == \"Multicast\":\n            #Verify that mask length for multicast subnet is between 8 and 30\n            tokens = MULTICAST_GROUP_SUBNET.split(\"/\")\n            if len(tokens) == 2:\n                prefix = int(tokens[1])\n                if prefix < 8 or prefix > 30:\n                    respObj.addErrorReport(funcName,\n                          \"Multicast subnet prefix length supported is 8 - 30: Value: \"+ str(prefix))\n                    respObj.setFailureRetCode()\n                    return respObj\n            else:\n                Wrapper.print(\"fabricInit: MULTICAST_GROUP_SUBNET: Tokens equal:\" + str(len(tokens)))\n                respObj.addErrorReport(funcName, \"Multicast subnet invalid: \" + MULTICAST_GROUP_SUBNET)\n                respObj.setFailureRetCode()\n                return respObj\n\n            respObj = Helper.isValidIPv4MCAddress(MULTICAST_GROUP_SUBNET)\n            if respObj.isRetCodeFailure():\n                return respObj\n            else:\n                Wrapper.print(\"fabricInit: MC group subnet is Valid\")\n\n            if ((ENABLE_TRM == \"true\") and (L3VNI_MCAST_GROUP != \"\")):\n                addr, prefix = MULTICAST_GROUP_SUBNET.split(\"/\")\n                mcastGroupSubnet = Util.getSubnetStringWithPrefix(addr, prefix)\n                mdtAddressSubnet = Util.getSubnetStringWithPrefix(L3VNI_MCAST_GROUP, prefix)\n                if mcastGroupSubnet != mdtAddressSubnet:\n                    errorMsg = (\"Default MDT address for TRM VRFs [%s] must be an address \"\n                                \"within the underlay multicast group subnet [%s]\" %\n                                (L3VNI_MCAST_GROUP, MULTICAST_GROUP_SUBNET))\n                    respObj.addErrorReport(funcName, errorMsg)\n                    return respObj\n            \n            if RP_MODE == \"bidir\":\n                # Verify that mask length for RP subnet for PIM Bidir must be 24\n                tokens = ANYCAST_RP_IP_RANGE.split(\"/\")\n                Wrapper.print(\"fabricInit: ANYCAST_RP_IP_RANGE: Tokens [%d]\" % (len(tokens)))\n                if len(tokens) == 2:\n                    prefix = int(tokens[1])\n                    if prefix != 24:\n                        respObj.addErrorReport(funcName, \"Phantom RP subnet prefix length must be 24: Value: \" + str(prefix))\n                        respObj.setFailureRetCode()\n                        return respObj\n                else:\n                    respObj.addErrorReport(funcName, \"RP subnet invalid: \" + ANYCAST_RP_IP_RANGE)\n                    respObj.setFailureRetCode()\n                    return respObj\n        else:\n            Wrapper.print(\"fabricInit: Not validating MC/RP Subnet as mode is: \" + REPLICATION_MODE)\n\n            if ENABLE_TRM == \"true\":\n                Wrapper.print(\"fabricInit: TRM can not be enabled while Replication Mode is Ingress\")\n                respObj.addErrorReport(funcName, \"TRM can not be enabled while Replication Mode is Ingress\")\n                respObj.setFailureRetCode()\n                return respObj\n\n        dict = getGlobals()\n        dict[\"GLOBALS_SET\"] = False\n        processRespObj(respObj, PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dict, \"sanityCheckLoopbackId\"))\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        Wrapper.print(\"Syntax check on IBGP_PEER_TEMPLATE %s\" % IBGP_PEER_TEMPLATE)\n        if IBGP_PEER_TEMPLATE:\n            bgp_peer_template = IBGP_PEER_TEMPLATE.splitlines()\n            Wrapper.print(\"bgp_peer_template %s\" % bgp_peer_template)\n            remote_as_present, af_evpn_present, af_mvpn_present, errorMsg = False, False, False, \"\"\n\n            errCmd = \"\"\n            for index, cmd in enumerate(bgp_peer_template):\n                if index == 0:\n                    if not cmd.startswith(\"  \") or cmd[2] == \" \":\n                        errorMsg += \"iBGP peer template: bgp peer template command must have 2 leading spaces. Please fix spacing problem: %s. \" % cmd\n                elif not cmd.startswith(\"    \"):\n                    errCmd += (\"[%s] \" % cmd)\n            if errCmd != \"\":\n                errorMsg += \"iBGP peer template: bgp peer template sub-command must have 4 or 6 leading spaces. Please fix spacing problem in the following commands: %s. \" % errCmd\n\n            if not bgp_peer_template[0].strip().startswith('template peer') and not bgp_peer_template[0].strip().startswith('template peer-session'):\n                errorMsg += \"iBGP peer template: peer template needs to start with '  template peer' or '  template peer-session'. \"\n            else:\n                peer_cmd = bgp_peer_template[0].strip().split(\" \")\n                if len(peer_cmd) != 3:\n                    errorMsg += \"iBGP peer template: command '%s' has invalid syntax. \" % bgp_peer_template[0]\n\n            for index, line in enumerate(bgp_peer_template, start=1):\n                if line.strip().startswith('remote-as'):\n                    remote_as_present = True\n                    if not line.startswith(\"    re\"):\n                        errorMsg += \"iBGP peer template: remote-as command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                    as_cmd = line.strip().split(' ')\n                    if len(as_cmd) == 2:\n                        if as_cmd[1] != BGP_AS:\n                            errorMsg += \"iBGP peer template: remote ASN %s does not match fabric BGP ASN %s. \" % (as_cmd[1], BGP_AS)\n                    else:\n                        errorMsg += \"iBGP peer template: '%s' command with invalid syntax. \" % line\n                elif line.strip() == 'address-family l2vpn evpn':\n                    af_evpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                elif line.strip() == 'address-family ipv4 mvpn':\n                    af_mvpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n\n            if not remote_as_present:\n                errorMsg += \"iBGP peer template: missing 'remote-as' command. \"\n            if not af_evpn_present:\n                errorMsg += \"iBGP peer template: missing 'address-family l2vpn evpn' command. \"\n            if ENABLE_TRM == \"true\" and not af_mvpn_present:\n                errorMsg += \"iBGP peer template: missing 'address-family ipv4 mvpn' command. \"\n            if ENABLE_TRM != \"true\" and af_mvpn_present:\n                errorMsg += \"iBGP peer template: 'address-family ipv4 mvpn' present while Tenant Routed Multicast is not enabled. \"\n\n            if errorMsg:\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n        Wrapper.print(\"Syntax check on IBGP_PEER_TEMPLATE_LEAF %s\" % IBGP_PEER_TEMPLATE_LEAF)\n        if IBGP_PEER_TEMPLATE_LEAF:\n            if not IBGP_PEER_TEMPLATE:\n                errorMsg = \"Please fill the iBGP peer template field when Leaf/Border/Border Gateway iBGP peer template is non empty. \"\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n            bgp_peer_template = IBGP_PEER_TEMPLATE_LEAF.splitlines()\n            Wrapper.print(\"leaf bgp_peer_template %s\" % bgp_peer_template)\n            remote_as_present, af_evpn_present, af_mvpn_present, rr_client_present, errorMsg = False, False, False, False, \"\"\n\n            errCmd = \"\"\n            for index, cmd in enumerate(bgp_peer_template):\n                if index == 0:\n                    if not cmd.startswith(\"  \") or cmd[2] == \" \":\n                        errorMsg += \"Leaf iBGP peer template: bgp peer template command must have 2 leading spaces. Please fix spacing problem: %s. \" % cmd\n                elif not cmd.startswith(\"    \"):\n                    errCmd += (\"[%s] \" % cmd)\n            if errCmd != \"\":\n                errorMsg += \"Leaf iBGP peer template: bgp peer template sub-command must have 4 or 6 leading spaces. Please fix spacing problem in the following commands: %s. \" % errCmd\n\n            if not bgp_peer_template[0].strip().startswith('template peer') and not bgp_peer_template[0].strip().startswith('template peer-session'):\n                errorMsg += \"Leaf iBGP peer template: peer template needs to start with '  template peer' or '  template peer-session'. \"\n            else:\n                peer_cmd = bgp_peer_template[0].strip().split(\" \")\n                if len(peer_cmd) != 3:\n                    errorMsg += \"Leaf iBGP peer template: command '%s' has invalid syntax. \" % bgp_peer_template[0]\n\n            for index, line in enumerate(bgp_peer_template, start=1):\n                if line.strip().startswith('route-reflector-client'):\n                    rr_client_present = True\n\n                if line.strip().startswith('remote-as'):\n                    remote_as_present = True\n                    if not line.startswith(\"    r\"):\n                        errorMsg += \"Leaf iBGP peer template: remote-as command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                    as_cmd = line.strip().split(' ')\n                    if len(as_cmd) == 2:\n                        if as_cmd[1] != BGP_AS:\n                            errorMsg += \"Leaf iBGP peer template: remote ASN %s does not match fabric BGP ASN %s. \" % (as_cmd[1], BGP_AS)\n                    else:\n                        errorMsg += \"Leaf iBGP peer template: '%s' command with invalid syntax. \" % line\n                elif line.strip() == 'address-family l2vpn evpn':\n                    af_evpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"Leaf iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n                elif line.strip() == 'address-family ipv4 mvpn':\n                    af_mvpn_present = True\n                    if not line.startswith(\"    a\"):\n                        errorMsg += \"Leaf iBGP peer template: address-family command must start with 4 leading spaces. Please fix spacing problem:%s. \" % line\n\n            if rr_client_present:\n                errorMsg += \"Leaf iBGP peer template should not contain 'route-reflector-client' command. \"\n            if not remote_as_present:\n                errorMsg += \"Leaf iBGP peer template: missing 'remote-as' command. \"\n            if not af_evpn_present:\n                errorMsg += \"Leaf iBGP peer template: missing 'address-family l2vpn evpn' command. \"\n            if ENABLE_TRM == \"true\" and not af_mvpn_present:\n                errorMsg += \"Leaf iBGP peer template: missing 'address-family ipv4 mvpn' command. \"\n            if ENABLE_TRM != \"true\" and af_mvpn_present:\n                errorMsg += \"Leaf iBGP peer template: 'address-family ipv4 mvpn' present while Tenant Routed Multicast is not enabled. \"\n\n            if errorMsg:\n                respObj.addErrorReport(funcName, errorMsg)\n                respObj.setFailureRetCode()\n                return respObj\n\n        if not checkFabricMtuSettings(respObj):\n            return respObj\n\n        if not checkFabricVpcDomainId(respObj):\n            return respObj\n\n        if not checkBgpAsChange(respObj):\n            return respObj\n\n        if not checkLinkProtocolTagChange(respObj):\n            return respObj\n\n        if not checkOverlayModeChange(respObj):\n            return respObj\n\n        if not macSecSanityCheck(respObj):\n            return respObj\n\n        # check loopback resource range\n        if STATIC_UNDERLAY_IP_ALLOC == \"false\":\n            if UNDERLAY_IS_V6 == \"false\":\n                ip0, mask0 = LOOPBACK0_IP_RANGE.split(\"/\")\n                ip1, mask1 = LOOPBACK1_IP_RANGE.split(\"/\")\n                if mask0 == \"32\" or mask1 == \"32\":\n                    errMsg = \"Underlay Routing or VTEP Loopback IP Range Mask has to be smaller than 32. \"\n                    respObj.addErrorReport(funcName, errMsg)\n                    respObj.setFailureRetCode()\n                if MPLS_HANDOFF == \"true\":\n                    ip, mask = MPLS_LOOPBACK_IP_RANGE.split(\"/\")\n                    if mask == \"32\":\n                        errMsg = \"MPLS Loopback IP Range Mask has to be smaller than 32. \"\n                        respObj.addErrorReport(funcName, errMsg)\n                        respObj.setFailureRetCode()\n            else:\n                ip0, mask0 = LOOPBACK0_IPV6_RANGE.split(\"/\")\n                ip1, mask1 = LOOPBACK1_IPV6_RANGE.split(\"/\")\n                if mask0 == \"128\" or mask1 == \"128\":\n                    errMsg = \"Underlay Loopback IPV6 Range Mask has to be smaller than 128.\"\n                    respObj.addErrorReport(funcName, errMsg)\n                    respObj.setFailureRetCode()\n\n            if respObj.isRetCodeFailure():\n                return respObj\n\n        dynamicIPPoolsEnable = True\n        try:\n            if STATIC_UNDERLAY_IP_ALLOC == \"true\":\n                dynamicIPPoolsEnable = False\n        except:\n            pass\n\n        # Initialization of resource manager for Underlay Resources.\n        if dynamicIPPoolsEnable:\n            dictObj = {\"FABRIC_NAME\" : FABRIC_NAME}\n            newRespObj = PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"checkIfDuplicatePools\")\n            Util.processRespObj(respObj, newRespObj)\n            if UNDERLAY_IS_V6 == \"false\":\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET, SUBNET_RANGE, SUBNET_TARGET_MASK))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", PoolType.IP, LOOPBACK0_IP_RANGE))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK1_IP_POOL\", PoolType.IP, LOOPBACK1_IP_RANGE))\n\n                # special processing for Inband POAP and unnumbered fabric\n                if inbandPOAPEnable == \"true\" and FABRIC_INTERFACE_TYPE != \"p2p\":\n                    #   - set RM with the anycast IP for the POAP default GW (the first IP in the range)\n                    lb0NwkAddr = LOOPBACK0_IP_RANGE.split(\"/\")[0]\n                    lb0NwkPrefix = LOOPBACK0_IP_RANGE.split(\"/\")[1]\n\n                    #Pick first address in loopback0 ip range as the default gw for the DHCP subnet scope programming\n                    lb0NwkBytes = lb0NwkAddr.split(\".\")\n                    lb0NwkGwLastByte = int(lb0NwkBytes[3]) + 1\n                    dhcpUnnumGwIp = lb0NwkBytes[0] + \".\" + lb0NwkBytes[1] + \".\" + lb0NwkBytes[2] + \".\" + str(lb0NwkGwLastByte)\n\n                    Wrapper.print(\"%s: FAB [%s]: dhcpUnnumGwIp [%r]\" % (funcName, FABRIC_NAME, dhcpUnnumGwIp))\n                    # reserve this in RM for DHCP code to use\n                    Util.exeRM(RM.set(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", EntityType.FABRIC, \"INBAND_POAP_GW\", dhcpUnnumGwIp))\n\n                ip, mask = ANYCAST_RP_IP_RANGE.split(\"/\") if ANYCAST_RP_IP_RANGE else (\"\",\"\")\n                if mask == \"32\":\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"ANYCAST_RP_IP_POOL\", PoolType.IP))\n                else:\n                    Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"ANYCAST_RP_IP_POOL\", PoolType.IP, ANYCAST_RP_IP_RANGE))\n\n                if MPLS_HANDOFF == \"true\":\n                    Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"MPLS_LOOPBACK_IP_POOL\", PoolType.IP, MPLS_LOOPBACK_IP_RANGE))\n                else:\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"MPLS_LOOPBACK_IP_POOL\", PoolType.IP))\n            else:\n                if USE_LINK_LOCAL == \"false\":\n                    Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET, V6_SUBNET_RANGE, V6_SUBNET_TARGET_MASK))\n                else:\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", PoolType.IP, LOOPBACK0_IPV6_RANGE))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK1_IP_POOL\", PoolType.IP, LOOPBACK1_IPV6_RANGE))\n                Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"ROUTER_ID_POOL\", PoolType.IP, ROUTER_ID_RANGE))\n        else:\n            # init IP pools to be empty. The IP addresses are expected to be explicitly set in RM offline\n            Wrapper.print(\"fabricInit: Init Empty Subnet Pool - PoolName.SUBNET\")\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, PoolName.SUBNET, PoolType.SUBNET))\n            Wrapper.print(\"fabricInit: Init Empty IP Pool - LOOPBACK0_IP_POOL\")\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"LOOPBACK0_IP_POOL\", PoolType.IP))\n            Wrapper.print(\"fabricInit: Init Empty IP Pool - LOOPBACK1_IP_POOL\")\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"LOOPBACK1_IP_POOL\", PoolType.IP))\n            if UNDERLAY_IS_V6 == \"false\":\n                Wrapper.print(\"fabricInit: Init Empty IP Pool - ANYCAST_RP_IP_POOL\")\n                Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"ANYCAST_RP_IP_POOL\", PoolType.IP))\n                if MPLS_HANDOFF == \"true\":\n                    Wrapper.print(\"fabricInit: Init Empty IP Pool - MPLS_LOOPBACK_IP_POOL\")\n                    Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"MPLS_LOOPBACK_IP_POOL\", PoolType.IP))\n            else:\n                Wrapper.print(\"fabricInit: Init Empty IP Pool - ROUTER_ID_POOL\")\n                Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"ROUTER_ID_POOL\", PoolType.IP))\n\n        if DCI_SUBNET_RANGE != \"\":\n            Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"DCI subnet pool\",\n                                            PoolType.SUBNET, DCI_SUBNET_RANGE,\n                                            DCI_SUBNET_TARGET_MASK))\n        else:\n            Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"DCI subnet pool\",\n                                             PoolType.SUBNET))\n            Wrapper.print(\"Empty DCI Subnet range, ignore\")\n        # Initialize an empty DCI subnet pool for IPv6\n        Util.exe(RM.addOrUpdateEmptyPool(FABRIC_NAME, \"IPv6 DCI subnet pool\", PoolType.SUBNET))\n        Wrapper.print(\"Empty IPv6 DCI Subnet range, ignore\")\n\n        # Initialization of resource manager for Overlay and Underlay Resources (port-channel and other IDs).\n        # PC ID pool should be 1-499, 501-4096 once RM get/set is working with range.\n        # 500 is default for underlay - vpc peer link port-channel and vpc id\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"PORT_CHANNEL_ID\", \"501-4000\"))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"FEX_ID\", \"101-199\"))\n\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"VPC_ID\", \"1-100, 200-499\"))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"VPC_DOMAIN_ID\", VPC_DOMAIN_ID_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"VPC_PEER_LINK_VLAN\", VPC_PEER_LINK_VLAN))\n\n        # Loopback pool should be 2-199, 201-1000 once RM get/set is working with range.\n        # 0,1,254,255 reserved for underlay - bgp, nve, border gateway, anycast rp loopbacks\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"LOOPBACK_ID\", \"0-1023\"))\n\n        # Initialization of resource manager for Overlay Resources.\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"TOP_DOWN_L3_DOT1Q\", SUBINTERFACE_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"TOP_DOWN_NETWORK_VLAN\", NETWORK_VLAN_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"TOP_DOWN_VRF_VLAN\", VRF_VLAN_RANGE))\n\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"BGP_ASN_ID\", PoolType.ID, BGP_AS))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"L3_VNI\", L3_PARTITION_ID_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"L2_VNI\", L2_SEGMENT_ID_RANGE))\n        Util.exe(RM.addOrUpdateOverlapPool(FABRIC_NAME, \"MCAST_IP_POOL\", PoolType.IP, MULTICAST_GROUP_SUBNET))\n\n        # always have the relevant pool as user may define the policies before enabling PBR flag\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"SERVICE_NETWORK_VLAN\", SERVICE_NETWORK_VLAN_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"ROUTE_MAP_SEQUENCE_NUMBER_POOL\", ROUTE_MAP_SEQUENCE_NUMBER_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"SLA_ID\", SLA_ID_RANGE))\n        Util.exe(RM.addOrUpdatePoolData(FABRIC_NAME, \"OBJECT_TRACKING_NUMBER_POOL\", OBJECT_TRACKING_NUMBER_RANGE))\n\n        # Validate additional settings\n        dict[\"FABRIC_VALIDATION_PARAMS\"] = {\"validateManagebilitySettings\": True,\n                                            \"validateNetflowSettings\" : True,\n                                            \"validatePvlanSettings\": True,\n                                            \"validateNxCloudSettings\": True,\n                                            \"validateLanDeviceConnectivityMode\" : True}\n        dict[\"FABRIC_INIT\"] = True\n        Util.exe(PTI.executePyTemplateMethod(\"fabric_utility_11_1\", dict, \"validateInitFabricSettings\"))\n\n        # validation passes. Update if applicable\n        if ENABLE_PVLAN_PREV != ENABLE_PVLAN:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"ENABLE_PVLAN_PREV\", ENABLE_PVLAN))\n\n        allowNxc = fabricSettings.get(\"ALLOW_NXC\", \"false\")\n        allowNxcPrev = fabricSettings.get(\"ALLOW_NXC_PREV\", \"false\")\n        if allowNxcPrev != allowNxc:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"ALLOW_NXC_PREV\", allowNxc))\n\n        if (AUTO_UNIQUE_VRF_LITE_IP_PREFIX == \"false\" and \n            AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV == \"false\" and\n            PER_VRF_LOOPBACK_AUTO_PROVISION == \"false\" and \n            PER_VRF_LOOPBACK_AUTO_PROVISION_PREV == \"false\" and\n            TOPDOWN_CONFIG_RM_TRACKING != \"completed\"):\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"TOPDOWN_CONFIG_RM_TRACKING\", \"notstarted\"))\n\n        autoVrfLiteUniqIp = fabricSettings.get(\"AUTO_UNIQUE_VRF_LITE_IP_PREFIX\", \"false\")\n        autoVrfLiteUniqIpPrev = fabricSettings.get(\"AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV\", \"false\")\n        if autoVrfLiteUniqIpPrev != autoVrfLiteUniqIp:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"AUTO_UNIQUE_VRF_LITE_IP_PREFIX_PREV\", autoVrfLiteUniqIp))\n            if TOPDOWN_CONFIG_RM_TRACKING == \"completed\" and autoVrfLiteUniqIp == \"true\":\n                Util.exe(FabricWrapper.update(FABRIC_NAME, \"TOPDOWN_CONFIG_RM_TRACKING\", \"restart\"))\n\n        pervrfLbProv = fabricSettings.get(\"PER_VRF_LOOPBACK_AUTO_PROVISION\", \"false\")\n        pervrfLbProvPrev = fabricSettings.get(\"PER_VRF_LOOPBACK_AUTO_PROVISION_PREV\", \"false\")\n        if pervrfLbProvPrev != pervrfLbProv:\n            Util.exe(FabricWrapper.update(FABRIC_NAME, \"PER_VRF_LOOPBACK_AUTO_PROVISION_PREV\", pervrfLbProv))\n\n\n        # dhcp initialization for DHCP IPs provided in bootstrap section.\n        dict = getGlobals(dictionaryObj)\n        Util.exe(dhcpInit(dict))\n\n        Util.exe(BRW.CreateBackUpJob(FABRIC_NAME, enableRealTimeBackup, enableScheduledBackup, scheduledTime))\n    except Exception as e:\n        if isinstance(e, respObjError):\n            Util.processRespObj(respObj, e.value)\n        else:\n            Util.handleException(\"Unexpected error creating fabric\", e, respObj)\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" %\n                (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n    return respObj\n\n#initialize DHCP scope in dchp.conf for bootstrapped devices for automatic IP assignments\ndef dhcpInit(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        respObj = PTI.executePyTemplateMethod(\"dhcp_common\", getGlobals(dictionaryObj), \"dhcpInit\")\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" % \\\n                    (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n    return respObj\n\ndef getFabErrEntity(fnName, entityName=None):\n    if entityName:\n        return fnName + \":\" + entityName\n    else:\n        return fnName\n\ndef getStrGlobals():\n    newDict = {}\n    gDict = globals()\n    for key in gDict.keys():\n        if type(gDict[key]) is str:\n            newDict[key] = gDict[key]\n    return newDict\n\ndef actionAllow():\n    Wrapper.print(\"actionAllow: FAB [%s]: FF [%s]\" % (FABRIC_NAME, FF))\n    r = WrappersResp.getRespObj()\n    r.setSuccessRetCode()\n    try:\n        extFabricType = EXT_FABRIC_TYPE\n    except:\n        extFabricType = \"\"\n\n    if FF != \"Easy_Fabric\":\n        fabricType = Util.mapFFToFabricType(FF, extFabricType)\n        article = \"An\" if fabricType[0].lower() in ['a','e','i','o','u'] else \"A\"\n        r.addErrorReport(\"actionAllow\", \"%s %s fabric may not be converted to a Data Center VXLAN EVPN fabric \"\n                         \"as that may cause configuration issues. Please revert the fabric to %s and save.\" %\n                         (article, fabricType, fabricType))\n        r.setFailureRetCode()\n    return r\n\ndef preAdd(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: preAdd: Serial [%s]\" %\n        (FABRIC_NAME, dictionaryObj[\"deviceSerial\"]))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        # need to allocate below new object using wrapper to return response of success/failure to GUI.\n        # by default below API sets retCode to SUCCESS\n        Util.exe(actionAllow())\n\n        Wrapper.print(\"==========preAdd: Fabric Name = %s, keys = %d, Device Serial = %s, Device Model = %s, Preserve Config = %s\" %\n                      (FABRIC_NAME, len(dictionaryObj), dictionaryObj[\"deviceSerial\"],  dictionaryObj[\"deviceModel\"],\n                       dictionaryObj[\"devicePreserveConfig\"]))\n        dict = getGlobals(dictionaryObj)\n        respObj = Util.exe(PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dict, \"preAddExt\"))\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preAdd: Serial [%s]. Success = [%r]\" %\n                (FABRIC_NAME, dictionaryObj[\"deviceSerial\"], respObj.isRetCodeSuccess()))\n        return respObj\n\ndef getGlobals(additionalDict=None):\n    newDict = {}\n    gDict = globals()\n    for key in gDict.keys():\n        if ((type(gDict[key]) is str) or\n            (type(gDict[key]) is dict)):\n            newDict[key] = gDict[key]\n    if additionalDict:\n        newDict.update(additionalDict)\n    return newDict\n\ndef preChangeDiscoveryIP(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    Util.exe(actionAllow())\n    try:\n        dict = getGlobals(dictionaryObj)\n        respObj = PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dict, \"doPreChangeDiscoveryIP\")\n    except Exception as e:\n        msg = (\"Unexpected error during change discovery IP handling\")\n        if isinstance(e, respObjError):\n            respObj.addErrorReport(getFabErrEntity(funcName), msg)\n            respObj.setFailureRetCode()\n            Util.processRespObj(respObj, e.value)\n        else:\n            Util.handleException(msg, e, respObj)\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" % (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n        return respObj\n\ndef postAdd(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: postAdd: Serial [%s] dictionaryObj %s\" %\n            (FABRIC_NAME, dictionaryObj[\"deviceSerial\"], dictionaryObj))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        dict = getGlobals(dictionaryObj)\n        respObj = Util.exe(PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", dict, \"postAddExt\"))\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: postAdd: Serial [%s]. Success = [%r]\" %\n                (FABRIC_NAME, dictionaryObj[\"deviceSerial\"], respObj.isRetCodeSuccess()))\n\ndef getIntegerRange(rangeStr):\n    return sum(((list(range(*[int(j) + k for k,j in enumerate(i.split('-'))]))\n                        if '-' in i else [int(i)]) for i in rangeStr.split(',')), [])\n\ndef bootstrapDevice(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s, dictionaryObj %s\" % (FABRIC_NAME, funcName, str(dictionaryObj)))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        Util.exe(actionAllow())\n        dict = getGlobals(dictionaryObj)\n        devices = dictionaryObj[\"bootstrapDevices\"]\n        numDevicesToBootstrap = len(devices)\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        dcnmUser = fabricSettings.get(\"dcnmUser\", \"\")\n        inbandPOAPEnable = isInbandPoapEnabled(fabricSettings)\n        Wrapper.print(\"%s: Fabric [%s]: inbandPOAPEnable [%s] dcnmUser [%s] Num devices [%d]\" % (funcName, \n                        FABRIC_NAME, inbandPOAPEnable, dcnmUser, numDevicesToBootstrap))\n\n        for i in range(numDevicesToBootstrap):\n            Wrapper.print(\"Fabric [%s]: Attempting Bootstrap for Switch [%s] - #%d of %d\" %(FABRIC_NAME,\n                                        devices[i].serialNumber, i+1, numDevicesToBootstrap))\n\n        # Wrapper.print(\"%s: Sending dictionary obj %s for fabric %s\" %(funcName, FABRIC_NAME, str(dict)))\n        newRespObj = PTI.executePyTemplateMethod(\"dhcp_common\", dict, \"bootstrapDevice\")\n        processRespObj(respObj, newRespObj)\n        if inbandPOAPEnable == \"true\":\n            if newRespObj.isRetCodeFailure():\n                # bootstrap for some switches failed... log them here. Fabric errors must already be present from earlier call\n                failedSwitchSerials = newRespObj.getValue()\n                numDevices = len(failedSwitchSerials)\n                i = 0\n                for serial in failedSwitchSerials:\n                    Wrapper.print(\"Fabric [%s]: Bootstrap failed for Switch [%s] - #%d of %d\" % (FABRIC_NAME, serial, ++i, numDevices))\n\n                devicesToContinue = []\n                for i in range(numDevicesToBootstrap):\n                    if devices[i].serialNumber not in failedSwitchSerials:\n                        devicesToContinue.append(copy.deepcopy(devices[i]))\n            else:\n                devicesToContinue = devices\n\n            if len(devicesToContinue):\n                dictionaryObj[\"bootstrapDevices\"] = devicesToContinue\n                # Additional processing for inband POAP\n                #Should call configSave to generate the full startup config of the switch being bootstrapped\n                processRespObj(respObj, configSaveInband(dict))\n    except respObjError as e:\n        respObj = e.value\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" % (FABRIC_NAME, \n                                                            funcName, respObj.isRetCodeSuccess()))\n    return respObj\n\ndef preFabricDelete(dictionaryObj):\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: preFabricDelete\" % (FABRIC_NAME))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    #check switches\n    try:\n        Util.exe(actionAllow())\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)  # all devices serial number\n        devices = filter(None, devices)\n        Wrapper.print(\"PFD: Found %d Switches\" % len(devices))\n        if (len(devices) > 0):\n            respObj.addErrorReport(getFabErrEntity(preFabricDelete.__name__),\n                                   \"Fabric cannot be deleted with switches present. \"\n                                   \"Please check the Switches page to make sure \"\n                                   \"there are no switch entries and retry.\")\n            respObj.setFailureRetCode()\n            return respObj\n        RM.deleteFabricResources(FABRIC_NAME)\n        dictionaryObj[\"FABRIC_NAME\"] = FABRIC_NAME\n        PTI.executePyTemplateMethod(\"dhcp_utility\", dictionaryObj, \"deleteDHCPScopeV6\")\n        PTI.executePyTemplateMethod(\"dhcp_utility\", dictionaryObj, \"deleteDHCPScope\")\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preFabricDelete: Success = [%r]\" %\n                (FABRIC_NAME, respObj.isRetCodeSuccess()))\n                \n#preSwitchDelete - PSD#\ndef preSwitchDelete(dictionaryObj):\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    funcName = sys._getframe(0).f_code.co_name\n    \n    Fabric_name = \"\"\n    try:\n      forceDelete = dictionaryObj.get(\"force\", False)\n      deleteSwitch = True\n      if (\"notDeleteSwitch\" in dictionaryObj):\n          deleteSwitch = False\n          Fabric_name = dictionaryObj[\"FABRIC_NAME\"]\n      else:\n          Fabric_name = FABRIC_NAME\n          Util.exe(actionAllow())\n      Wrapper.print(\"==========ACTION: FAB [%s]: Start: preSwitchDelete. Serial [%s], deleteSwitch [%s]\" %\n                    (Fabric_name, dictionaryObj[\"deviceSerial\"], deleteSwitch))\n\n      sn = dictionaryObj[\"deviceSerial\"]\n      topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(Fabric_name)))\n      isVPC = Util.exe(VpcWrapper.isVpc(Fabric_name, sn))\n      switchRole = topologyDataObj.getSwitchRole(sn)\n      hostName = Util.exe(InventoryWrapper.getHostName(sn))\n      fabricSettings = Util.exe(FabricWrapper.get(Fabric_name)).getNvPairs()\n\n      Wrapper.print(\"%s[%s]: Role [%s] isVPC [%s]\" % (sn, hostName, switchRole, isVPC))\n\n      dictObj = getGlobals(dictionaryObj)\n      dictObj[\"SRNO\"] = sn\n      dictObj[\"FABRIC_NAME\"] = Fabric_name\n      dictObj[\"topologyObj\"] = topologyDataObj\n\n      FF = dictObj.get(\"FF\", \"Easy_Fabric\")\n      if FF == \"Easy_Fabric\":\n          Wrapper.print(\"Easy Fabric template\")\n          \n          # check whether service has been enabled\n          if \"border\" in switchRole or \"leaf\" in switchRole:\n              resp = ElasticServiceWrapper.serviceNetworkAttached(sn, True)\n              if resp.isRetCodeSuccess() and resp.getValue():\n                    respObj = WrappersResp.getRespObj()\n                    respObj.addErrorReport(\"SwitchRemoval\", (\"There are service networks being attached to this switch (or its peer switch). Please detach the service networks and deploy the changes (detach service networks) before removing this switch.\"), sn)\n                    respObj.setFailureRetCode()\n                    return respObj   \n              else:\n                  Wrapper.print(\"%s(): No service network is attached, so proceed to validate the pre-deletion of switch [%s]\" % (funcName, sn))                    \n          if switchRole == \"tor\":\n              if isVPC:\n                  vpcPairSerialKey = Util.exe(VpcWrapper.get(VPCMetaDataType.VPC_PAIR, Fabric_name, sn))\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(vpcPairSerialKey))\n                  unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(vpcPairSerialKey))\n              else:\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(sn))\n                  unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(sn))\n              if pairingSns:\n                  respObj.addErrorReport(getFabErrEntity(funcName, sn),\n                      \"Switch has a leaf-tor pairing. Please remove the pairing before deleting the tor switch from the fabric.\", sn)\n                  respObj.setFailureRetCode()\n                  return respObj\n              if unpairingSns:\n                  respObj.addErrorReport(getFabErrEntity(funcName, sn),\n                      \"Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the tor switch from the fabric.\", sn)\n                  respObj.setFailureRetCode()\n                  return respObj\n          elif switchRole == \"leaf\" and deleteSwitch:\n              if isVPC:\n                  vpcPairSerialKey = Util.exe(VpcWrapper.get(VPCMetaDataType.VPC_PAIR, Fabric_name, sn))\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(vpcPairSerialKey))\n              else:\n                  pairingSns = Util.exe(ToRWrapper.getTorAssociation(sn))\n              unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(sn))\n              if isVPC and not unpairingSns:\n                  unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(vpcPairSerialKey))\n                  if not unpairingSns:\n                      vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n                      unpairingSns = Util.exe(ToRWrapper.getMarkDeletedPairs(vpcPeerSn))\n              if unpairingSns:\n                  respObj.addErrorReport(getFabErrEntity(funcName, sn),\n                      \"Please perform Recalculate and Deploy to complete Leaf-ToR unpairing before deleting the leaf switch from the fabric.\", sn)\n                  respObj.setFailureRetCode()\n                  return respObj\n\n              if pairingSns:\n                  # Delete all tors that are associated with this leaf\n                  Util.exe(cleanupLeafTorAssoc(sn, pairingSns))\n                  vpcPeerProcessedList = []\n                  for torSn in pairingSns:\n                      if torSn in vpcPeerProcessedList:\n                          continue\n                      isTorVpc = Util.exe(VpcWrapper.isVpc(Fabric_name, torSn))\n                      if isTorVpc:\n                          torVpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, torSn))\n                          PTI.createOrUpdate(torSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n                          PTI.createOrUpdate(torVpcPeerSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n                          Wrapper.print(\"PSD: Unpair VPC on torSn [%s]\" % torSn)\n                          Util.exe(VpcWrapper.delete(torSn))\n\n                          Wrapper.print(\"PSD: Delete all PTIs and resource for torVpcPeerSn [%s]\" % torVpcPeerSn)\n                          PTI.delete(torVpcPeerSn)\n                          RM.deleteSwitchResources(torVpcPeerSn)\n                          CDW.clearDeployerHistory(torVpcPeerSn)\n                          InventoryWrapper.removeSwitch(Fabric_name, torVpcPeerSn)\n                          vpcPeerProcessedList.append(torVpcPeerSn)\n\n                      Wrapper.print(\"PSD: Delete all PTIs and resource for torSn [%s]\" % torSn)\n                      PTI.delete(torSn)\n                      RM.deleteSwitchResources(torSn)\n                      CDW.clearDeployerHistory(torSn)\n                      InventoryWrapper.removeSwitch(Fabric_name, torSn)\n\n          SSPINE_ADD_DEL_DEBUG_FLAG = fabricSettings.get(\"SSPINE_ADD_DEL_DEBUG_FLAG\",\"Disable\")\n          if \"super\" in switchRole:\n              Wrapper.print(\"Easy Fabric Super in role %s\"%(switchRole))\n              spinesWithSuperRole = topologyDataObj.get(TopologyInfoType.SPINES_WITH_SUPER_ROLE)\n              spines = topologyDataObj.get(TopologyInfoType.SPINES)\n\n              Wrapper.print(\"Easy Fabric Super role in spines count %s and normal spines count %s\"%(len(spinesWithSuperRole),len(spines)))\n              if len(spinesWithSuperRole) == 1 and len(spines) > 0:\n                  if SSPINE_ADD_DEL_DEBUG_FLAG == \"Disable\":\n                      respObj.addWarnReport(getFabErrEntity(funcName, sn+\":Fabric without super spine role devices\"),\n                                            \"After deletion of this device, fabric doesn't have any more super spine roles \"\n                                            \"and performing Recalculate Config without any super spine device will generate bgp peering between spines and leafs.\", sn)\n                      respObj.setWarningRetCode()\n\n      #Delete all overlays on border switches before IFCs are deleted\n      if \"border\" == switchRole or \"border spine\" == switchRole or \"border super spine\" == switchRole:\n          Util.exe(validateInterfabricDelete(sn, forceDelete))\n          ptiList = Util.exe(PTI.get(sn))\n          Wrapper.print(\"Count is %s\" % (len(ptiList)))\n          count = 0\n          for pti in ptiList:\n               if pti.getSource() == \"OVERLAY\":\n                   PTI.deleteInstance(pti.getPolicyId())\n                   count = count + 1\n          if count > 0:\n              Util.exe(Helper.removeItemsCSM(sn))\n\n      if \"border gateway\" in switchRole:\n          Util.exe(validateInterfabricDelete(sn, forceDelete))\n          ifcPtiList = Util.exe(PTI.get(sn, \"SWITCH\", \"SWITCH\", \"\", \"ifcdelete\"))\n          if len(ifcPtiList) == 0:\n              dictObj[\"force\"] = forceDelete\n              processRespObj(respObj, PTI.executePyTemplateMethod(\"interface_utility\", dictObj, \"isMSDMemberSwitchDelAllowed\"))\n              if respObj.isRetCodeFailure():\n                  return respObj\n              else:\n                  if isVPC:\n                      vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n                      PTI.createOrUpdate(vpcPeerSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"ifcdelete\", {})\n          ptiList = Util.exe(PTI.get(sn))\n          Wrapper.print(\"Count is %s\" % (len(ptiList)))\n          count = 0\n          for pti in ptiList:\n              if pti.getSource() == \"OVERLAY\":\n                  PTI.deleteInstance(pti.getPolicyId())\n                  count = count + 1\n          if count > 0:\n             Util.exe(Helper.removeItemsCSM(sn))\n\n          if isVPC:\n              Wrapper.print(\"PSD: started overlay deletion for VPC config\")\n              vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n              ptiList = Util.exe(PTI.get(vpcPeerSn))\n              Wrapper.print(\"Count is %s\" % (len(ptiList)))\n              count = 0\n              for pti in ptiList:\n                  if pti.getSource() == \"OVERLAY\":\n                      PTI.deleteInstance(pti.getPolicyId())\n                      count = count + 1\n              if count > 0:\n                 Util.exe(Helper.removeItemsCSM(vpcPeerSn))\n              # let the delete template do this\n              # get Source Switch Id for sn\n              # get count of the MS overlay IFCs for sn - snCount\n              # get Source Switch Id for vpcPeerSn\n              # get count of the MS overlay IFCs for vpcPeerSn --- vpcSnCount\n              # remove all overlay PTIs from sn and vpcPeerSn\n              # if snCount == 1 or vpcSnCount == 1:\n              #     if overlays are extended over MS Overlay IFCs:\n              #         Report error\n\n      if deleteSwitch:\n          # check whether service has been enabled\n          if FF == \"Easy_Fabric\" and (\"border\" in switchRole or \"leaf\" in switchRole):\n              ElasticServiceWrapper.deleteServiceNode(sn)\n              Wrapper.print(\"%s(): Finished the service related config deletion for switch [%s].\" % (funcName, sn))\n\n          Util.exe(PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"delFabricIntfConfig\"))\n          Wrapper.print(\"PSD: started for BGP config\")\n          PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"bgpConfigDel\")\n          Wrapper.print(\"PSD: started for RP config\")\n          PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dictObj, \"rpConfigDel\")\n\n      if isVPC:\n          Wrapper.print(\"PSD: started for VPC config\")\n          vpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, Fabric_name, sn))\n          PTI.createOrUpdate(sn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n          PTI.createOrUpdate(vpcPeerSn, \"SWITCH\", \"SWITCH\", \"\", 10, \"switch_delete_simulated\", {})\n          #disjoinvpcParing(topologyDataObj, vpcPeerSn, False)\n          Wrapper.print(\"PSD: Unpair VPC\")\n          Util.exe(VpcWrapper.delete(sn))\n\n      Wrapper.print(\"PSD: Delete all PTIs of device and Convert fabric connections to hosts\")\n      PTI.delete(sn)\n      #This is done after PTI delete to ensure Resource for\n      #link subnet after freed up in the end\n      RM.deleteSwitchResources(sn)\n      CDW.clearDeployerHistory(sn)\n\n      if \"super\" in switchRole:\n          spinesWithSuperRole = topologyDataObj.get(TopologyInfoType.SPINES_WITH_SUPER_ROLE)\n          spinesWithSuperRoleCnt = str(len(spinesWithSuperRole) - 1)\n          FabricWrapper.update(Fabric_name, \"SSPINE_COUNT\", spinesWithSuperRoleCnt)\n      elif \"spine\" in switchRole:\n          spines = topologyDataObj.get(TopologyInfoType.SPINES)\n          spinesRoleCnt = str(len(spines) - 1)\n          FabricWrapper.update(Fabric_name, \"SPINE_COUNT\", spinesRoleCnt)\n\n      #If VPC then delete both VPC pair\n      if isVPC and deleteSwitch:\n          InventoryWrapper.removeSwitch(Fabric_name, sn, forceDelete)\n          if \"border gateway\" not in switchRole:\n              #if check and code under it is not needed in 11.5 as not last stage of release\n              #avoiding this case for taking care of vPC BGW Deletion scenarios for the B2B case\n              dictionaryObj.update({\"deviceSerial\":vpcPeerSn})\n              dictionaryObj.update({\"force\":forceDelete})\n              preSwitchDelete(dictionaryObj)\n          InventoryWrapper.removeSwitch(Fabric_name, vpcPeerSn, forceDelete)\n\n      enableMacSec = fabricSettings.get(\"ENABLE_MACSEC\")\n      if enableMacSec == \"true\" and deleteSwitch:\n          devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n          devices = filter(None, devices)\n          devicesLeftCnt = (len(devices) - 2) if isVPC else (len(devices) - 1)\n          if devicesLeftCnt <= 0:\n              jobId = Fabric_name + \"-macsec_oper_status\"\n              reportRespObj = ReportWrapper.getReportJob(jobId)\n              if reportRespObj.isRetCodeSuccess():\n                  Wrapper.print(\"%s(): Delete periodic report for jobId:%s\" % (funcName, jobId))\n                  ReportWrapper.deleteReportJob(jobId)\n\n      if ((not isVPC) and isInbandPoapEnabled(dictObj) == \"true\"): \n          isLocalDhcpEnabled = True if dictObj.get(\"DHCP_ENABLE\", \"false\") == \"true\" else False\n          isNumbered = True if dictObj.get(\"FABRIC_INTERFACE_TYPE\", \"p2p\") == \"p2p\" else False\n          if isLocalDhcpEnabled and isNumbered:\n            # generate all the DHCP scopes and upload to DB\n            Util.exe(PTI.executePyTemplateMethod(\"dhcp_utility\", dictObj, \"dhcpScope\"))     \n\n      return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: preSwitchDelete: Serial [%s]. Success = [%r]\" %\n                (Fabric_name, dictionaryObj[\"deviceSerial\"], respObj.isRetCodeSuccess()))\n\ndef configSaveInband(dictionaryObj):\n    funcName = sys._getframe(0).f_code.co_name\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: %s\" % (FABRIC_NAME, funcName))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n\n        #get the whole topology from topology database\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n\n        #Need to pass bootstrapDevices dictionary to configSaveExtnInband\n        dict = getGlobals(dictionaryObj)\n        dict[\"topologyObj\"] = topologyDataObj\n        dict[\"DEVICES\"] = devices\n        #Wrapper.print(\"%s: Updated dictionary is %s\" % (funcName, str(dict)))\n        #Validate fabric setting change\n        Util.exe(PTI.executePyTemplateMethod(\"fabric_utility_11_1\", dict, \"validateFabricSetting\"))\n        \n        processRespObj(respObj, PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dict, \"configSaveExtnInband\"))\n    except Exception as e:\n        if isinstance(e, respObjError):\n            Util.processRespObj(respObj, e.value)\n        else:\n            Util.handleException(\"Unexpected error process inband POAP Bootstrap switch\", e, respObj)\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: %s: Success = [%r]\" %\n                (FABRIC_NAME, funcName, respObj.isRetCodeSuccess()))\n        return respObj\n\ndef configSave(dictionaryObj):\n    global abstract_isis, ISIS_LEVEL, AAA_SERVER_CONF, DNS_SERVER_IP_LIST, NTP_SERVER_IP_LIST, SYSLOG_SERVER_IP_LIST, DNS_SERVER_VRF, NTP_SERVER_VRF, SYSLOG_SEV, SYSLOG_SERVER_VRF\n\n    Wrapper.print(\"==========ACTION: FAB [%s]: Start: configSave\" % (FABRIC_NAME))\n    respObj = WrappersResp.getRespObj()\n    respObj.setSuccessRetCode()\n    try:\n        Util.exe(actionAllow())\n\n        dcnmUser = dictionaryObj.get(\"dcnmUser\")\n        Util.exe(FabricWrapper.update(FABRIC_NAME, \"dcnmUser\", dcnmUser))\n\n        #get the whole topology from topology database\n        topologyDataObj = TopologyData(Util.exe(TopologyWrapper.get(FABRIC_NAME)))\n\n        devices = topologyDataObj.get(TopologyInfoType.SWITCHES)\n        devices = filter(None, devices)\n\n        #Valid topology\n        if len(devices) == 0:\n            respObj.addErrorReport(configSave.__name__, \"Fabric %s cannot be deployed without any switches\" % FABRIC_NAME)\n            respObj.setFailureRetCode()\n            return respObj\n\n        # handle a few ISIS specific things for the DCNM 11.0 or 11.1 upgrade\n        if LINK_STATE_ROUTING == 'is-is':\n            # get current fabric settings\n            fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n\n            # Handle inline upgrade from 11.0 or 11.1\n            cur_abstract_isis = fabricSettings['abstract_isis']\n            if cur_abstract_isis == \"base_isis\":\n                Wrapper.print(\"++++++++ configSave: abstract policies have 11_0/1 value, set to 11_2\")\n                # Even though the fabric is operating at level-1 we will set the 'abstract_isis' variable\n                # to 'base_isis_level2'\n                # this vatriable is not used anymore and kept only for backward compatibility\n                abstract_isis = \"base_isis_level2\"\n                Util.exe(FabricWrapper.update(FABRIC_NAME, \"abstract_isis\", abstract_isis))\n\n            # check the presence of the ISIS_LEVEL fabric variable\n            if not ('ISIS_LEVEL' in fabricSettings):\n                Wrapper.print(\"++++++++ configSave: ISIS_LEVEL not found in fabric settings\")\n                # variable does not exist (upgrade case).. set it to 'level-1' since earlier DCNM supported level-1 only\n                ISIS_LEVEL = \"level-1\"\n                Util.exe(FabricWrapper.update(FABRIC_NAME, \"ISIS_LEVEL\", ISIS_LEVEL))\n\n        gVarDictObj = getStrGlobals()\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        upgradeFromVersion = fabricSettings.get(\"UPGRADE_FROM_VERSION\", \"\")\n        isUpgrade = (upgradeFromVersion != \"\")\n        if isUpgrade and upgradeFromVersion in [\"11.5.4\", \"12.1.1e\", \"12.1.2e\", \"12.1.2p\"]:\n            gVarDictObj.update({\"topologyObj\": topologyDataObj})\n            gVarDictObj[\"upgradeFromVersion\"] = upgradeFromVersion\n            gVarDictObj[\"fabricType\"] = \"Switch_Fabric\"\n            gVarDictObj[\"fabricName\"] = FABRIC_NAME\n            FabricWrapper.sendProgress(FABRIC_NAME, \"configSave\", 6, \"One time policies update after upgrade\")\n            Wrapper.print(\"$$$$$$$$$$$$ START PTI REGEN UPGRADE HANDLING [%s] for Fabric [%s] and upgradeFromVersion [%s] $$$$$$$$$\"%\n                          (datetime.datetime.time(datetime.datetime.now()), FABRIC_NAME, upgradeFromVersion))\n            processRespObj(respObj, PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", gVarDictObj, \"handleUpgradeInRecalc\"))\n            if respObj.isRetCodeFailure():\n                return respObj\n            FabricErrorLogger.clear(FABRIC_NAME, Category.Fabric, ET.Fabric, FABRIC_NAME+\":Upgrade\")\n            FabricWrapper.update(FABRIC_NAME, \"UPGRADE_FROM_VERSION\", \"\")\n            FabricWrapper.sendProgress(FABRIC_NAME, \"configSave\", 9, \"Policies update completed\")\n            Wrapper.print(\"$$$$$$$$$$$$ COMPLETED PTI REGEN UPGRADE HANDLING [%s] for Fabric [%s] and upgradeFromVersion [%s] $$$$$$$$$\"%\n                          (datetime.datetime.time(datetime.datetime.now()), FABRIC_NAME, upgradeFromVersion))\n\n        gVarDictObj.update({\"BRFIELD_DEBUG_FLAG\": BRFIELD_DEBUG_FLAG})\n        gVarDictObj.update({\"topologyObj\": topologyDataObj})\n        gVarDictObj.update({\"dcnmUser\": dcnmUser})\n        processRespObj(respObj, PTI.executePyTemplateMethod(\"fabric_upgrade_11_1\", gVarDictObj, \"handleUpgradeOrBrownfield\"))\n        if respObj.isRetCodeFailure():\n            return respObj\n\n        if LINK_STATE_ROUTING == \"is-is\":\n            # the ISIS_LEVEL setting could have been updated in handleUpgradeOrBrownfield.. update the variable so that\n            # subsequent code will get the updated value\n            try:\n                ISIS_LEVEL = str(Util.exe(FabricWrapper.get(FABRIC_NAME, \"ISIS_LEVEL\")))\n                Wrapper.print(\"[%s]: configSave: ISIS_LEVEL set to [%s]\" % (FABRIC_NAME, ISIS_LEVEL))\n            finally:\n                pass\n\n        fabricSettings = Util.exe(FabricWrapper.get(FABRIC_NAME)).getNvPairs()\n        if \"DNS_SERVER_IP_LIST\" in fabricSettings:\n            DNS_SERVER_IP_LIST = str(fabricSettings[\"DNS_SERVER_IP_LIST\"])\n        if \"NTP_SERVER_IP_LIST\" in fabricSettings:\n            NTP_SERVER_IP_LIST = str(fabricSettings[\"NTP_SERVER_IP_LIST\"])\n        if \"SYSLOG_SERVER_IP_LIST\" in fabricSettings:\n            SYSLOG_SERVER_IP_LIST = str(fabricSettings[\"SYSLOG_SERVER_IP_LIST\"])\n        if \"DNS_SERVER_VRF\" in fabricSettings:\n            DNS_SERVER_VRF = str(fabricSettings[\"DNS_SERVER_VRF\"])\n        if \"NTP_SERVER_VRF\" in fabricSettings:\n            NTP_SERVER_VRF = str(fabricSettings[\"NTP_SERVER_VRF\"])\n        if \"SYSLOG_SEV\" in fabricSettings:\n            SYSLOG_SEV = str(fabricSettings[\"SYSLOG_SEV\"])\n        if \"SYSLOG_SERVER_VRF\" in fabricSettings:\n            SYSLOG_SERVER_VRF = str(fabricSettings[\"SYSLOG_SERVER_VRF\"])\n                 \n        #Validate fabric setting change\n        dictObj = getStrGlobals()\n        dictObj.update({\"DEVICES\": devices})\n        dictObj.update({\"topologyObj\": topologyDataObj})\n        Util.exe(PTI.executePyTemplateMethod(\"fabric_utility_11_1\", dictObj, \"validateFabricSetting\"))\n\n        dict = getGlobals()\n        dict[\"topologyObj\"] = topologyDataObj\n        processRespObj(respObj, PTI.executePyTemplateMethod(\"Easy_Fabric_Extn_11_1\", dict, \"configSaveExtn\"))\n        Util.exe(Util.topDownRmTrackingRqrd(FABRIC_NAME, devices))\n        Wrapper.print(\"configSave: after calling configSaveExtn\")\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n    finally:\n        Wrapper.print(\"==========ACTION: FAB [%s]: Finish: configSave: Success = [%r]\" %\n                (FABRIC_NAME, respObj.isRetCodeSuccess()))\n\ndef processRespObj(respObj, newResp):\n    Wrapper.print(\"processRespObj: respObj isSuccess [%r] newResp isSuccess [%r]\" % (respObj.isRetCodeSuccess(), newResp.isRetCodeSuccess()))\n    errs = newResp.getErrorList()\n    if (errs != None):\n        if not respObj.isRetCodeFailure():\n            # since there is a valid error list.. we assume the retcode is a non-success error code\n            respObj.setRetCode(newResp.getRetCode())\n        list = respObj.getErrorList()\n        if (list != None):\n            Wrapper.print(\"processRespObj: Found %d error entries. Adding %d more\" % (len(list), len(errs)))\n        else:\n            Wrapper.print(\"processRespObj: Adding %d entries\" % len(errs))\n            list = []\n\n        for err in errs:\n            list.append(err)\n        respObj.setErrorList(list)\n    if newResp.isResolve() == True:\n        respObj.setResolve(newResp.isResolve())\n        respObj.setResolveId(newResp.getResolveId())\n        resolvePayload = {}\n        respObj.setResolvePayload(newResp.getResolvePayload())\n        \n    Wrapper.print(\"processRespObj: After respObj isSuccess [%r]\" % (respObj.isRetCodeSuccess()))\n\ndef getFormattedSwitchName(serialNum):\n    formattedStr = serialNum\n    hostName = InventoryWrapper.getHostNameString(serialNum)\n    if hostName:\n        formattedStr += (\"/\" + hostName)\n    return formattedStr\n\ndef cleanupLeafTorAssoc(leafSn, pairingSns):\n    try:\n        funcName = sys._getframe(0).f_code.co_name\n        Wrapper.print(\"%s(): leafSn:[%s] pairingSns:%s\" % (funcName, leafSn, pairingSns))\n\n        vpcPeerProcessedList = []\n        for torSn in pairingSns:\n            if torSn in vpcPeerProcessedList:\n                continue\n            leafVpcPeerSn = torVpcPeerSn = torVpcPairSerialKey = \"\"\n            isTorVpc = Util.exe(VpcWrapper.isVpc(FABRIC_NAME, torSn))\n            if isTorVpc:\n                torVpcPairSerialKey = Util.exe(VpcWrapper.get(VPCMetaDataType.VPC_PAIR, FABRIC_NAME, torSn))\n                serials = torVpcPairSerialKey.split(Helper.DELIMITER)\n                torVpcPeerSn = serials[0] if serials[1] == torSn else serials[1]\n                leafSns = Util.exe(ToRWrapper.getTorAssociation(torVpcPairSerialKey))\n                vpcPeerProcessedList.append(torVpcPeerSn)\n            else:\n                leafSns = Util.exe(ToRWrapper.getTorAssociation(torSn))\n\n            if not leafSns:\n                Wrapper.print(\"%s(): No leaf-tor pairing found for the tor\" % torSn)\n                continue\n\n            if len(leafSns) == 2:\n                leafVpcPeerSn = Util.exe(VpcWrapper.get(VPCMetaDataType.PEER_DEVICE_SN, FABRIC_NAME, leafSn))\n\n            Wrapper.print(\"%s(): Calling deleteLeafToR() leafSn %s leafVpcPeerSn %s torSn %s torVpcPeerSn %s\" %\n                          (funcName, leafSn, leafVpcPeerSn, torSn, torVpcPeerSn))\n            Util.exe(ToRWrapper.deleteLeafToR(leafSn, leafVpcPeerSn, torSn, torVpcPeerSn))\n\n        respObj = WrappersResp.getRespObj()\n        respObj.setSuccessRetCode()\n        return respObj\n\n    except respObjError as e:\n        return e.value\n\ndef validateInterfabricDelete(serial_number, forceDelete):\n    Wrapper.print(\"==========ACTION: Serial Number [%s] : Start: validateInterfabricDelete with forceDelete [%s]\" % (serial_number, forceDelete))\n    try:\n        respObj = WrappersResp.getRespObj()\n        respObj.setSuccessRetCode()\n\n        wResp = InterfabricConnectionWrapper.listInterfabrics(serial_number)\n        if wResp.isRetCodeSuccess():\n            Wrapper.print(\"validateInterfabricDelete: Incoming IFC links to: [%s]\" % (serial_number))\n            interfabric_list = wResp.getValue()\n        else:\n            Wrapper.print(\"validateInterfabricDelete: Error hit in get Incoming IFC links for [%s]: \" %(serial_number))\n            return wResp\n        \n        if forceDelete:\n            for ifc in interfabric_list:\n                Wrapper.print(\"validateInterfabricDelete: IFC links for [%s]: ifc [%s]\" %(serial_number, ifc))\n                srcSn = ifc[\"source_switch_sn\"]\n                dstSn = ifc[\"dest_switch_sn\"]\n                Util.exe(Util.deleteExtensions(srcSn, dstSn))\n\n        for ifc in interfabric_list:\n            if ifc[\"extension_type\"] == \"VRF_LITE\" or ifc[\"extension_type\"] == \"VXLAN_MPLS_OVERLAY\":\n                Wrapper.print(\"validateInterfabricDelete: Processing IFC ID %s\" %(ifc[\"interfabricId\"]))\n                extension_id = int(ifc[\"interfabricId\"])\n                ifc_extension_exists = Util.exe(InterfabricConnectionWrapper.checkIFCExtensions(extension_id))\n\n                if ifc_extension_exists:\n                    srcSwitchStr = getFormattedSwitchName(ifc[\"source_switch_sn\"])\n                    destSwitchStr = getFormattedSwitchName(ifc[\"dest_switch_sn\"])\n\n                    errorMsg = (\"Failed to delete switch. Overlays are extended for interfabric link [%s] [%s]<-->[%s] [%s]\"\n                                %(srcSwitchStr, ifc[\"source_if_name\"], destSwitchStr, ifc[\"dest_if_name\"]))\n                    respObj.addErrorReport((\"InterFabricLink\"), errorMsg, serial_number)\n                    respObj.setFailureRetCode()\n                    return respObj\n        return respObj\n    except respObjError as e:\n        respObj = e.value\n        return respObj\n\n    finally:\n        Wrapper.print(\"==========ACTION: SN [%s]: Finish: validateInterfabricDelete: Success = [%r]\" % \\\n                (serial_number, respObj.isRetCodeSuccess()))\n##\n#\n",
    "fileName": "Easy_Fabric.template",
    "templateType": "FABRIC",
    "contentType": "PYTHON",
    "templateSubType": "NA",
    "_implements": "",
    "dependencies": "",
    "referenceCount": 0,
    "published": false,
    "timestamp": "2023-08-18 08:10:43",
    "importedTemplates": null,
    "implements": ""
    }"""
    return template

def fixup_template(template):
    new_template = ""
    for line in template.split("\n"):
        # "IsShow": "\"VRF_LITE_AUTOCONFIG!=Manual\"",
        line = re.sub(r'\"','', line)
        line = re.sub(r'\\\\',r'\\\\\\', line)
        new_template += f"{line}\n"
    return new_template

def make_bool(value):
    if value in ["true", "yes", "True", "Yes", "TRUE", "YES"]:
        return True
    if value in ["false", "no", "False", "No", "FALSE", "NO"]:
        return False
    return None

def display_all_keys(template):
    for item in template["parameters"]:
        if item.get("name", None):
            print(f"name: {item.get('name')}")
        for key in item:
            if key == "metaProperties":
                print(f"    {key}:")
                for meta_key in item[key]:
                    print(f"        {meta_key}: {item[key][meta_key]}")
            elif key == "annotations":
                print(f"    {key}:")
                for anno_key in item[key]:
                    print(f"        {anno_key}: {item[key][anno_key]}")
            else:
                print(f"    {key}: {item[key]}")

def display_internal_keys(template):
    for item in template["parameters"]:
        try:
            is_internal = make_bool(item["annotations"]["IsInternal"])
        except:
            continue
        if item.get("name", None):
            print(f"name: {item.get('name')}")
#print(f"{easy_fabric_template()}")

template = fixup_template(easy_fabric_template())
print(f"template: {template}")
display_internal_keys(json.loads(easy_fabric_template()))