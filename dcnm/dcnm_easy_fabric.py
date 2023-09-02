#!/usr/bin/python
#
# Copyright (c) 2020-2022 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Classes and methods for Ansible support of NDFC Data Center VXLAN EVPN Fabric.

Ansible states "merged", "deleted", and "query" are implemented.
"""
from __future__ import absolute_import, division, print_function

import copy
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send,
    dcnm_version_supported,
    get_fabric_details,
    #get_fabric_inventory_details,
    validate_list_of_dicts,
)
from ansible_collections.cisco.dcnm.plugins.module_utils.fabric.fabric import (
    VerifyFabricParams,
)

__metaclass__ = type
__author__ = "Allen Robel"

# NOTE: Going forward, add an "version_added" field for each
# parameter that contains the version of NDFC that first
# introduced the parameter.
DOCUMENTATION = """
---
module: dcnm_easy_fabric
short_description: Create VXLAN/EVPN Fabrics.
version_added: "0.9.0"
description:
    - "Create VXLAN/EVPN Fabrics."
author: Allen Robel
options:
    state:
        description:
        - The state of DCNM after module completion.
        - I(merged) and I(query) are the only states supported.
        type: str
        choices:
        - merged
        - query
        default: merged
    config:
        description:
        - A list of fabric configuration dictionaries
        type: list
        elements: dict
        suboptions:
            aaa_remote_ip_enabled:
                description:
                - Enable (True) or disable (False) AAA IP Authorization
                - Enable only when IP Authorization is enabled on the AAA Server
                - NDFC label, Enable AAA IP Authorization
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            aaa_server_conf:
                description:
                - AAA Configurations
                - NDFC label, AAA Freeform Config
                - NDFC tab, Manageability
                type: str
                required: false
                default: "2020.0000.00aa"
            advertise_pip_bgp:
                description:
                - Enable (True) or disable (False) usage of Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes
                - NDFC label, vPC advertise-pip
                - NDFC tab, VPC
                type: bool
                required: false
                default: False
            anycast_bgw_advertise_pip:
                description:
                - Enable (True) or disable (False) advertising Anycast Border Gateway PIP as VTEP.
                - Effective after Recalculate Config on parent MSD fabric.
                - NDFC label, Anycast Border Gateway advertise-pip
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            anycast_gw_mac:
                description:
                - Shared MAC address for all leafs (xx:xx:xx:xx:xx:xx, xxxx.xxxx.xxxx, etc)
                - NDFC label, Anycast Gateway MAC
                - NDFC tab, General Parameters
                type: str
                required: false
                default: "2020.0000.00aa"
            anycast_lb_id:
                description:
                - Underlay Anycast Loopback Id
                - NDFC label, Underlay Anycast Loopback Id
                - NDFC tab, Protocols
                type: int
                required: false
                default: ""
            anycast_rp_ip_range:
                description:
                - Anycast or Phantom RP IP Address Range
                - NDFC label, Underlay RP Loopback IP Range
                - NDFC tab, Resources
                type: str
                required: false
                default: 10.254.254.0/24
            auto_symmetric_default_vrf:
                description:
                - Enable (True) or disable (False) auto generation of Default VRF interface and BGP peering configuration on managed neighbor devices.
                - If True, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF for Peer' enabled.
                - vrf_lite_autoconfig must be set to 1
                - auto_symmetric_vrf_lite must be set to True
                - auto_vrflite_ifc_default_vrf must be set to True
                - NDFC label: Auto Deploy Default VRF for Peer
                - NDFC tab: Resources
                type: bool
                required: false
                default: False
            auto_symmetric_vrf_lite:
                description:
                - Enable (True) or disable (False) auto generation of Whether to auto generate VRF LITE sub-interface and BGP peering configuration on managed neighbor devices.
                - If True, auto created VRF Lite IFC links will have 'Auto Deploy for Peer' enabled.
                - NDFC label, Auto Deploy for Peer
                - NDFC tab, Resources
                - vrf_lite_autoconfig must be set to 1
                type: bool
                required: false
                default: False
            auto_vrflite_ifc_default_vrf:
                description:
                - Enable (True) or disable (False) auto generation of Default VRF interface and BGP peering configuration on VRF LITE IFC auto deployment.
                - If True, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF' enabled.
                - NDFC label, Auto Deploy Default VRF
                - NDFC tab, Resources
                - vrf_lite_autoconfig must be set to 1
                type: bool
                required: false
                default: False
            banner:
                description:
                - Message of the Day (motd) banner. Delimiter char (very first char is delimiter char) followed by message ending with delimiter
                - NDFC label, Banner
                - NDFC tab, Manageability
                - Example: ^This is a banner^
                type: str
                required: false
                default: ""
                version_added: 12.1.3f
            bfd_auth_enable:
                description:
                - Enable (True) or disable (False) BGP Authentication
                - Valid for P2P Interfaces only
                - NDFC label, Enable BFD Authentication
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bfd_auth_key:
                description:
                - Encrypted SHA1 secret value
                - NDFC label, BFD Authentication Key
                - NDFC tab, Protocols
                type: str
                required: false
            bfd_auth_key_id:
                description:
                - Encrypted SHA1 secret value
                - NDFC label, BFD Authentication Key ID
                - NDFC tab, Protocols
                type: str
                required: false
            bfd_enable:
                description:
                - Enable (True) or disable (False) BFD
                - Valid for IPv4 Underlay only
                - NDFC label, Enable BFD
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bfd_ibgp_enable:
                description:
                - Enable (True) or disable (False) BFD for iBGP
                - Valid for IPv4 Underlay only
                - NDFC label, Enable BFD For iBGP
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bfd_isis_enable:
                description:
                - Enable (True) or disable (False) BFD for ISIS
                - Valid for IPv4 Underlay only
                - NDFC label, Enable BFD For ISIS
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bfd_ospf_enable:
                description:
                - Enable (True) or disable (False) BFD for OSPF
                - Valid for IPv4 Underlay only
                - NDFC label, Enable BFD For OSPF
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bfd_pim_enable:
                description:
                - Enable (True) or disable (False) BFD for PIM
                - Valid for IPv4 Underlay only
                - NDFC label, Enable BFD For PIM
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bgp_as:
                description:
                - The fabric BGP Autonomous System number
                - NDFC label, BGP ASN
                - NDFC tab, General Parameters
                type: str
                required: true
            bgp_auth_enable:
                description:
                - Enable (True) or disable (False) BGP Authentication
                - NDFC label, Enable BGP Authentication
                - NDFC tab, Protocols
                type: bool
                required: false
                default: False
            bgp_auth_key:
                description:
                - Encrypted BGP Authentication Key based on type
                - NDFC label, BGP Authentication Key
                - NDFC tab, Protocols
                type: str
                required: false
            bgp_auth_key_type:
                description:
                - BGP Key Encryption Type: 3 - 3DES, 7 - Cisco
                - NDFC label, BGP Authentication Key Encryption Type
                - NDFC tab, Protocols
                type: str
                required: false
            bgp_lb_id:
                description:
                - (Min:0, Max:1023)
                - NDFC label, Underlay Routing Loopback Id
                - NDFC tab, Protocols
                type: int
                required: false
                default: 0
            bgp_auth_enable:
                description:
                - Enable (True) or disable (False) Automatic IP Assignment For POAP
                - NDFC label, Enable Bootstrap
                - NDFC tab, Bootstrap
                type: bool
                required: false
                default: False
            bootstrap_conf:
                description:
                - Additional CLIs required during device bootup/login e.g. AAA/Radius
                - NDFC label, Bootstrap Freeform Config
                - NDFC tab, Bootstrap
                type: str
                required: false
            bootstrap_enable:
                description:
                - Automatic IP Assignment For POAP
                - NDFC label, Enable Bootstrap
                - NDFC tab, Bootstrap
                type: bool
                required: false
                default: False
            bootstrap_multisubnet:
                description:
                - DHCPv4 Multi Subnet Scope
                - lines with # prefix are ignored here
                - Enter One Subnet Scope per line.
                - Start_IP, End_IP, Gateway, Prefix
                - e.g.
                - 10.6.0.2, 10.6.0.9, 10.6.0.1, 24
                - # This is a comment
                - 10.7.0.2, 10.7.0.9, 10.7.0.1, 24
                - NDFC label, DHCPv4 Multi Subnet Scope
                - NDFC tab, Bootstrap
                type: str
                required: false
                default: False
            brfield_debug_flag:
                description:
                - Valid values: Disable, Enable
                - NDFC label, ??
                - NDFC tab, ??
                type: str
                required: False
                default: Disable
            brownfield_network_name_format:
                description:
                - Brownfield Overlay Network Name Format
                - Generated network name should be < 64 characters
                - NDFC label, Brownfield Overlay Network Name Format
                - NDFC tab, Advanced
                type: str
                required: False
                default: "Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$"
            brownfield_skip_overlay_network_attachments:
                description:
                - Enable (True) or disable (False) skipping overlay network interface attachments for Brownfield and Host Port Resync cases
                - NDFC label, Skip Overlay Network Interface Attachments
                - NDFC tab, Advanced
                type: bool
                required: False
                default: False
            cdp_enable:
                description:
                - Enable (True) or disable (False) CDP on management interface 
                - NDFC label, Enable CDP for Bootstrapped Switch
                - NDFC tab, Advanced
                type: bool
                required: False
                default: False
            copp_policy:
                description:
                type: str
                - Fabric Wide CoPP Policy
                - Customized CoPP policy should be provided when 'manual' is selected 
                - NDFC label, CoPP Profile
                - NDFC tab, Advanced
                required: False
                default: strict
                choices: dense, lenient, manual, moderate, strict
            dci_subnet_range:
                description:
                - Address range to assign P2P Interfabric Connections
                - NDFC label, VRF Lite Subnet IP Range
                - NDFC tab, Resources
                type: str
                required: False
                default: 10.33.0.0/16
            dci_subnet_target_mask:
                description:
                - Prefix length for P2P Interfabric Connections
                - Min:8, Max:31
                - NDFC label, VRF Lite Subnet Mask
                - NDFC tab, Resources
                type: int
                required: False
                default: 30
            default_pvlan_sec_network:
                description:
                - Default PVLAN Secondary Network Template
                - NDFC label, PVLAN Secondary Network Template
                - NDFC tab, Advanced
                type: str
                required: False
                default: Pvlan_Secondary_Network
            default_queuing_policy_cloudscale:
                description:
                - Queuing Policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX series switches in the fabric
                - NDFC label, N9K Cloud Scale Platform Queuing Policy
                - NDFC tab, Advanced
                type: str
                required: False
                choices: queuing_policy_default_8q_cloudscale, queuing_policy_default_4q_cloudscale
            default_queuing_policy_other:
                description:
                - Queuing Policy for all other switches in the fabric
                - NDFC label, Other N9K Platform Queuing Policy
                - NDFC tab, Advanced
                type: str
                required: False
                choices: queuing_policy_default_other
            default_queuing_policy_r_series:
                description:
                - Queuing Policy for all R-Series switches in the fabric
                - NDFC label, N9K R-Series Platform Queuing Policy
                - NDFC tab, Advanced
                type: str
                required: False
                choices: queuing_policy_default_r_series
            default_vrf_redis_bgp_rmap:
                description:
                - Route Map used to redistribute BGP routes to IGP in default vrf in auto created VRF Lite IFC links
                - NDFC label, Redistribute BGP Route-map Name
                - NDFC tab, Resources
                type: str
                required: false, unless auto_vrflite_ifc_default_vrf is set to True
            deployment_freeze:
                description:
                - Enable (True) or disable (False) Fabric Deployment
                - NDFC label, None
                - NDFC tab, None
                - Fabric deployment is enabled/disabled in the NDFC GUI by right-clicking on a fabric and selecting 'More... Deployment Enable/Disable'
                type: bool
                required: false
                default: False
            dhcp_enable:
                description:
                - Automatic IP Assignment For POAP From Local DHCP Server
                - NDFC label, Enable Local DHCP Server
                - NDFC tab, Bootstrap
                type: bool
                required: false
                default: False
            dhcp_end:
                description:
                - End Address For Switch POAP
                - NDFC label, DHCP Scope End Address
                - NDFC tab, Bootstrap
                type: str
                required: false
                default: ""
            dhcp_ipv6_enable:
                description:
                - The DHCP version to use when DHCP is enabled
                - This has nothing to do with ipv6 and is not a boolean
                - Valid value: DHCPv4
                - NDFC label, DHCP Version
                - NDFC tab, Bootstrap
                type: str
                required: false
                default: ""
            dhcp_start:
                description:
                - Start Address For Switch POAP
                - NDFC label, DHCP Scope Start Address
                - NDFC tab, Bootstrap
                type: str
                required: false
                default: ""
            dns_server_ip_list:
                description:
                - List of DNS servers used by switches within the fabric
                - Comma separated list of ipv4/ipv6 addresses
                - Example "10.4.0.1,2001::1"
                - NDFC label, DNS Server IPs
                - NDFC tab, Manageability
                type: str
                required: false
                default: ""
            dns_server_vrf:
                description:
                - List of VRFs in which the DNS server(s) in dns_server_ip_list reside
                - Comma separated list of VRF names
                - If a single VRF is specified, it will be used for all DNS servers, else the number of VRFs must match the number of DNS servers
                - NDFC label, DNS Server VRFs
                - NDFC tab, Manageability
                type: str
                required: false
                default: ""
            enable_aaa:
                description:
                - Include AAA configs from Manageability tab during device bootup
                - NDFC label, Enable AAA Config
                - NDFC tab, Bootstrap
                type: bool
                required: false
                default: False
            enable_agent:
                description:
                - ??
                - NDFC label, ??
                - NDFC tab, ??
                type: bool
                required: false
                default: False
            enable_default_queuing_policy:
                description:
                - Enable (True) or disable (False) Default Queuing Policies
                - NDFC label, Enable Default Queuing Policies
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            enable_fabric_vpc_domain_id:
                description:
                - Enable (True) or disable (False) the same vPC Domain Id for all vPC Pairs
                - Not recommended
                - NDFC label, Enable the same vPC Domain Id for all vPC Pairs
                - NDFC tab, vPC
                type: bool
                required: false
                default: True
            enable_macsec:
                description:
                - Enable (True) or disable (False) MACsec in the fabric
                - NDFC label, Enable MACsec
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            enable_netflow:
                description:
                - Enable (True) or disable (False) Netflow on VTEPs
                - NDFC label, Enable Netflow
                - NDFC tab, Flow Monitor
                type: bool
                required: false
                default: False
            enable_ngoam:
                description:
                - Enable (True) or disable (False) the Next Generation (NG) OAM feature for all switches in the fabric to aid in trouble-shooting VXLAN EVPN fabrics
                - NDFC label, Enable VXLAN OAM
                - NDFC tab, Advanced
                type: bool
                required: false
                default: True
            enable_nxapi:
                description:
                - Enable (True) or disable (False) HTTPS NX-API
                - NDFC label, Enable NX-API
                - NDFC tab, Advanced
                type: bool
                required: false
                default: True
            enable_nxapi_http:
                description:
                - Enable (True) or disable (False) HTTP NX-API
                - NDFC label, Enable HTTP NX-API
                - NDFC tab, Advanced
                type: bool
                required: false
                default: True
            enable_pbr:
                description:
                - Enable (True) or disable (False) PBR or ePBR
                - NDFC label, Enable Policy-Based Routing (PBR)/Enhanced PBR (ePBR)
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            enable_pvlan:
                description:
                - Enable (True) or disable (False) Private VLAN (PVLAN) Enable PVLAN on switches except spines and super spines
                - NDFC label, Enable Private VLAN (PVLAN)
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            enable_tenant_dhcp:
                description:
                - Enable (True) or disable (False) Tenant DHCP
                - NDFC label, Enable Tenant DHCP
                - NDFC tab, Advanced
                type: bool
                required: false
                default: True
            enable_trm:
                description:
                - Enable (True) or disable (False) Overlay Multicast Support In VXLAN Fabrics
                - NDFC label, Enable Tenant Routed Multicast (TRM)
                - NDFC tab, Replication
                type: bool
                required: false
                default: False
            esr_option:
                description:
                - Choose between Policy-Based Routing (PBR) or Enhanced PBR (ePBR)
                - Determines whether PBR or ePBR is used when enable_pbr is True
                - NDFC label, Elastic Services Re-direction (ESR) Options
                - NDFC tab, Advanced
                - Valid values: PBR, ePBR
                type: str
                required: false
                default: PBR
            fabric_name:
                description:
                - The name of the fabric
                type: str
                required: true
            fabric_vpc_domain_id:
                description:
                - vPC Domain Id to be used on all vPC pairs
                - NDFC label, vPC Domain Id
                - NDFC tab, vPC
                - Min:1, Max:1000
                type: str
                required: true
            grfield_debug_flag:
                description:
                - Switch Cleanup Without Reload When PreserveConfig=no
                - Valid values: Disable, Enable
                - NDFC label, Greenfield Cleanup Option
                - NDFC tab, Advanced
                type: str
                required: False
                default: Disable
            l3vni_mcast_group:
                description:
                - Default Underlay Multicast group IP assigned for every overlay VRF
                - Valid values: ipv4 multicast address
                - Default value is applied if enable_trm is True if not set in the playbook.
                - Default: 239.1.1.0
                - NDFC label, Default MDT Address for TRM VRFs
                - NDFC tab, Replication
                type: str
                required: False
            loopback0_ipv6_range:
                description:
                - Underlay Routing Loopback IPv6 Range
                - Valid values: ipv6 network with prefix
                - Default: fd00::a02:0/119
                - NDFC label, Underlay Routing Loopback IPv6 Range
                - NDFC tab, Resources
                type: str
                required: False
            loopback1_ipv6_range:
                description:
                - Underlay VTEP Loopback IPv6 Range
                - Typically Loopback1 and Anycast Loopback IPv6 Address Range
                - Valid values: ipv6 network with prefix
                - Default: fd00::a03:0/118
                - NDFC label, Underlay VTEP Loopback IPv6 Range
                - NDFC tab, Resources
                type: str
                required: False
            macsec_algorithm:
                - Configure Cipher Suite
                - Valid values:
                - 1 AES_128_CMAC
                - 2 AES_256_CMAC
                - NDFC label, MACsec Primary Cryptographic Algorithm
                - NDFC tab, Advanced
                type: int
                required: When enable_macsec is True
                default: ""
            macsec_cipher_suite:
                - Configure Cipher Suite
                - Valid values:
                - 1 GCM-AES-128
                - 2 GCM-AES-256
                - 3 GCM-AES-XPN-128
                - 4 GCM-AES-XPN-256
                - NDFC label, MACsec Cipher Suite
                - NDFC tab, Advanced
                type: int
                required: When enable_macsec is True
                default: ""
            macsec_fallback_algorithm:
                - Configure Cipher Suite
                - Valid values:
                - 1 AES_128_CMAC
                - 2 AES_256_CMAC
                - NDFC label, MACsec Fallback Cryptographic Algorithm
                - NDFC tab, Advanced
                type: int
                required: When enable_macsec is True
                default: ""
            macsec_fallback_key_string:
                - Cisco Type 7 Encrypted Octet String
                - Must be 66 hex characters for AES_128_CMAC algorithm
                - Must be 130 hex characters for AES_256_CMAC algorithm
                - NDFC label, MACsec Fallback Key String
                - NDFC tab, Advanced
                type: str
                required: When enable_macsec is True
                default: ""
            macsec_key_string:
                - Cisco Type 7 Encrypted Octet String
                - Must be 66 hex characters for AES_128_CMAC algorithm
                - Must be 130 hex characters for AES_256_CMAC algorithm
                - NDFC label, MACsec Primary Key String
                - NDFC tab, Advanced
                type: str
                required: When enable_macsec is True
                default: ""
            macsec_report_timer:
                - MACsec Operational Status periodic report timer in minutes
                - Valid values: 5-60
                - NDFC label, MACsec Status Report Timer
                - NDFC tab, Advanced
                type: int
                required: When enable_macsec is True
                default: ""
            netflow_exporter_list:
                description:
                - List of dictionaries containing Netflow Exporter details
                - NDFC label, Netflow Exporter
                - NDFC tab, Flow Monitor
                - Dictionary keys:
                    - EXPORTER_NAME: The name of the exporter
                    - IP: The IP address of the exporter
                    - VRF: The VRF in which the exporter resides
                    - UDP_PORT: The UDP port used by the exporter
                type: list of dict
                required: When enable_netflow is True
            netflow_record_list:
                description:
                - List of dictionaries containing Netflow Record details
                - NDFC label, Netflow Record
                - NDFC tab, Flow Monitor
                - Dictionary keys:
                    - RECORD_NAME: The name of the record
                    - RECORD_TEMPLATE: The template to use for the record
                    - LAYER2_RECORD: True or False.  If True, this is a layer-2 record.
                type: list of dict
                required: When enable_netflow is True
            netflow_monitor_list:
                description:
                - List of dictionaries containing Netflow Exporter details
                - NDFC label, Netflow Exporter
                - NDFC tab, Flow Monitor
                - Dictionary keys:
                    - MONITOR_NAME: The name of the monitor
                    - RECORD_NAME: The name of the netflow record. Must match RECORD_NAME in netflow_record_list.
                    - EXPORTER1: The name of the exporter for this monitor. Must match EXPORTER_NAME in netflow_exporter_list.
                type: list of dict
                required: When enable_netflow is True
            nxapi_https_port:
                description:
                - HTTPS Port Number For NX-API
                - Default 443
                - NDFC label, NX-API HTTPS Port Number
                - NDFC tab, Advanced
                type: int
                required: false
            nxapi_http_port:
                description:
                - HTTPS Port Number For NX-API
                - Default 80
                - NDFC label, NX-API HTTP Port Number
                - NDFC tab, Advanced
                type: int
                required: false
            mgmt_gw:
                description:
                - Default Gateway For Management VRF On The Switch
                - NDFC label, Switch Mgmt Default Gateway
                - NDFC tab, Bootstrap
                type: str
                required: false
            mgmt_prefix:
                description:
                - Min:8, Max:30
                - NDFC label, Switch Mgmt IP Subnet Prefix
                - NDFC tab, Bootstrap
                type: int
                required: false
            mpls_handoff:
                description:
                - Enable (True) or disable (False) VXLAN to MPLS SR/LDP Handoff
                - NDFC label, Enable MPLS Handoff
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            mpls_lb_id:
                description:
                - Min:0, Max:1023
                - NDFC label, Underlay MPLS Loopback Id
                - NDFC tab, Advanced
                type: int
                required: When mpls_handoff is True
            mpls_loopback_ip_range:
                description:
                - Used for VXLAN to MPLS SR/LDP Handoff
                - NDFC label, Underlay MPLS Loopback IP Range
                - NDFC tab, Resources
                type: str
                required: When mpls_handoff is True
            # TODO: Check if these are ND vs NDFC
            # mso_connectivity_deployed:
            # mso_controler_id:
            # mso_site_group_name:
            # mso_site_id:
            mst_instance_range:
                description:
                - Vlan range for multi-instance spanning tree (mst).
                - Example "0-3,5,7-9"
                - Default No default via API ("0" via the NDFC GUI)
                - NDFC label, MST Instance Range
                - NDFC tab, Advanced
                type: str
                required: When stp_root_option is "mst"
            multicast_group_subnet:
                description:
                - Multicast pool prefix between 8 to 30. A multicast group IP from this pool is used for BUM traffic for each overlay network.
                - l3vni_mcast_group must reside within this pool.
                - NDFC label, Multicast Group Subnet
                - NDFC tab, Advanced
                default: 239.1.1.0/25
                type: str
                required: False
            ntp_server_ip_list:
                description:
                - List of NTP servers used by switches within the fabric
                - Comma separated list of ipv4/ipv6 addresses
                - Example "10.4.0.1,2001::1"
                - NDFC label, NTP Server IPs
                - NDFC tab, Manageability
                type: str
                required: false
                default: ""
            ntp_server_vrf:
                description:
                - List of VRFs in which the NTP server(s) in ntp_server_ip_list reside
                - Comma separated list of VRF names
                - If a single VRF is specified, it will be used for all NTP servers, else the number of VRFs must match the number of NTP servers
                - NDFC label, NTP Server VRFs
                - NDFC tab, Manageability
                type: str
                required: false
                default: ""
            pm_enable:
                description:
                - Enable (True) or disable (False) fabric performance monitoring
                - NDFC label, Enable Performance Monitoring
                - NDFC tab, General Parameters
                type: bool
                required: false
                default: False
            replication_mode:
                description:
                - Replication Mode for BUM Traffic
                - NDFC label, Replication Mode
                - NDFC tab, Replication
                type: str
                required: False
                choices:
                - Ingress
                - Multicast
                default: Multicast
            router_id_range:
                description:
                - BGP Router ID Range for IPv6 Underlay
                - NDFC label, BGP Router ID Range for IPv6 Underlay
                - NDFC tab, Resources
                - Default: 10.2.0.0/23
                type: str
                required: False
            stp_bridge_priority:
                description:
                - Bridge priority for the spanning tree in increments of 4096.
                - NDFC label, Spanning Tree Bridge Priority
                - NDFC tab, Advanced
                type: int
                required: false
                choices: [0, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768, 36864, 40960, 45056, 49152, 53248, 57344, 61440]
            stp_root_option:
                description:
                - Which protocol to use for configuring root bridge.
                - NDFC label, Spanning Tree Root Bridge Protocol
                - NDFC tab, Advanced
                type: str
                required: false
                default: 0
                choices:
                - "mst" Multiple Spanning Tree
                - "rpvst+" Rapid Per-VLAN Spanning Tree
                - "unmanaged" (default) STP Root not managed by NDFC
            stp_vlan_range:
                description:
                - Vlan range for rpvst+ spanning tree.
                - Example "1,3-5,7,9-11"
                - No default via API ("1-3967" via the NDFC GUI)
                - NDFC label, Spanning Tree VLAN Range
                - NDFC tab, Advanced
                type: str
                required: When stp_root_option is "rpvst+"
            strict_cc_mode:
                description:
                - Enable (True) or disable (False) bi-directional compliance checks to flag additional configs in the running config that are not in the intent/expected config
                - NDFC label, Enable Strict Config Compliance
                - NDFC tab, Advanced
                type: bool
                required: false
                default: False
            subinterface_range:
                description:
                - Per Border Dot1q Range For VRF Lite Connectivity
                - Min 2, Max 4093
                - Example "2-511"
                - NDFC label, Subinterface Dot1q Range
                - NDFC tab, Resources
                type: str
            subnet_range:
                description:
                - Address range to assign Numbered and Peer Link SVI IPs
                - Example "10.4.0.0/16"
                - NDFC label, Underlay Subnet IP Range
                - NDFC tab, Resources
                type: str
            subnet_target_mask:
                description:
                - Mask (prefix) for Underlay Subnet IP Range
                - Min: 30, Max 31
                - Default 30
                - Example 31
                - NDFC label, Underlay Subnet IP Mask
                - NDFC tab, General Parameters
                type: int
            syslog_server_ip_list:
                description:
                - Comma separated list of IP Addresses(v4/v6)
                - Example "10.4.0.1,2001::1"
                - NDFC label, Syslog Server IPs
                - NDFC tab, Manageability
                type: str
            syslog_server_vrf:
                description:
                - List of VRFs in which the Syslog server(s) in syslog_server_ip_list reside
                - Comma separated list of VRF names
                - If a single VRF is specified, it will be used for all Syslog servers, else the number of VRFs must match the number of Syslog servers
                - Example "management,default"
                - NDFC label, Syslog Server VRFs
                - NDFC tab, Manageability
                type: str
            syslog_sev:
                description:
                - Comma separated list of Syslog severity values, one per Syslog server
                - Min:0, Max:7
                - Example "0,4,7"
                - NDFC label, Syslog Server Severity
                - NDFC tab, Manageability
                type: str
            tcam_allocation:
                description:
                - Enable (True) or disable (False) auto-generation of TCAM commands for VxLAN and vPC Fabric Peering
                - NDFC label, Enable TCAM Allocation
                - NDFC tab, Advanced
                type: bool
                required: false
                default: True
            underlay_is_v6:
                description:
                - Enable (True) or disable (False) IpV6 Underlay Addressing
                - NDFC label, Enable IPv6 Underlay
                - NDFC tab, General Parameters
                type: bool
                required: false
                default: False
            use_link_local:
                description:
                - Enable (True) or disable (False) IPv6 link-local addressing for Spine-Leaf interfaces
                - NDFC label, Enable IPv6 Link-Local Address
                - NDFC tab, General Parameters
                type: bool
                required: false
                default: True (when underlay_is_v6 is True)
            v6_subnet_range:
                description:
                - IPv6 Address range to assign Numbered and Peer Link SVI IPs
                - Valid values: ipv6 network with prefix
                - Default: fd00::a03:0/118 (when use_link_local is True)
                - Default: fd00::a04:0/112 (when use_link_local is False)
                - NDFC label, Underlay Subnet IPv6 Range
                - NDFC tab, Resources
                type: str
                required: False
            v6_subnet_target_mask:
                description:
                - Mask (prefix) for IPv6 Underlay Subnet
                - Min: 126, Max 127
                - Default 126
                - Example 127
                - NDFC label, Underlay Subnet IPv6 Mask
                - NDFC tab, General Parameters
                type: int
                required: False
            vrf_lite_autoconfig:
                description:
                - VRF Lite Inter-Fabric Connection Deployment Options.
                - If (0), VRF Lite configuration is Manual.
                - If (1), VRF Lite IFCs are auto created between border devices of two Easy Fabrics
                - If (1), VRF Lite IFCs are auto created between border devices in Easy Fabric and edge routers in External Fabric.
                - The IP address is taken from the 'VRF Lite Subnet IP Range' pool.
                - NDFC label, VRF Lite Deployment
                - NDFC tab, Resources
                type: int
                required: false
                default: 0
                choices:
                - 0
                - 1

"""

EXAMPLES = """
# This module supports the following states:
#
# Merged:
#   Fabric defined in the playbook will be created.
#
# Query:
#   Returns the current DCNM state for the fabric.


# The following will create fabric my-fabric
- name: Create fabric
  cisco.dcnm.dcnm_fabric:
    state: merged
    config:
    -   fabric_name: my-fabric
        bgp_as: 100

"""


class DcnmFabric:
    """
    Ansible support for Data Center VXLAN EVPN (Easy_Fabric)
    """

    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.verify = VerifyFabricParams()
        # populated in self.validate_input()
        self.payloads = {}
        # TODO:1 set self.debug to False to disable self.log_msg()
        self.debug = True
        # File descriptor set by self.log_msg()
        self.fd = None
        # File self.log_msg() logs to
        self.logfile = "/tmp/dcnm_easy_fabric.log"

        self.config = module.params.get("config")
        if not isinstance(self.config, list):
            msg = "expected list type for self.config. "
            msg = f"got {type(self.config).__name__}"
            self.module.fail_json(msg=msg)

        self.check_mode = False
        self.validated = []
        self.have_create = []
        self.want_create = []
        self.diff_create = []
        self.diff_save = {}
        self.query = []
        self.result = dict(changed=False, diff=[], response=[])

        self.nd_prefix = "/appcenter/cisco/ndfc/api/v1/lan-fabric"
        self.controller_version = dcnm_version_supported(self.module)
        self.nd = self.controller_version >= 12

        # TODO:4 Will need to revisit bgp_as at some point since the
        # following fabric types don't require it.
        # - Fabric Group
        # - Classis LAN
        # - LAN Monitor
        # - VXLAN EVPN Multi-Site
        # We'll cross that bridge when we get to it
        self.mandatory_keys = {"fabric_name", "bgp_as"}
        # Populated in self.get_have()
        self.fabric_details = {}
        # Not currently using. Commented out in self.get_have()
        self.inventory_data = {}
        for item in self.config:
            if not self.mandatory_keys.issubset(item):
                msg = f"missing mandatory keys in {item}. "
                msg += f"expected {self.mandatory_keys}"
                self.module.fail_json(msg=msg)

    def get_have(self):
        """
        Caller: main()

        Determine current fabric state on NDFC for all existing fabrics
        """
        for item in self.config:
            # mandatory keys have already been checked in __init__()
            fabric = item["fabric_name"]
            self.fabric_details[fabric] = get_fabric_details(self.module, fabric)
            # self.inventory_data[fabric] = get_fabric_inventory_details(
            #     self.module, fabric
            # )

        fabrics_exist = set()
        for fabric in self.fabric_details:
            path = f"/rest/control/fabrics/{fabric}"
            if self.nd:
                path = self.nd_prefix + path
            fabric_info = dcnm_send(self.module, "GET", path)
            result = self._handle_get_response(fabric_info)
            if result["found"]:
                fabrics_exist.add(fabric)
            if not result["success"]:
                msg = "Unable to retrieve fabric information from NDFC"
                self.module.fail_json(msg=msg)
        if fabrics_exist:
            msg = "Fabric(s) already present on NDFC: "
            msg += f"{','.join(sorted(fabrics_exist))}"
            self.module.fail_json(msg=msg)

    def get_want(self):
        """
        Caller: main()

        Update self.want_create for all fabrics defined in the playbook
        """
        want_create = []

        # we don't want to use self.validated here since
        # validate_list_of_dicts() adds items the user did not set to
        # self.validated.  self.validate_input() has already been called,
        # so if we got this far the items in self.config have been validated
        # to conform to their param spec.
        for fabric_config in self.config:
            want_create.append(fabric_config)
        if not want_create:
            return
        self.want_create = want_create

    def get_diff_merge(self):
        """
        Caller: main()

        Populates self.diff_create list() with items from our want list
        that are not in our have list.  These items will be sent to NDFC.
        """
        diff_create = []

        for want_c in self.want_create:
            found = False
            for have_c in self.have_create:
                if want_c["fabric_name"] == have_c["fabric_name"]:
                    found = True
            if not found:
                diff_create.append(want_c)
        self.diff_create = diff_create

    @staticmethod
    def _build_params_spec_for_merged_state():
        """
        Build the specs for the parameters expected when state == merged.

        Caller: _validate_input_for_merged_state()
        Return: params_spec, a dictionary containing the set of
                parameter specifications.
        """
        params_spec = {}
        params_spec.update(
            aaa_remote_ip_enabled=dict(
            required=False,
            type="bool",
            default=False)
        )
        params_spec.update(
            aaa_server_conf=dict(
            required=False,
            type="str",
            default="")
        )
        # TODO:6 active_migration
        # active_migration doesn't seem to be represented in
        # the NDFC EasyFabric GUI.  Add this param if we figure out
        # what it's used for and where in the GUI it's represented
        params_spec.update(
            advertise_pip_bgp=dict(required=False, type="bool", default=False)
        )
        # TODO:6 agent_intf (add if needed)
        params_spec.update(
            anycast_bgw_advertise_pip=dict(required=False, type="bool", default=False)
        )
        params_spec.update(
            anycast_gw_mac=dict(required=False, type="str", default="2020.0000.00aa")
        )
        params_spec.update(
            anycast_lb_id=dict(
                required=False, type="int", range_min=0, range_max=1023, default=""
            )
        )
        params_spec.update(
            anycast_rp_ip_range=dict(
                required=False, type="ipv4_subnet", default="10.254.254.0/24"
            )
        )
        params_spec.update(
            auto_symmetric_default_vrf=dict(required=False, type="bool", default=False)
        )
        params_spec.update(
            auto_symmetric_vrf_lite=dict(required=False, type="bool", default=False)
        )
        params_spec.update(
            auto_vrflite_ifc_default_vrf=dict(
                required=False, type="bool", default=False
            )
        )
        params_spec.update(banner=dict(required=False, type="str", default=""))
        params_spec.update(bfd_auth_enable=dict(required=False, type="bool", default=False))
        params_spec.update(bfd_auth_key=dict(required=False, type="str"))
        params_spec.update(bfd_auth_key_id=dict(required=False, type="str"))
        params_spec.update(bfd_enable=dict(required=False, type="bool", default=False))
        params_spec.update(bfd_ibgp_enable=dict(required=False, type="bool", default=False))
        params_spec.update(bfd_isis_enable=dict(required=False, type="bool", default=False))
        params_spec.update(bfd_ospf_enable=dict(required=False, type="bool", default=False))
        params_spec.update(bfd_pim_enable=dict(required=False, type="bool", default=False))
        params_spec.update(bgp_as=dict(required=True, type="str"))
        params_spec.update(
            bgp_auth_enable=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            bgp_auth_key=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            bgp_auth_key_type=dict(
                required=False,
                type="str",
                default="",
                choices=["3", "7"],
            )
        )
        params_spec.update(
            bgp_lb_id=dict(
                required=False, type="int", range_min=0, range_max=1023, default=""
            )
        )
        params_spec.update(
            bootstrap_conf=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            bootstrap_enable=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            bootstrap_multisubnet=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            brfield_debug_flag=dict(
                required=False,
                type="str",
                default="Disable",
                choices=["Disable", "Enable"],
            )
        )
        params_spec.update(
            brownfield_network_name_format=dict(
                required=False,
                type="str",
                default="Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$",
            )
        )
        params_spec.update(
            brownfield_skip_overlay_network_attachments=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            cdp_enable=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            copp_policy=dict(
                required=False,
                type="str",
                default="strict",
                choices=["dense", "lenient", "manual", "moderate", "strict"],
            )
        )
        params_spec.update(
            dci_subnet_range=dict(
                required=False,
                type="ipv4_subnet",
                default="10.33.0.0/16",
            )
        )
        params_spec.update(
            dci_subnet_target_mask=dict(
                required=False,
                type="int",
                range_min=8,
                range_max=31,
                default=30,
            )
        )
        params_spec.update(
            default_queuing_policy_cloudscale=dict(
                required=False,
                type="str",
                default="",
                choices=["queuing_policy_default_8q_cloudscale", "queuing_policy_default_4q_cloudscale"],
            )
        )
        params_spec.update(
            default_queuing_policy_other=dict(
                required=False,
                type="str",
                default="",
                choices=["queuing_policy_default_other"],
            )
        )
        params_spec.update(
            default_queuing_policy_r_series=dict(
                required=False,
                type="str",
                default="",
                choices=["queuing_policy_default_r_series"],
            )
        )
        params_spec.update(
            default_vrf_redis_bgp_rmap=dict(required=False, type="str", default="")
        )
        params_spec.update(
            deployment_freeze=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            dhcp_enable=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            dhcp_end=dict(
                required=False,
                type="ipv4",
                default=False,
            )
        )
        params_spec.update(
            dhcp_ipv6_enable=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            dhcp_start=dict(
                required=False,
                type="ipv4",
                default=False,
            )
        )
        params_spec.update(
            dns_server_ip_list=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            dns_server_vrf=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            enable_aaa=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            enable_agent=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            default_pvlan_sec_network=dict(
                required=False,
                type="str",
                default="Pvlan_Secondary_Network",
                choices=["Pvlan_Secondary_Network"],
            )
        )
        params_spec.update(
            enable_default_queuing_policy=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        # enable_evpn is not required or supported by 
        # VXLAN/EVPN fabric type
        params_spec.update(enable_http_nxapi=dict(required=False, type="bool", default=True))
        params_spec.update(
            enable_fabric_vpc_domain_id=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            enable_macsec=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            enable_netflow=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(enable_ngoam=dict(required=False, type="bool", default=True))
        params_spec.update(enable_nxapi=dict(required=False, type="bool", default=True))
        params_spec.update(enable_pbr=dict(required=False, type="bool", default=False))
        params_spec.update(enable_pvlan=dict(required=False, type="bool", default=False))
        params_spec.update(enable_tenant_dhcp=dict(required=False, type="bool", default=True))
        params_spec.update(enable_trm=dict(required=False, type="bool", default=False))
        params_spec.update(
            esr_option=dict(
                required=False,
                type="str",
                default="PBR",
                choices=["ePBR", "PBR"],
            )
        )
        params_spec.update(fabric_name=dict(required=True, type="str"))
        params_spec.update(
            fabric_vpc_domain_id=dict(
                required=False,
                type="int",
                default="",
                range_min=1,
                range_max=1000,
            )
        )
        params_spec.update(
            grfield_debug_flag=dict(
                required=False,
                type="str",
                default="Disable",
                choices=["Disable", "Enable"],
            )
        )
        params_spec.update(
            l3vni_mcast_group=dict(
                required=False,
                type="ipv4_mcast_address",
                default="239.1.1.0",
            )
        )
        params_spec.update(
            loopback0_ipv6_range=dict(
                required=False,
                type="ipv6_subnet",
                default="",
            )
        )
        params_spec.update(
            loopback1_ipv6_range=dict(
                required=False,
                type="ipv6_subnet",
                default="",
            )
        )
        params_spec.update(
            macsec_algorithm=dict(
                required=False,
                type="int",
                default="",
                range_min=1,
                range_max=2,
            )
        )
        params_spec.update(
            macsec_cipher_suite=dict(
                required=False,
                type="int",
                default="",
                range_min=1,
                range_max=4,
            )
        )
        params_spec.update(
            macsec_fallback_algorithm=dict(
                required=False,
                type="int",
                default="",
                range_min=1,
                range_max=2,
            )
        )
        params_spec.update(
            macsec_fallback_key_string=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            macsec_key_string=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            macsec_report_timer=dict(
                required=False,
                type="int",
                default="",
                range_min=5,
                range_max=60,
            )
        )
        params_spec.update(
            mgmt_gw=dict(
                required=False,
                type="ipv4",
                default=False,
            )
        )
        params_spec.update(
            mgmt_prefix=dict(
                required=False,
                type="int",
                range_min=8,
                range_max=30,
                default=False,
            )
        )
        params_spec.update(
            mpls_handoff=dict(
                required=False,
                type="bool",
                default=False,
            )
        )
        params_spec.update(
            mpls_lb_id=dict(
                required=False,
                type="int",
                range_min=0,
                range_max=1023,
                default="",
            )
        )
        params_spec.update(
            mpls_loopback_ip_range=dict(
                required=False,
                type="ipv4_subnet",
                default="",
            )
        )
        params_spec.update(
            mst_instance_range=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            multicast_group_subnet=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            netflow_exporter_list=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            netflow_record_list=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            netflow_monitor_list=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            ntp_server_ip_list=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            ntp_server_vrf=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            nxapi_https_port=dict(
                required=False,
                type="int",
                default=443,
            )
        )
        params_spec.update(
            nxapi_http_port=dict(
                required=False,
                type="int",
                default=80,
            )
        )
        params_spec.update(pm_enable=dict(required=False, type="bool", default=False))
        params_spec.update(
            replication_mode=dict(
                required=False,
                type="str",
                default="Multicast",
                choices=["Ingress", "Multicast"],
            )
        )
        params_spec.update(
            stp_bridge_priority=dict(
                required=False,
                type="str",
                # validate_list_of_dicts() does not support choices
                # being a list of int, so we've converted
                # the user's input to str and compare to str(). We convert
                # this back to int() before sending to NDFC.
                choices=[str(x) for x in range(0,61441) if not x % 4096],
            )
        )        
        params_spec.update(
            stp_root_option=dict(
                required=False,
                type="str",
                default="unmanaged",
                choices=["mst", "rpvst+", "unmanaged"],
            )
        )
        params_spec.update(
            stp_vlan_range=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(strict_cc_mode=dict(required=False, type="bool", default=False))
        params_spec.update(
            subinterface_range=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            subnet_range=dict(
                required=False,
                type="ipv4_subnet",
                default="10.4.0.0/16",
            )
        )
        params_spec.update(
            subnet_target_mask=dict(
                required=False,
                type="int",
                range_min=30,
                range_max=31,
                default=30,
            )
        )
        params_spec.update(
            syslog_server_ip_list=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            syslog_server_vrf=dict(
                required=False,
                type="str",
                default="",
            )
        )
        params_spec.update(
            syslog_sev=dict(
                required=False,
                type="str",
            )
        )
        params_spec.update(tcam_allocation=dict(required=False, type="bool", default=True))
        params_spec.update(underlay_is_v6=dict(required=False, type="bool", default=False))
        params_spec.update(use_link_local=dict(required=False, type="bool", default=False))
        # TODO:4 Ask about this.  The default is different depending on the value of use_link_local
        params_spec.update(
            v6_subnet_range=dict(
                required=False,
                type="ipv6_subnet",
                default="fd00::a03:0/118",
            )
        )
        params_spec.update(
            v6_subnet_target_mask=dict(
                required=False,
                type="int",
                range_min=126,
                range_max=127,
                default=126,
            )
        )
        params_spec.update(
            vrf_lite_autoconfig=dict(
                required=False,
                type="int",
                default=0,
                range_min=0,
                range_max=1,
            )
        )
        return params_spec

    def validate_input(self):
        """
        Caller: main()

        Validate the playbook parameters
        Build the payloads for each fabric
        """
        state = self.params["state"]

        # TODO:2 remove this when we implement query state
        if state != "merged":
            msg = f"Only merged state is supported. Got state {state}"
            self.module.fail_json(msg=msg)

        if state == "merged":
            self._validate_input_for_merged_state()

        self.payloads = {}
        for fabric_config in self.config:
            verify = VerifyFabricParams()
            verify.state = state
            verify.config = fabric_config
            # At this point VerifyFabricParams has validated
            # state and config and seeded an appropriate msg
            # in the event something is wrong with either.
            if verify.result is False:
                self.module.fail_json(msg=verify.msg)
            verify.validate_config()
            # Now we're validating the specific parameters
            # that are set in the playbook.
            if verify.result is False:
                self.module.fail_json(msg=verify.msg)
            # If everything is good, we have a validated payload
            self.payloads[fabric_config["fabric_name"]] = verify.payload

    def _validate_input_for_merged_state(self):
        """
        Caller: self._validate_input()

        Valid self.config contains appropriate values for merged state
        """
        params_spec = self._build_params_spec_for_merged_state()
        msg = None
        if not self.config:
            msg = "config: element is mandatory for state merged"
            self.module.fail_json(msg=msg)

        # validate_list_of_dicts() does not like a list of int()
        # for choices.  We convert things like stp_bridge_priority
        # to str() before calling it, then convert it back to int()
        # afterwards.  If there are more parameters like this, we'll
        # move this to its own function.
        if "stp_bridge_priority" in self.config:
            self.config["stp_bridge_priority"] = str(
                self.config["stp_bridge_priority"]
            )

        valid_params, invalid_params = validate_list_of_dicts(
            self.config, params_spec, self.module
        )
        # We're not using self.validated. Keeping this to avoid
        # linter error due to non-use of valid_params
        self.validated = copy.deepcopy(valid_params)

        if "stp_bridge_priority" in self.config:
            # this is safe, since we've already validated
            # this is an int-like string.
            self.config["stp_bridge_priority"] = int(
                self.config["stp_bridge_priority"]
            )

        if invalid_params:
            msg = "Invalid parameters in playbook: "
            msg += f"{','.join(invalid_params)}"
            self.module.fail_json(msg=msg)

    def create_fabrics(self):
        """
        Caller: main()

        Build and send the payload to create the
        fabrics specified in the playbook.
        """
        path = "/rest/control/fabrics"
        if self.nd:
            path = self.nd_prefix + path

        for item in self.want_create:
            fabric = item["fabric_name"]

            payload = self.payloads[fabric]
            self.log_msg(f"create_fabrics: payload {payload}")
            response = dcnm_send(self.module, "POST", path, data=json.dumps(payload))
            result = self._handle_post_put_response(response, "POST")

            if not result["success"]:
                self.log_msg(
                    f"create_fabrics: calling self._failure with response {response}"
                )
                self._failure(response)

    def _handle_get_response(self, response):
        """
        Caller:
            - self.get_have()
        Handle NDFC responses to GET requests
        Returns: dict() with the following keys:
        - found:
            - False, if request error was "Not found" and RETURN_CODE == 404
            - True otherwise
        - success:
            - False if RETURN_CODE != 200 or MESSAGE != "OK"
            - True otherwise
        """
        # Example response
        # {
        #     'RETURN_CODE': 404,
        #     'METHOD': 'GET',
        #     'REQUEST_PATH': '...user path goes here...',
        #     'MESSAGE': 'Not Found',
        #     'DATA': {
        #         'timestamp': 1691970528998,
        #         'status': 404,
        #         'error': 'Not Found',
        #         'path': '/rest/control/fabrics/IR-Fabric'
        #     }
        # }
        result = {}
        success_return_codes = {200, 404}
        if (
            response.get("RETURN_CODE") == 404
            and response.get("MESSAGE") == "Not Found"
        ):
            result["found"] = False
            result["success"] = True
            return result
        if (
            response.get("RETURN_CODE") not in success_return_codes
            or response.get("MESSAGE") != "OK"
        ):
            result["found"] = False
            result["success"] = False
            return result
        result["found"] = True
        result["success"] = True
        return result

    def _handle_post_put_response(self, response, verb):
        """
        Caller:
            - self.create_fabrics()

        Handle POST, PUT responses from NDFC.

        Returns: dict() with the following keys:
        - changed:
            - True if changes were made to NDFC
            - False otherwise
        - success:
            - False if RETURN_CODE != 200 or MESSAGE != "OK"
            - True otherwise

        """
        # Example response
        # {
        #     'RETURN_CODE': 200,
        #     'METHOD': 'POST',
        #     'REQUEST_PATH': '...user path goes here...',
        #     'MESSAGE': 'OK',
        #     'DATA': {...}
        valid_verbs = {"POST", "PUT"}
        if verb not in valid_verbs:
            msg = f"invalid verb {verb}. "
            msg += f"expected one of: {','.join(sorted(valid_verbs))}"
            self.module.fail_json(msg=msg)

        result = {}
        if response.get("MESSAGE") != "OK":
            result["success"] = False
            result["changed"] = False
            return result
        if response.get("ERROR"):
            result["success"] = False
            result["changed"] = False
            return result
        result["success"] = True
        result["changed"] = True
        return result

    def _failure(self, resp):
        """
        Caller: self.create_fabrics()

        This came from dcnm_inventory.py, but doesn't seem to be correct
        for the case where resp["DATA"] does not exist?

        If resp["DATA"] does not exist, the contents of the
        if block don't seem to actually do anything:
            - data will be None
            - Hence, data.get("stackTrace") will also be None
            - Hence, data.update() and res.update() are never executed

        So, the only two lines that will actually ever be executed are
        the happy path:

        res = copy.deepcopy(resp)
        self.module.fail_json(msg=res)
        """
        res = copy.deepcopy(resp)

        if not resp.get("DATA"):
            data = copy.deepcopy(resp.get("DATA"))
            if data.get("stackTrace"):
                data.update(
                    {"stackTrace": "Stack trace is hidden, use '-vvvvv' to print it"}
                )
                res.update({"DATA": data})

        self.module.fail_json(msg=res)

    def log_msg(self, msg):
        """
        used for debugging. disable this when committing to main
        """
        if self.debug is False:
            return
        if self.fd is None:
            try:
                self.fd = open(f"{self.logfile}", "a+", encoding="UTF-8")
            except IOError as err:
                msg = f"error opening logfile {self.logfile}. "
                msg += f"detail: {err}"
                self.module.fail_json(msg=msg)

        self.fd.write(msg)
        self.fd.write("\n")
        self.fd.flush()


def main():
    """main entry point for module execution"""

    element_spec = dict(
        config=dict(required=False, type="list", elements="dict"),
        state=dict(default="merged", choices=["merged"]),
    )

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)
    dcnm_fabric = DcnmFabric(module)
    dcnm_fabric.validate_input()
    dcnm_fabric.get_have()
    dcnm_fabric.get_want()

    if module.params["state"] == "merged":
        dcnm_fabric.get_diff_merge()

    if dcnm_fabric.diff_create:
        dcnm_fabric.result["changed"] = True
    else:
        module.exit_json(**dcnm_fabric.result)

    if module.check_mode:
        dcnm_fabric.result["changed"] = False
        module.exit_json(**dcnm_fabric.result)

    if dcnm_fabric.diff_create:
        dcnm_fabric.create_fabrics()

    module.exit_json(**dcnm_fabric.result)


if __name__ == "__main__":
    main()
