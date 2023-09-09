#!/usr/bin/env python
#from yaml import load, dump, Loader, Dumper
import yaml
import json
import copy

def get_config():
    return """
        config:
            #policy: NR3F
            stage: false
            upgrade: false
            switches:
            -   ip_address: 192.168.1.1
                #policy: NR1F
                #stage: true
                #upgrade: true
            -   ip_address: 192.168.1.2
                policy: NR2F
                stage: false
                upgrade: false
    """
def fail(msg):
    print(msg)
    exit(1)

def merge_global_and_switch_configs(config):
    global_config = {}
    global_config['policy'] = config.get('policy')
    global_config['stage'] = config.get('stage')
    global_config['upgrade'] = config.get('upgrade')

    switch_configs = []
    if not config.get('switches'):
        msg = "playbook is missing list of switches"
        fail(msg)
    for switch in config['switches']:
        switch_configs.append(global_config | switch)
    for switch in switch_configs:
        if not switch.get('ip_address'):
            msg = "playbook is missing ip_address for at least one switch"
            fail(msg)
        if not switch.get('policy'):
            msg = "playbook is missing image policy for at least one switch, and global image policy is not defined"
            fail(msg)
        if switch.get('stage') is None:
            switch['stage'] = True
        if not switch.get('upgrade') is None:
            switch['upgrade'] = True
    return switch_configs

config = yaml.load(get_config(), Loader=yaml.Loader)
# print(json.dumps(config.get("config"), indent=4))
#switch_configs1 = merge_global_and_switch_configs_orig(config.get("config"))
#print(json.dumps(switch_configs1, indent=4))
switch_configs2 = merge_global_and_switch_configs(config.get("config"))
print(json.dumps(switch_configs2, indent=4))
