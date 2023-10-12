#!/usr/bin/env python
import copy

def _init_defaults():
    defaults = {}
    defaults["stage"] = True
    defaults["validate"] = True
    defaults["upgrade"] = {}
    defaults["upgrade"]["nxos"] = True
    defaults["upgrade"]["epld"] = False
    defaults["options"] = {}
    defaults["options"]["nxos"] = {}
    defaults["options"]["nxos"]["mode"] = "disruptive"
    defaults["options"]["nxos"]["bios_force"] = False
    defaults["options"]["epld"] = {}
    defaults["options"]["epld"]["module"] = "ALL"
    defaults["options"]["epld"]["golden"] = False
    defaults["options"]["reboot"] = {}
    defaults["options"]["reboot"]["config_reload"] = False
    defaults["options"]["reboot"]["write_erase"] = False
    defaults["options"]["package"] = {}
    defaults["options"]["package"]["install"] = False
    defaults["options"]["package"]["uninstall"] = False
    return copy.deepcopy(defaults)

def _merge_defaults_to_switch_config(defaults, config):
    if config.get("stage") is None:
        config["stage"] = defaults["stage"]
    if config.get("upgrade") is None:
        config["upgrade"] = defaults["upgrade"]
    if config.get("upgrade").get("nxos") is None:
        config["upgrade"]["nxos"] = defaults["upgrade"]["nxos"]
    if config.get("upgrade").get("epld") is None:
        config["upgrade"]["epld"] = defaults["upgrade"]["epld"]
    if config.get("options") is None:
        config["options"] = defaults["options"]
    if config["options"].get("nxos") is None:
        config["options"]["nxos"] = defaults["options"]["nxos"]
    if config["options"]["nxos"].get("mode") is None:
        config["options"]["nxos"]["mode"] = defaults["options"]["nxos"]["mode"]
    if config["options"]["nxos"].get("bios_force") is None:
        config["options"]["nxos"]["bios_force"] = defaults["options"]["nxos"]["bios_force"]
    if config["options"].get("epld") is None:
        config["options"]["epld"] = defaults["options"]["epld"]
    if config["options"]["epld"].get("module") is None:
        config["options"]["epld"]["module"] = defaults["options"]["epld"]["module"]
    if config["options"]["epld"].get("golden") is None:
        config["options"]["epld"]["golden"] = defaults["options"]["epld"]["golden"]
    if config["options"].get("reboot") is None:
        config["options"]["reboot"] = defaults["options"]["reboot"]
    if config["options"]["reboot"].get("config_reload") is None:
        config["options"]["reboot"]["config_reload"] = defaults["options"]["reboot"]["config_reload"]
    if config["options"]["reboot"].get("write_erase") is None:
        config["options"]["reboot"]["write_erase"] = defaults["options"]["reboot"]["write_erase"]
    if config["options"].get("package") is None:
        config["options"]["package"] = defaults["options"]["package"]
    if config["options"]["package"].get("install") is None:
        config["options"]["package"]["install"] = defaults["options"]["package"]["install"]
    if config["options"]["package"].get("uninstall") is None:
        config["options"]["package"]["uninstall"] = defaults["options"]["package"]["uninstall"]
    return config

config = {}
config["stage"] = True
config["validate"] = True
config["upgrade"] = {}
config["upgrade"]["nxos"] = False
config["upgrade"]["epld"] = True
config["options"] = {}
config["options"]["nxos"] = {}
config["options"]["nxos"]["mode"] = "non_disruptive"
config["options"]["epld"] = {}
config["options"]["epld"]["module"] = "27"
config["options"]["epld"]["golden"] = True


print(f"config before merge {config}")
switch_final = _merge_defaults_to_switch_config(_init_defaults(), config)
print(f"config after merge {switch_final}")
