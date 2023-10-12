#!/usr/bin/env python
def get_serial_numbers(devices):
    """
    return a list of serial numbers from a dict of devices
    """
    return [device.get("serialNumber") for device in devices]

devices = [
    {
        "serialNumber": "1234567890",
        "policyName": "NR1F",
    },
    {
        "serialNumber": "A234567890",
        "policyName": "NR1F",
    },
    {
        "serialNumber": "B234567890",
        "policyName": "NR1F",
    }
]

print(get_serial_numbers(devices))