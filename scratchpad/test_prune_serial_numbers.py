#!/usr/bin/env python
def prune_serial_numbers(devices):
    """
    If the image is already upgraded on a device, remove that device
    from self.devices.  self.devices has already been validated, so
    no error checking is needed here.
    """
    serial_numbers_to_remove = set()
    serial_numbers_to_remove.add("1234567890")
    for device in devices:
        serial_number = device.get("serialNumber")
        upgrade = issu_mock_data.get(serial_number, {}).get("upgrade")
        ip_address = issu_mock_data.get(serial_number, {}).get("ipAddress")
        if upgrade == "Success":
            msg = "image already upgraded for "
            msg += f"{serial_number} / {ip_address}"
            print(msg)
            serial_numbers_to_remove.add(serial_number)
    return [device for device in devices if device.get("serialNumber") not in serial_numbers_to_remove]

issu_mock_data = {}
issu_mock_data["1234567890"] = {}
issu_mock_data["1234567890"]["upgrade"] = "Success"
issu_mock_data["1234567890"]["ipAddress"] = "172.22.150.102"

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

print(prune_serial_numbers(devices))