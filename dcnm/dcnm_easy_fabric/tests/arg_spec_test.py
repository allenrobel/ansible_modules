#!/usr/bin/env python
import sys
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
argument_spec = {}
argument_spec.update(
    name=dict(
        type='str',
        required=True,
        choices=["foo", "bar"],
    )
)
argument_spec.update(
    age=dict(type='int'),
)

mutually_exclusive = [
    ['name', 'age'],
]
required_if = [
    ('name', 'bo', ['age']),
]
parameters = {
    'name': 'bo',
    'age': '42',
}

#validator = ArgumentSpecValidator(argument_spec, mutually_exclusive=mutually_exclusive, required_if=required_if)
validator = ArgumentSpecValidator(argument_spec, required_if=required_if)
result = validator.validate(parameters)

if result.error_messages:
    sys.exit("Validation failed: {0}".format(", ".join(result.error_messages)))

valid_params = result.validated_parameters
print(f"Validated parameters: {valid_params}")