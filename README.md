# Motor Adapter for PyCasbin
[![Test](https://github.com/wf-yamaday/motor-adapter/actions/workflows/ci-test.yml/badge.svg)](https://github.com/wf-yamaday/motor-adapter/actions/workflows/ci-test.yml)
[![Lint](https://github.com/wf-yamaday/motor-adapter/actions/workflows/ci-lint.yml/badge.svg)](https://github.com/wf-yamaday/motor-adapter/actions/workflows/ci-lint.yml)
[![Release](https://github.com/wf-yamaday/motor-adapter/actions/workflows/release.yml/badge.svg)](https://github.com/wf-yamaday/motor-adapter/actions/workflows/release.yml)
[![Coverage Status](https://coveralls.io/repos/github/wf-yamaday/motor-adapter/badge.svg?branch=main)](https://coveralls.io/github/wf-yamaday/motor-adapter?branch=main)
![PyPI - Version](https://img.shields.io/pypi/v/casbin_motor_adapter)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/casbin_motor_adapter)
![PyPI - License](https://img.shields.io/pypi/l/casbin_motor_adapter)


[Motor](https://motor.readthedocs.io/en/stable/) adapter for [PyCasbin](https://github.com/casbin/pycasbin).  
With this library, Casbin can load policy from MongoDB or save policy to it.

## Example

Motor support a coroutine-based API for non-blocking access to MongoDB.  
So that, this adapter allows you to use pycasbin's [AsyncEnforcer](https://github.com/casbin/pycasbin/blob/master/casbin/async_enforcer.py).

### `load_policy()`

`load_policy()` loads all policies from storage.

```py
import casbin_motor_adapter
import casbin

adapter = casbin_motor_adapter.Adapter('mongodb://localhost:27017/', "dbname")

e = casbin.AsyncEnforcer('path/to/model.conf', adapter, True)
await e.load_policy()

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass
```

### `load_filtered_policy()`

`load_filtered_policy()` loads filtered policies from storage. This is useful for performance optimization.

> Policy Subset Loading, https://casbin.org/docs/policy-subset-loading

Additionally, `load_filtered_policy()` supports the MongoDB native queries for filtering conditions.

```py
import casbin_motor_adapter
import casbin

adapter = casbin_motor_adapter.Adapter('mongodb://localhost:27017/', "dbname")

e = casbin.AsyncEnforcer('path/to/model.conf', adapter, True)

# define filter conditions
filter = Filter()
filter.ptype = ["p"]
filter.v0 = ["alice"]

# support MongoDB native query
filter.raw_query = {
    "ptype": "p",
    "v0": {
        "$in": ["alice"]
    }
}

# In this case, load only policies with sub value alice
await e.load_filtered_policy(filter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass

```

## Acknowledgments

This adapter was inspired by [pymongo-adapter](https://github.com/pycasbin/pymongo-adapter).

## License

[Apache 2.0 license](./LICENSE.txt).