Syscat scripts
==============

Much as it sounds, a repo of scripts for interacting with Syscat.

# Setup

These scripts are in the `scripts` subdirectory. Yes, this thing's full of surprises.

`./create_schema.py` will install the default schema, which you can then customise to your needs.

`./default_dataset.py` will install a reasonable set of defaults, which you may wish to customise for your own environment.

Both scripts are driven by YAML files, making it as easy as possible to manage them. If YAML sounds tedious to edit by hand, consider that the first iteration used JSON.

Both scripts assume you're running Syscat on http://localhost:4950, so you may need to edit them on that basis, if nothing else.


# Discovery

`discovery/discover_into_syscat.py` explores a device via [netdescribe](https://github.com/equill/netdescribe/), and ensures there's an entry in Syscat corresponding to what it just found.

If an entry exists for that device, its details will be updated to match what was discovered.

## Usage

```
./discover_into_syscat.py <address> \
    [--syscat-url <URL for your Syscat server>] \
    [--name <name for Syscat to use>] \
    [-- use_sysname <boolean>] \
    [--community <SNMP community string>] \
    [--debug]
```

- `address` is the only mandatory argument
    - the IP address, FQDN, or otherwise resolvable name or address for the device to explore.
    - if you don't specify a name via the `--name` parameter, this will be used instead.
- `--syscat-url` is the base URL for your Syscat server, _without_ a trailing slash.
    - default is `http://localhost:4950`
- `--name` is the name you want Syscat to call this device, instead of `address`
    - takes precedence over `--use-sysname`
- `--use-sysname` indicates whether you want to use the SNMP-discovered sysName instead of `address`
    - is ignored if you also specify `--name`
- `--community` is the SNMP string accepted by the target device
    - default is `public`.


## Discovered data

That is, what it actually puts into Syscat

- device, i.e, an instance of `/devices/<hostname>`, where `<hostname>` is either `address` or the value of `--name`
    - sysname = the value of the SNMP OID `sysName`. Usually the hostname as configured on the device itself
    - sysdescr = the value of the SNMP OID `sysDescr`.
