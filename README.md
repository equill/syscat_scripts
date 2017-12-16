Syscat scripts
==============

Much as it sounds, a repo of scripts for interacting with Syscat.

It's a new application, so there isn't much here yet.

# Discovery

`discovery/discover_into_syscat.py` explores a device via [netdescribe](https://github.com/equill/netdescribe/), and ensures there's an entry in Syscat corresponding to what it just found.

## Usage

```
./discover_into_syscat.py <address> [--syscat-url <URL for your Syscat server>] [--name <name for Syscat to use>] \
    [--community <SNMP community string>] [--debug]
```

- `address` is the only mandatory argument
    - the IP address, FQDN, or otherwise resolvable name or address for the device to explore.
    - if you don't specify a name via the `--name` parameter, this will be used instead.
- `--syscat-url` is the base URL for your Syscat server, _without_ a trailing slash.
    - default is `http://localhost:4950`
- `--name` is the name you want Syscat to call this device
- `--community` is the SNMP string accepted by the target device
    - default is `public`.


## Discovered data

That is, what it actually puts into Syscat

- device, i.e, an instance of `/devices/<hostname>`, where `<hostname>` is either `address` or the value of `--name`
    - sysname = the value of the SNMP OID `sysName`. Usually the hostname as configured on the device itself
    - sysdescr = the value of the SNMP OID `sysDescr`.
