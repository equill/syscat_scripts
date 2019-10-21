device42.py - migrate data from Device42 into Syscat
====================================================

# Usage

```
./device42.py [options...]
```

See the output of `./device42.py` for details about the options.


# What it does

It replicates a subset of data from Device42 into Syscat, adapting from one data model to the other, and making a few assumptions about how best to match them.


## What it replicates, and what they become in Syscat

- tags -> `tags`
- customers -> `organisations`
-- in Syscat "vendor" and "customer" is a relative thing
- vendors -> `makes`
-- in practice, this seems to be what vendors represent in Device42
- hardwares -> `models`
- operating systems -> `operatingSystems`
- buildings -> `sites` _and_ `buildings`
-- Device42 assumes a single campus or, at most, multiple single-building sites. Syscat makes the logical distinction between sites and buildings, and this script assumes that a building in Device42 represents both.
- rooms -> `rooms`
- devices -> `devices`
-- also creates links to resources representing the following device attributes from Device42:
--- `customer` -> `BusinessOwner` relationship to an `organisations` resource
--- `os` -> `OperatingSystems` link to an `operatingSystems` resource
--- `tags` -> 'Tags` link to the relevant `tags`
--- 'building` or `room` to a `buildings` or `rooms` resource, as appropriate
- Switchports -> `/devices/<device id>/Interfaces/networkInterfaces`
-- but only if it can be attributed to a device. Free-floating switchports are ignored.
- VMs -> `devices`
-- with a `Host` relationship to the host device.
- subnets
-- attributed to a VRF as appropriate
-- tagged as appropriate.


## Assumptions/changes made

You may wish to bear these in mind and make some post-migration adjustments.


### Differences in perspectives

Device42 describes the world from the fixed perspective of a single organisation, where each thing can only ever have one role. Syscat, by contrast, takes a broader and explicitly multi-organisation view, in which roles are relative to the relationships between things: an organisation can concurrently be a vendor to this one, and a customer of that one.
