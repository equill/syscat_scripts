#!/usr/bin/env python3

#   Copyright [2017] [James Fleming <james@electronic-quill.net]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Update Syscat with the results of discovering a device.
"""

# Third-party libraries
import netdescribe.snmp.device_discovery
from netdescribe.utils import create_logger
import requests

# Included batteries
import argparse
from collections import namedtuple
import ipaddress
import json
import re
import sys


class IPInterfaceEncoder(json.JSONEncoder):
    """
    Render an ipaddress.IPv4Interface object to a serialisable string.
    Enable rendering interface objects in JSON.
     """
    def default(self, obj):
        if isinstance(obj, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
            return obj.with_prefixlen
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

def dictdefault(key, data, default=None):
    "Returns either the entry from a dict corresponding to the key, or a default value."
    if key in data:
        returnval = data[key]
    else:
        returnval = default
    return returnval

def jsonify(data):
    "Pretty-print a data structure in JSON, for output to logs."
    return json.dumps(data, indent=4, sort_keys=True, cls=IPInterfaceEncoder)

def sanitise_uid(uid):
    "Sanitise a UID string in the same way Restagraph does"
    return re.sub('[/ ]', '_', uid)

SyscatIface = namedtuple('syscatIface', ['snmpindex',
                                         'ifname',
                                         'ifdescr',
                                         'ifalias',
                                         'iftype',
                                         'ifspeed',
                                         'ifhighspeed',
                                         'ifphysaddress'])

def add_device(uid, sysname, sysdescr, base_url, logger):
    """
    Provide a consistent way to add a device to the database.
    uid = UID by which this device is to be created
    sysname = sysName value
    sysdecr = sysDescr value
    Return a boolean to indicate success or failure.
    """
    response = requests.post("%s/raw/v1/devices" % base_url,
                             data={'uid': uid, 'sysName': sysname, 'sysDescr': sysdescr})
    # Success!
    if response.status_code == 201:
        logger.info("Successfully created device %s", uid)
        return True
    # Not success!
    logger.error("Unexpected response from the server: %s %s",
                 response.status_code, response.text)
    return False

def add_interface(host_uid, iface_uid, iface, base_url, logger):
    '''
    Add an interface to a device.
    Arguments:
    - host_uid
    - iface_uid - doesn't assume it's always ifName
    - iface: SyscatIface namedtuple
    - logger
    '''
    ifurl = '%s/raw/v1/devices/%s/Interfaces/networkInterfaces' % (base_url, host_uid)
    details = {'uid': iface_uid,
               'snmpindex': iface.snmpindex,
               'ifname': iface.ifname,
               'ifdescr': iface.ifdescr,
               'ifalias': iface.ifalias,
               'iftype': iface.iftype,
               'ifspeed': iface.ifspeed,
               'ifhighspeed': iface.ifhighspeed,
               'ifphysaddress': iface.ifphysaddress}
    logger.debug('Attempting to add network interface %s to device %s at URL %s with details %s',
                 iface.ifname, host_uid, ifurl, jsonify(details))
    netresponse = requests.post(ifurl, data=details)
    logger.debug('result of interface creation for %s (%s): %s - %s',
                 iface.snmpindex, iface.ifname, netresponse.status_code, netresponse.text)

def delete_interface(host_uid, iface_uid, base_url, logger):
    """
    Remove an interface from a device.
    """
    logger.info('Deleting interface %s:%s', host_uid, iface_uid)
    url = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces/{}'.format(base_url,
                                                                        host_uid,
                                                                        iface_uid)
    response = requests.delete(url, data={'delete-dependent': True, 'recursive': True})
    # Success!
    if response.status_code == 204:
        logger.debug('Successfully deleted interface %s:%s', host_uid, iface_uid)
        return True
    #Not success!
    logger.error('Failed to delete interface %s:%s - %s %s',
                 host_uid, iface_uid, response.status_code, response.text)
    return False

def add_ip_address(host_uid, iface_uid, addr, base_url, logger):
    """
    Provide a consistent way to add an IP address to an interface.
    Return a boolean to indicate success or failure.
    """
    # Version-specific wrangling
    if addr.version == 4:
        ipurl = '{}/devices/{}/Interfaces/networkInterfaces/{}/Addresses/ipv4Addresses'.format(
            base_url, host_uid, iface_uid)
    elif addr.version == 6:
        ipurl = '{}/devices/{}/Interfaces/networkInterfaces/{}/Addresses/ipv6Addresses'.format(
            base_url, host_uid, iface_uid)
    else:
        logger.error('Unknown IP version %s for address %s', addr.version, addr)
    # Now do the work.
    logger.debug('Attempting to create IPv%s Address %s under URL %s',
                 addr.version, addr.with_prefixlen, ipurl)
    addresponse = requests.post(
        ipurl, data={'uid': str(addr.ip),
                     'prefixlength': re.split('\/', addr.with_prefixlen)[1]})
    if addresponse.status_code != 201:
        logger.error('Failed to add address %s to interface: %s %s',
                     addr.with_prefixlen, addresponse.status_code, addresponse.text)
        return False
    return True

def delete_ip_address(host_uid, iface_uid, addr, base_url, logger):
    """
    Remove an IP address from an interface, in a manner consistent with the way we add them.
    """
    logger.debug('Deleting IPv%s address %s from interface %s:%s',
                 addr.version, addr.with_prefixlen, host_uid, iface_uid)
    url = '{}/devices/{}/Interfaces/networkInterfaces/{}/Addresses/ipv4Addresses/{}'.format(
        base_url, host_uid, iface_uid, addr.with_prefixlen)
    response = requests.delete(url, data={'delete-dependent': True})
    if response.status_code == 204:
        logger.info('Removed address %s from interface %s', addr.with_prefixlen, iface_uid)
    else:
        logger.warning('Failed to remove address %s from interface %s: %s %s',
                       addr.with_prefixlen, iface_uid, response.status_code, response.text)

def compare_discovered_device_to_syscat(discovered, syscat, logger):
    '''
    Compare the discovered details with the existing device by the same identifier.
    Return a dict of diffs:
    - attribute
        - discovered = <discovered value>
        - existing = <value already in Syscat>
    '''
    diffs = {}
    for attr in [('sysname', 'sysName'),
                 ('sysdescr', 'sysDescr')]:
        # Make it easier to follow the references, because case-sensitivity
        s_attr = attr[0]  # Syscat name for the attribute
        s_val = syscat[s_attr]
        d_attr = attr[1]    # Netdescribe name for the attribute
        d_val = discovered['sysinfo'][d_attr]
        if d_val != s_val:
            logger.debug('Discovered %s "%s" differs from existing %s "%s"',
                         d_attr, d_val, s_attr, s_val)
            # Ensure there's a 'sysinfo' entry in the accumulators
            if 'sysinfo' not in diffs:
                diffs['sysinfo'] = {}
            # Now prepare the update and the report
            diffs['sysinfo'][s_attr] = {'discovered': d_val,
                                        'existing': s_val}
    return diffs

def discovered_ifaces_to_syscat_format(network, logger):
    '''
    Take the 'network' sub-tree of explore_device(), and return a list of (SyscatIface namedtuple,
    address dict) tuples, that approximates what we'd get if we extracted the equivalent tree from
    Syscat.
    Makes it much simpler to compare both sets.
    '''
    logger.debug('Converting discovered iface data into Syscat format. Input structure is:\n%s',
                 jsonify(network))
    ifaces = {} # Accumulator for the final output
    for index, details in network['interfaces'].items():
        # Decide the UID.
        # There's enough inconsistency among implementations to justify making this a discrete step.
        iface_uid = details['ifName']
        # Enumerate any addresses the interface has
        addrs = {}
        if str(index) in network['ipIfaceAddrMap']: # Not all interfaces have addresses
            for addr in network['ipIfaceAddrMap'][str(index)]:
                if isinstance(addr, ipaddress.IPv4Interface):
                    logger.debug('Adding IPv4 address %s', addr.with_prefixlen)
                    # Ensure there's a subsection of the dict for these
                    if 'ipv4Addresses' not in addrs:
                        addrs['ipv4Addresses'] = []
                    addrs['ipv4Addresses'].append(addr)
                if isinstance(addr, ipaddress.IPv6Interface):
                    logger.debug('Adding IPv6 address %s', addr.with_prefixlen)
                    # Ensure there's a subsection of the dict for these
                    if 'ipv6Addresses' not in addrs:
                        addrs['ipv6Addresses'] = []
                    addrs['ipv6Addresses'].append(addr)
                else:
                    logger.warn('Purported address %s of type %s found', addr, type(addr))
        # Construct the SyscatIface namedtuple to append to the list.
        ifaces[iface_uid] = ((SyscatIface(snmpindex=index,
                                          ifname=details['ifName'],
                                          ifdescr=details['ifDescr'],
                                          ifalias=details['ifAlias'],
                                          iftype=details['ifType'],
                                          ifspeed=details['ifSpeed'],
                                          ifhighspeed=details['ifHighSpeed'],
                                          ifphysaddress=details['ifPhysAddress']),
                              addrs))
    # Return the list
    logger.debug('Output structure of iface data:\n%s', jsonify(ifaces))
    return ifaces

def get_addresses_for_iface(host_uid, iface_uid, syscat_url, logger):
    '''
    Retrieve a list of addresses for an interface.
    Return them in a dict:
    - ipv4Addresses
        - list of IPv4Interface objects
    - ipv6Addresses
        - list of IPv6Interface objects
    '''
    returnval = {}  # Accumulator for the result
    # IPv4 addresses
    # Extract the list of addresses for this interface
    logger.debug('Retrieving IPv4 addresses for interface %s:%s', host_uid, iface_uid)
    addresponse = requests.get(
        '%s/devices/%s/Interfaces/networkInterfaces/%s/Addresses/ipv4Addresses' % (
            syscat_url, host_uid, iface_uid))
    # If we got a sensible response, assemble the list
    if addresponse.status_code == 200:
        logger.debug('IPv4 addresses retrieved from Syscat for interface %s:\n%s',
                     iface_uid, jsonify(addresponse.json()))
        for addr in addresponse.json():
            # Sanity-check: is this thing even valid?
            if 'uid' not in addr:
                logger.error('Interface lacks a UID. Somebody bypassed the API: %s', addr)
            # Both UID and prefixlength -> create and add an entry for it
            elif 'uid' in addr and 'prefixlength' in addr:
                # Ensure there's an IPv4 entry in the dict
                if 'ipv4Addresses' not in returnval:
                    returnval['ipv4Addresses'] = []
                # Now create and add this entry
                logger.debug('Adding IP address %s/%s', addr['uid'], addr['prefixlength'])
                returnval['ipv4Addresses'].append(
                    ipaddress.IPv4Interface('%s/%s' % (addr['uid'], addr['prefixlength'])))
            # Both UID and netmask -> create and add an entry for it
            elif 'uid' in addr and 'netmask' in addr:
                # Ensure there's an IPv4 entry in the dict
                if 'ipv4Addresses' not in returnval:
                    returnval['ipv4Addresses'] = []
                # Now create and add this entry
                logger.debug('Adding IP address %s/%s', addr['uid'], addr['netmask'])
                returnval['ipv4Addresses'].append(
                    ipaddress.IPv4Interface('%s/%s' % (addr['uid'], addr['netmask'])))
            else:
                logger.error('Address had a UID, but neither a prefixlength nor a netmask: %s',
                             addr)
    # No addresses for this interface; just return an empty dict
    elif addresponse.status_code == 404:
        logger.debug('No addresses found for %s:%s', host_uid, iface_uid)
    # Unexpected response code; fail noisily
    else:
        logger.error('Unexpected response while querying addresses for interface %s:%s - %s %s',
                     host_uid, iface_uid, addresponse.status_code, addresponse.text)
        sys.exit(1)
    #
    # IPv6 addresses
    # Extract the list of addresses for this interface
    logger.debug('Retrieving IPv6 addresses for interface %s:%s', host_uid, iface_uid)
    addresponse = requests.get(
        '%s/devices/%s/Interfaces/networkInterfaces/%s/Addresses/ipv6Addresses' % (
            syscat_url, host_uid, iface_uid))
    # If we got a sensible response, assemble the list
    if addresponse.status_code == 200:
        logger.debug('IPv6 addresses retrieved from Syscat for interface %s:\n%s',
                     iface_uid, jsonify(addresponse.json()))
        for addr in addresponse.json():
            # Sanity-check: is this thing even valid?
            if 'uid' not in addr:
                logger.error('Interface lacks a UID. Somebody bypassed the API: %s', addr)
            # Both UID and prefixlength -> create and add an entry for it
            elif 'uid' in addr and 'prefixlength' in addr:
                # Ensure there's an IPv6 entry in the dict
                if 'ipv6Addresses' not in returnval:
                    returnval['ipv6Addresses'] = []
                # Now create and add this entry
                logger.debug('Adding IP address %s/%s', addr['uid'], addr['prefixlength'])
                returnval['ipv6Addresses'].append(
                    ipaddress.IPv6Interface('%s/%s' % (addr['uid'], addr['prefixlength'])))
            else:
                logger.error('Address had a UID, but no prefixlength: %s', addr)
    # No addresses for this interface; just return an empty dict
    elif addresponse.status_code == 404:
        logger.debug('No addresses found for %s:%s', host_uid, iface_uid)
    # Unexpected response code; fail noisily
    else:
        logger.error('Unexpected response while querying addresses for interface %s:%s - %s %s',
                     host_uid, iface_uid, addresponse.status_code, addresponse.text)
        sys.exit(1)
    #
    # Return what we found
    logger.debug('Full Syscat address list for %s:%s\n%s', host_uid, iface_uid, jsonify(returnval))
    return returnval

def get_iface_list_from_syscat(host_uid, syscat_url, logger):
    '''
    Retrieve a list of interfaces on a device, as currently seen by Syscat.
    Return a dict, where the keys are the interface UIDs, and their values are (SyscatIface
    namedtuple, address dict) tuples, to match the output of discovered_ifaces_to_syscat_format.
    '''
    logger.debug('Retrieving list of interfaces for %s from Syscat.', host_uid)
    # Get the list of interfaces for this device
    response = requests.get('%s/devices/%s/Interfaces/networkInterfaces' % (syscat_url, host_uid))
    # If it has none, bail out now.
    if response.status_code == 404:
        logger.debug('No interfaces found for %s', host_uid)
        return None
    # If something else went wrong, fail noisily.
    elif response.status_code != 200:
        logger.error('Failed to retrieve list: %s %s', response.status_code, response.text)
        sys.exit(1)
    # If we got this far, presumably we have a list
    logger.debug('Raw iface data retrieved from Syscat:\n%s', jsonify(response.json()))
    ifacelist = {}
    # For each interface, get its list of addresses, then assemble the lot in output format
    for iface in response.json():
        # Assemble the namedtuple and append it to the accumulator
        ifacelist[iface['uid']] = (
            SyscatIface(snmpindex=dictdefault('snmpindex', iface),
                        ifname=dictdefault('ifname', iface),
                        ifdescr=dictdefault('ifdescr', iface),
                        ifalias=dictdefault('ifalias', iface),
                        iftype=dictdefault('iftype', iface),
                        ifspeed=dictdefault('ifspeed', iface),
                        ifhighspeed=dictdefault('ifhighspeed', iface),
                        ifphysaddress=dictdefault('ifphysaddress', iface)),
            get_addresses_for_iface(host_uid, iface['uid'], syscat_url, logger))
    logger.debug('Processed iface data from Syscat:\n%s', jsonify(ifacelist))
    return ifacelist

def compare_ifaces(uid, discovered, syscat, logger):
    '''
    Compare two SyscatIface instances.
    Return a dict describing the differences between the two.
    '''
    logger.debug('Comparing discovered and existing instances of interface %s', uid)
    diff = {}
    for field in SyscatIface._fields:
        if getattr(discovered, field) != getattr(syscat, field):
            diff[field] = {'discovered': getattr(discovered, field),
                           'existing': getattr(syscat, field)}
    return diff

def compare_addr_lists(iface, discovered, existing, logger):
    '''
    Compare the address-lists for two interfaces.
    - iface = UID for the interface in question. Used only for logging.
    - discovered, existing = the address section for a single address from
        discovered_ifaces_to_syscat_format
    - logger = logging object.
    Return the relevant subset of
    - diffs
        - discovered
        - existing
    - discovered-only
    - syscat-only
    '''
    logger.debug('On iface %s, comparing discovered addresses %s and existing addresses %s',
                 iface, jsonify(discovered), jsonify(existing))
    # Are they already OK?
    if discovered == existing:
        logger.debug('Addresses for interface %s match; no action required.', iface)
        return None
    # Some mismatch found
    logger.debug('Addresses for interface %s don´t match; do something here.', iface)
    diffs = {}
    # IPv4 addresses
    # Addresses discovered but not in Syscat
    if 'ipv4Addresses' in discovered:
        # If there are some in both, compare them to find the exact differences
        if 'ipv4Addresses' in existing:
            # Start with the discovered ones
            for disc_addr in discovered['ipv4Addresses']:
                logger.debug('Checking discovered %s "%s against existing IPv4 addresses"',
                             type(disc_addr), disc_addr)
                match = False   # Flag to indicate whether we've found one
                for exist in existing['ipv4Addresses']:
                    logger.debug('Checking it against %s "%s"', type(exist), exist)
                    # Exact match - nothing to do
                    if disc_addr.with_prefixlen == exist.with_prefixlen:
                        logger.debug('Exact match for IPv4 address %s', disc_addr)
                        match = True
                        break   # Stop checking the existing addresses now
                    # Address matches, but prefix-length does not;
                    # add them to the list of differing addresses.
                    elif disc_addr.ip == exist.ip:
                        logger.debug('Prefix-length differs between discovered %s and existing %s',
                                     disc_addr, existing)
                        # Ensure the dict has the necessary entries
                        if 'ipv4Addresses' not in diffs:
                            diffs['ipv4Addresses'] = {}
                        if 'diffs' not in diffs['ipv4Addresses']:
                            diffs['ipv4Addresses']['diffs'] = []
                        # Add the entry
                        diffs['ipv4Addresses']['diffs'].append({'discovered': disc_addr,
                                                                'existing': exist})
                        match = True
                        break   # Stop checking the existing addresses now
                # We've checked this discovered address against all the existing ones.
                # Is it a new one?
                if match is False:
                    logger.debug('Discovered address %s is not already present', disc_addr)
                    # Ensure there's an entry in the dict
                    if 'discovered-only' not in diffs:
                        diffs['discovered-only'] = []
                    # Add the entry
                    diffs['discovered-only'].append(disc_addr)
            # Now check for existing ones with no match against discovered ones.
            for exist_addr in existing['ipv4Addresses']:
                logger.debug('Checking existing %s %s against discovered IPv4 addresses',
                             type(exist_addr), exist_addr)
                match = False   # Flag to indicate whether we've found one
                for disc in discovered['ipv4Addresses']:
                    if exist_addr.ip == disc.ip:
                        match = True
                        break   # Don't bother checking the rest
                # Did we find a match?
                if match is False:
                    logger.debug('Existing %s "%s" was not discovered; adding it to the existing-only list.',
                                 type(exist_addr), exist_addr.with_prefixlen)
                    # Ensure there's an entry in the dict
                    if 'ipv4Addresses' not in diffs:
                        diffs['ipv4Addresses'] = {}
                    if 'syscat-only' not in diffs['ipv4Addresses']:
                        diffs['ipv4Addresses']['syscat-only'] = []
                    # Add it
                    diffs['ipv4Addresses']['syscat-only'].append(exist_addr)
        # If there aren't any in Syscat, don't bother with a comparison; just add the whole thing.
        else:
            logger.debug('IPv4 addresses discovered, but none existing. Adding them all:\n%s',
                         jsonify(discovered['ipv4Addresses']))
            diffs['ipv4Addresses'] = {'discovered-only': discovered['ipv4Addresses']}
    # IPv4 addresses exist already, but none were discovered:
    elif 'ipv4Addresses' in existing:
        logger.debug('Ipv4 addresses existing, but none discovered: Recording them all:\n%s',
                     jsonify(existing['ipv4Addresses']))
        diffs['ipv4Addresses']['syscat-only'] = existing
    # Return the result of the comparison
    logger.debug('compare_addr_lists returning diff-list for %s:\n%s', iface, jsonify(diffs))
    return diffs

def compare_iface_lists(discovered, syscat, logger):
    '''
    Compare the list of interfaces discovered by Netdescribe with that retrieved from Syscat.
    Return a dict of changes to apply, in order to bring Syscat in line with reality:
    - diffs
        - interface name
            - interface
                - <attribute to change>
                    - 'discovered': <discovered value>
                    - 'existing': <existing value>
            - addresses
                - ipv4Addresses
                    - <attribute to change>
                        - 'discovered': <discovered value>
                        - 'existing': <existing value>
                - ipv6Addresses
                    - <attribute to change>
                        - 'discovered': <discovered value>
                        - 'existing': <existing value>
    - discovered-only
        - [list of (SyscatIface, [<list of ipaddress.IPvNInterface objects>]) tuples]
    - syscat-only
        - [<list of interface names>]
    '''
    logger.debug('Comparing interface lists: discovered vs syscat.')
    diffs = {'discovered-only': [],
             'syscat-only': [],
             'diffs': {}}
    # Take each discovered interface, and look for its equivalent from Syscat
    for disc_key in discovered.keys():
        # Is there an existing one with a matching UID?
        if disc_key in syscat:
            # If there's a perfect match, move on to the next one.
            if discovered[disc_key] == syscat[disc_key]:
                logger.debug('Interface %s matches completely; no action required', disc_key)
                continue
            #
            # Interfaces
            # Ensure there's an entry in the diffs dict
            if disc_key not in diffs['diffs']:
                diffs['diffs'][disc_key] = {}
            # If there's an exact match, no action is required at this point.
            # The difference will be in the addresses.
            if discovered[disc_key][0] == syscat[disc_key][0]:
                logger.debug('Interface %s matches; no action required', disc_key)
            # If it's not an exact match, add the diffs to the accumulator
            else:
                logger.debug('Interface {} differs; calculating diffs between {} and {}'.format(
                    disc_key, jsonify(discovered[disc_key]), jsonify(syscat[disc_key])))
                # Now add the diffs
                diffs['diffs'][disc_key]['interface'] = compare_ifaces(
                    disc_key, discovered[disc_key][0], syscat[disc_key][0], logger)
            #
            # Addresses
            addr_diffs = compare_addr_lists(disc_key,
                                            discovered[disc_key][1],
                                            syscat[disc_key][1],
                                            logger)
            if addr_diffs:
                diffs['diffs'][disc_key]['addresses'] = addr_diffs
        # If not, we've discovered a new one
        else:
            logger.debug('Discovered interface %s is absent from Syscat', disc_key)
            diffs['discovered-only'].append(discovered[disc_key])
    # Now take each interface from Syscat, and check whether it's missing from discovery
    for sysc_key in syscat.keys():
        if sysc_key not in discovered:
            logger.debug('Syscat interface %s was not discovered', sysc_key)
            diffs['syscat-only'].append(sysc_key)
    return diffs

def populate_interfaces_flat_v1(host_uid, network, syscat_url, logger, newdevice=False):
    '''
    Add interface details to a device.
    Just attach each interface directly to the device, without making any attempt
    to distinguish between subinterfaces and parents.
    Assumes v1 of the Syscat API.
    Arguments:
    - host_uid: the name by which we're calling this device in Syscat
    - network: the contents of the 'network' sub-tree returned by Netdescribe
    - syscat_url: the base URL for the Syscat server
    - logger: a logging object
    - newdevice: are we adding interfaces to a newly-created device, or updating an existing one?
    '''
    logger.debug('Populating interfaces for device %s', host_uid)
    # Convert the discovered data into a Syscat-friendly layout
    discovered = discovered_ifaces_to_syscat_format(network, logger)
    # Set common variables ahead of time
    uri = '%s/raw/v1' % syscat_url
    ifurl = '%s/devices/%s/Interfaces/networkInterfaces' % (uri, host_uid)
    # New device: just go ahead and add the details
    if newdevice:
        for iface_uid, ifacetuple in discovered.items():
            add_interface(host_uid, iface_uid, ifacetuple[0], syscat_url, logger)
            # Add IPv4 addresses
            if ifacetuple[1] and 'ipv4Addresses' in ifacetuple[1]:
                for addr in ifacetuple[1]['ipv4Addresses']:
                    add_ip_address(host_uid, iface_uid, addr, uri, logger)
            # Add IPv6 addresses
            if ifacetuple[1] and 'ipv6Addresses' in ifacetuple[1]:
                for addr in ifacetuple[1]['ipv6Addresses']:
                    add_ip_address(host_uid, iface_uid, addr, uri, logger)
            else:
                logger.debug('No addresses found for interface with index number %s; moving on.',
                             str(ifacetuple[0].snmpindex))
    # Existing device: compare what's already there with what we have
    else:
        existing = get_iface_list_from_syscat(host_uid, uri, logger)
        logger.debug('Existing interfaces in Syscat:\n%s', jsonify(existing))
        if existing:
            # A more nuanced report is warranted here.
            diffs = compare_iface_lists(discovered, existing, logger)
            # No differences found; nothing to do
            if (not diffs['discovered-only']) and (not diffs['syscat-only']) and (
                    not diffs['diffs']):
                logger.info('Discovered ifaces match existing ones; no change required')
            # Differences found
            else:
                logger.debug('Differences identified between discovered and existing:\n%s',
                             jsonify(diffs))
                # Interfaces we already discovered, that have changed since last time
                if diffs['diffs']:
                    logger.warn('Discovered and existing ifaces differ:\n%s', jsonify(diffs))
                    for iface, details in diffs['diffs'].items():
                        # Extract and apply the diffs for each interface
                        #
                        # The interface itself
                        if 'interface' in details:
                            diff = {}
                            for attr, vals in details['interface'].items():
                                diff[attr] = vals['discovered']
                            logger.info('Applying the following diff to %s:%s\n%s',
                                        host_uid, iface, jsonify(diff))
                            iu_response = requests.put('%s/%s' % (ifurl, iface), data=diff)
                            if iu_response.status_code == 201:
                                logger.info('Update successful')
                            else:
                                logger.warning('Update unsuccessful: %s %s',
                                               iu_response.status_code, iu_response.text)
                        # Addresses on the interface
                        if 'addresses' in details:
                            if 'ipv4Addresses' in details['addresses']:
                                # Add newly-discoovered interfaces
                                if 'discovered-only' in details['addresses']['ipv4Addresses']:
                                    for addr in details['addresses']['ipv4Addresses']['discovered-only']:
                                        logger.info('Attempting to add newly-discovered address %s to interface %s',
                                                    addr.with_prefixlen, iface)
                                        add_ip_address(host_uid, iface, addr, uri, logger)
                                # Remove addresses that have gone away
                                if 'syscat-only' in details['addresses']['ipv4Addresses']:
                                    for addr in details['addresses']['ipv4Addresses']['syscat-only']:
                                        delete_ip_address(host_uid, iface, addr, syscat_url, logger)
                # Newly-discovered interfaces
                if diffs['discovered-only']:
                    for iface in diffs['discovered-only']:
                        iface_uid = iface[0].ifname    # Same assumption as above
                        logger.info('Adding interface %s:%s that has been newly discovered.',
                                    host_uid, iface_uid)
                        add_interface(host_uid, iface_uid, iface[0], syscat_url, logger)
                # Interfaces that have gone away
                if diffs['syscat-only']:
                    for iface in diffs['syscat-only']:
                        logger.info('Removing interface %s:%s because it doesn´t exist on the device.',
                                    host_uid, iface)
                        delete_interface(host_uid, iface, syscat_url, logger)
        else:
            logger.debug('Syscat has no network interfaces recorded for this device.')
            if discovered:
                for iface in discovered:
                    logger.info('Adding interface %s to %s', iface, host_uid)
                    add_interface(host_uid, iface, syscat_url, logger)
            else:
                logger.debug('No interfaces found on %s; how did we even query it?', host_uid)

def discover_into_syscat_v1(address,        # IP address, FQDN or otherwise resolvable address
                            name=None,      # Name of target device, to override the discovered one
                            use_sysname=False,  # Use the discovered sysName as the Syscat UID
                            snmpcommunity="public",
                            syscat_url="http://localhost:4950", # Default base URL for Syscat
                            loglevel="info" # Default loglevel
                           ):
    """
    Ensure that there's an entry in Syscat for the device we just discovered.
    Update existing instances, and return a dict describing any updates.
    Return True if the result was a new entry; otherwise, return a dict describing the updates.
    Assumes version 1 of the Syscat API.
    Structure of the return value:
    - sysinfo
        - <attribute-name>
            - existing: <value currently in Syscat>
            - discovered: <value discovered just now>
    """
    # Create the logger
    logger = create_logger(loglevel=loglevel)
    logger.info("Performing discovery on device at %s", address)
    # Perform discovery
    device = netdescribe.snmp.device_discovery.explore_device(address, logger, snmpcommunity)
    logger.debug("Result of discovery was:\n%s", jsonify(device))
    # Resolve the device's UID
    if name:
        uid = name
    elif use_sysname and device['sysinfo']['sysName'] and device['sysinfo']['sysName'] != "":
        uid = device['sysinfo']['sysName']
    else:
        uid = address
    logger.debug("Using name '%s' for device", uid)
    # Is it already there?
    existing_response = requests.get("%s/raw/v1/devices/%s" % (syscat_url, uid))
    # No existing entry; create one
    if existing_response.status_code == 404:
        logger.debug("%s is not present in Syscat; creating it.", uid)
        # Create the device entry itself
        add_device(uid,
                   device['sysinfo']['sysName'],
                   device['sysinfo']['sysDescr'],
                   syscat_url,
                   logger)
        created_new_device = True
    # We already have one of these; log the fact and ensure it's up to date
    elif existing_response.status_code == 200:
        logger.debug("%s is already present in Syscat. Ensuring it's up to date...", uid)
        created_new_device = False
        # Compare the sysinfo attributes
        diffs = compare_discovered_device_to_syscat(device, existing_response.json(), logger)
        # Perform any necessary updates to the device's own attributes
        if diffs and 'sysinfo' in diffs:
            devices_url = "%s/raw/v1/devices" % syscat_url
            payload = {}
            for attr, vals in diffs['sysinfo'].items():
                payload[attr] = vals['discovered']
            logger.info('Updating sysinfo for %s with details %s', uid, payload)
            requests.put('%s/%s' % (devices_url, uid), data=payload)
        # No updates needed. Do mention this, so the user knows where we're up to
        else:
            logger.debug('No sysinfo updates needed.')
    # Something else happened.
    else:
        logger.critical("Syscat returned an unexpected result: %s %s",
                        existing_response.status_code, existing_response.text)
        sys.exit(1)
    # Now ensure its interfaces are correctly described
    populate_interfaces_flat_v1(uid,
                                device['network'],
                                syscat_url,
                                logger,
                                newdevice=created_new_device)
    # Return a report on what we updated.
    if created_new_device:
        return True
    return diffs


def process_cli():
    """
    Handle CLI invocation.
    """
    # Get the command-line arguments
    parser = argparse.ArgumentParser(description='Perform SNMP discovery on a host, \
    returning its data in a single structure.')
    parser.add_argument('address',
                        type=str,
                        help='The hostname or address to perform discovery on')
    parser.add_argument('--syscat_url',
                        type=str,
                        default='http://localhost:4950',
                        help='The base URL for Syscat, e.g. http://localhost:4950')
    parser.add_argument('--name',
                        type=str,
                        action='store',
                        default=None,
                        help='The name (UID) that this device should have in Syscat')
    parser.add_argument('--use_sysname',
                        action='store_true',
                        default=False,
                        help='Whether to use the SNMP-discovered sysName instead of ´address´.')
    parser.add_argument('--community',
                        type=str,
                        action='store',
                        dest='community',
                        default='public',
                        help='SNMP v2 community string')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    # Set debug logging, if requested
    if args.debug:
        loglevel = "debug"
    else:
        loglevel = "info"
    # Now discover stuff
    discover_into_syscat_v1(args.address,
                            name=args.name,
                            use_sysname=args.use_sysname,
                            snmpcommunity=args.community,
                            loglevel=loglevel)

if __name__ == "__main__":
    process_cli()
