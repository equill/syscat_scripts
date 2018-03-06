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
import collections
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
        # Handle instances of IPv4Interface and IPv6Interface
        if isinstance(obj, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
            return obj.with_prefixlen
        # Fall back to the base class's default behaviour for anything else
        return json.JSONEncoder.default(self, obj)

def jsonify(data):
    "Pretty-print a data structure in JSON, for output to logs."
    return json.dumps(data, indent=4, sort_keys=True, cls=IPInterfaceEncoder)

def dictdefault(key, data, default=None):
    "Returns either the entry from a dict corresponding to the key, or a default value."
    if key in data:
        returnval = data[key]
    else:
        returnval = default
    return returnval

def sanitise_uid(uid):
    "Sanitise a UID string in the same way Restagraph does"
    return re.sub('[/ ]', '_', uid)

SyscatIface = collections.namedtuple('syscatIface', ['snmpindex',
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

def add_interface_with_ip_addrs(host_uid, iface_uid, ifacetuple, base_url, logger):
    '''
    Add an interface and all its IP addresses in a single function call.
    ifacetuple expects a tuple of
    - SyscatIface namedtuple, to feed to add_interface
    - dict
        - ipv4Addresses = list of ipaddress.IPv4Interface objects
        - ipv6Addresses = list of ipaddress.IPv6Interface objects
    '''
    # Add the interface
    add_interface(host_uid, iface_uid, ifacetuple[0], base_url, logger)
    # Now add any addresses we found on it
    if ifacetuple[1]:
        for addr in ifacetuple[1]:
            add_ip_address(host_uid, iface_uid, addr, base_url, logger)

def add_interface(host_uid, iface_uid, iface, base_url, logger):
    '''
    Add an interface to a device.
    Arguments:
    - host_uid
    - iface_uid - doesn't assume it's always ifName
    - iface: SyscatIface namedtuple
    - logger
    '''
    ifurl = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces'.format(base_url, host_uid)
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
    ipurl = '{url}/raw/v1/devices/{host}/Interfaces/networkInterfaces/{iface}/Addresses/ipv{version}Addresses'.format(
        url=base_url, host=host_uid, iface=iface_uid, version=addr.version)
    # Now do the work.
    logger.debug('Attempting to create IPv%s Address %s under URL %s as %s',
                 addr.version, addr.with_prefixlen, ipurl, addr.ip)
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
    url = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces/{}/Addresses/ipv4Addresses/{}'.format(
        base_url, host_uid, iface_uid, addr.ip)
    logger.debug('Using URL %s', url)
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
    # Lookup table for matching the attribute names between Syscat and SNMP discovery:
    # - first entry in each pair is the Syscat name for it
    # - second entry is the SNMP attribute name
    for attr in [('sysname', 'sysName'),
                 ('sysdescr', 'sysDescr')]:
        # Make it easier to follow the references, because case-sensitivity
        s_attr = attr[0]    # Syscat name for the attribute
        d_attr = attr[1]    # Netdescribe name for the attribute
        # Try to retrieve the value from Syscat, but default to None
        if s_attr in syscat:
            s_val = syscat[s_attr]
        else:
            s_val = None
        # Get the discovered value
        d_val = discovered['system'][d_attr]
        # Compare them and act on the result
        if d_val != s_val:
            logger.debug('Discovered %s "%s" differs from existing %s "%s"',
                         d_attr, d_val, s_attr, s_val)
            # Ensure there's a 'system' entry in the accumulators
            if 'system' not in diffs:
                diffs['system'] = {}
            # Now prepare the update and the report
            diffs['system'][s_attr] = {'discovered': d_val,
                                       'existing': s_val}
    return diffs

def discovered_ifaces_to_syscat_format(interfaces, logger):
    '''
    Take the 'interfaces' sub-tree of explore_device(), and return a dict of key = uid, value = 
    (SyscatIface namedtuple, address dict) tuple, that approximates what we'd get if we extracted
    the equivalent tree from Syscat.
    Makes it much simpler to compare both sets.
    Note that this function pre-sanitises the interface UID, to correctly search for an existing
    record of that interface in Syscat.
    '''
    logger.debug('Converting discovered iface data into Syscat format. Input structure is:\n%s',
                 jsonify(interfaces))
    ifaces = {} # Accumulator for the final output
    for index, details in interfaces.items():
        logger.debug('Processing interface with ifTable index %s', index)
        # Decide the UID.
        # There's enough inconsistency among implementations to justify making this a discrete step.
        iface_uid = details['ifName']
        logger.debug('Interface UID selected: %s', iface_uid)
        # Enumerate any addresses the interface has
        addrs = []
        for addr in details['addresses']:
            logger.info('Adding address %s', addr)
            if addr['protocol'] == 'ipv4':
                logger.debug('Adding IPv4 address %s/%s', addr['address'], addr['prefixLength'])
                addrs.append(ipaddress.IPv4Interface('{}/{}'.format(addr['address'],
                                                                    addr['prefixLength'])))
            elif addr['protocol'] == 'ipv6':
                logger.debug('Adding IPv6 address %s/%s', addr['address'], addr['prefixLength'])
                addrs.append(ipaddress.IPv6Interface('{}/{}'.format(addr['address'],
                                                                    addr['prefixLength'])))
            else:
                logger.warn('Purported address %s of type %s found',
                            addr['address'], addr['protocol'])
        # Construct the SyscatIface namedtuple to append to the list.
        ifaces[sanitise_uid(iface_uid)] = (SyscatIface(snmpindex=index,
                                                       ifname=details['ifName'],
                                                       ifdescr=details['ifDescr'],
                                                       ifalias=details['ifAlias'],
                                                       iftype=details['ifType'],
                                                       ifspeed=details['ifSpeed'],
                                                       ifhighspeed=details['ifHighSpeed'],
                                                       ifphysaddress=details['ifPhysAddress']),
                                           addrs)
    # Return the list
    logger.debug('Output structure of iface data:\n%s', jsonify(ifaces))
    return ifaces

def get_addresses_for_iface(host_uid, iface_uid, syscat_url, logger):
    '''
    Retrieve a list of addresses for an interface.
    Return them as a list of IPv4Interface and IPv6Interface objects.
    '''
    returnval = []  # Accumulator for the result
    # IPv4 addresses
    # Extract the list of addresses for this interface
    logger.debug('Retrieving IPv4 addresses for interface %s:%s', host_uid, iface_uid)
    url = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces/{}/Addresses/ipv4Addresses'.format(
        syscat_url, host_uid, iface_uid)
    logger.debug('Using URL %s', url)
    addresponse = requests.get(url)
    # If we got a sensible response, assemble the list
    if addresponse.status_code == 200:
        logger.debug('IPv4 addresses retrieved from Syscat for interface %s:\n%s',
                     iface_uid, jsonify(addresponse.json()))
        for addr in addresponse.json():
            # Sanity-check: is this thing even valid?
            if 'uid' not in addr:
                logger.warnng('Interface lacks a UID. Somebody bypassed the API: %s', addr)
                continue
            # Both UID and prefixlength -> create and add an entry for it
            elif 'uid' in addr and 'prefixlength' in addr:
                # Now create and add this entry
                logger.debug('Adding IP address %s/%s', addr['uid'], addr['prefixlength'])
                returnval.append(
                    ipaddress.IPv4Interface('%s/%s' % (addr['uid'], addr['prefixlength'])))
            # Both UID and netmask -> create and add an entry for it
            elif 'uid' in addr and 'netmask' in addr:
                # Now create and add this entry
                logger.debug('Adding IP address %s/%s', addr['uid'], addr['netmask'])
                returnval.append(
                    ipaddress.IPv4Interface('%s/%s' % (addr['uid'], addr['netmask'])))
            else:
                logger.error('Address had a UID, but neither a prefixlength nor a netmask: %s',
                             addr)
    # No IPv4 addresses for this interface: log this fact and carry on
    elif addresponse.status_code == 404:
        logger.debug('No IPv4 addresses found for %s:%s', host_uid, iface_uid)
    # Unexpected response code; fail noisily
    else:
        logger.error('Unexpected response while querying IPv4 addresses for %s:%s - %s %s',
                     host_uid, iface_uid, addresponse.status_code, addresponse.text)
        return False
    #
    # IPv6 addresses
    # Extract the list of addresses for this interface
    logger.debug('Retrieving IPv6 addresses for interface %s:%s', host_uid, iface_uid)
    url = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces/{}/Addresses/ipv6Addresses'.format(
        syscat_url, host_uid, iface_uid)
    logger.debug('Using URL %s', url)
    addresponse = requests.get(url)
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
                # Now create and add this entry
                logger.debug('Adding IP address %s/%s', addr['uid'], addr['prefixlength'])
                returnval.append(
                    ipaddress.IPv6Interface('%s/%s' % (addr['uid'], addr['prefixlength'])))
            else:
                logger.error('Address had a UID, but no prefixlength: %s', addr)
    # No IPv6 addresses for this interface; log the fact
    elif addresponse.status_code == 404:
        logger.debug('No IPv6 addresses found for %s:%s', host_uid, iface_uid)
    # Unexpected response code; fail noisily
    else:
        logger.error('Unexpected response while querying IPv6 addresses for %s:%s - %s %s',
                     host_uid, iface_uid, addresponse.status_code, addresponse.text)
        return False
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
    # Create the result accumulator now
    ifacedict = {}
    # Get the list of interfaces for this device
    uri = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces'.format(syscat_url, host_uid)
    logger.debug('Using URI %s', uri)
    response = requests.get(uri)
    # If it has none, bail out now.
    if response.status_code == 404:
        logger.debug('No interfaces found for %s', host_uid)
        return ifacedict
    # If something else went wrong, fail noisily.
    elif response.status_code != 200:
        logger.error('Failed to retrieve interface list from %s: %s %s',
                     host_uid, response.status_code, response.text)
        sys.exit(1)
    # If we got this far, presumably we have a list
    logger.debug('Raw iface data retrieved from Syscat:\n%s', jsonify(response.json()))
    # For each interface, get its list of addresses, then assemble the lot in output format
    for iface in response.json():
        # Assemble the namedtuple and append it to the accumulator
        ifacedict[iface['uid']] = (
            SyscatIface(snmpindex=iface['snmpindex'],
                        ifname=iface['ifname'],
                        ifdescr=dictdefault('ifdescr', iface, default=""),
                        ifalias=dictdefault('ifalias', iface, default=""),
                        iftype=dictdefault('iftype', iface, default=""),
                        ifspeed=dictdefault('ifspeed', iface, default=""),
                        ifhighspeed=dictdefault('ifhighspeed', iface, default=""),
                        ifphysaddress=dictdefault('ifphysaddress', iface, default="")),
            get_addresses_for_iface(host_uid, iface['uid'], syscat_url, logger))
    logger.debug('Processed iface data from Syscat:\n%s', jsonify(ifacedict))
    return ifacedict

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
    logger.debug('Addresses for interface %s don´t match; calculating the diffs.', iface)
    diffs = {}
    # IP addresses
    # Addresses discovered but not in Syscat
    # Start with the discovered ones
    for disc_addr in discovered:
        logger.debug('Checking discovered %s "%s against existing IPv4 addresses"',
                     type(disc_addr), disc_addr)
        match = False   # Flag to indicate whether we've found one
        for exist in existing:
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
                    diffs = {}
                if 'diffs' not in diffs:
                    diffs['diffs'] = []
                # Add the entry
                diffs['diffs'].append({'discovered': disc_addr,
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
    for exist_addr in existing:
        logger.debug('Checking existing %s %s against discovered IPv4 addresses',
                     type(exist_addr), exist_addr)
        match = False   # Flag to indicate whether we've found one
        for disc in discovered:
            if exist_addr.ip == disc.ip:
                match = True
                break   # Don't bother checking the rest
        # Did we find a match?
        if match is False:
            logger.debug('Adding %s "%s" to the existing-only list.',
                         type(exist_addr), exist_addr.with_prefixlen)
            # Ensure there's an entry in the dict
            if 'ipv4Addresses' not in diffs:
                diffs = {}
            if 'syscat-only' not in diffs:
                diffs['syscat-only'] = []
            # Add it
            diffs['syscat-only'].append(exist_addr)
    # Return the result of the comparison
    logger.debug('compare_addr_lists returning diff-list for %s:\n%s', iface, jsonify(diffs))
    return diffs

def compare_iface_lists(discovered, syscat, logger):
    '''
    Compare the list of interfaces discovered by Netdescribe with that retrieved from Syscat.
    Expects two dicts of uid = tuple(SyscatIface, [ipaddresses.ipinterface])
    Return a dict of changes to apply, in order to bring Syscat in line with reality:
    - diffs
        - interface name
            - interface
                - <attribute to change>
                    - 'discovered': <discovered value>
                    - 'existing': <existing value>
            - addresses
                - Addresses
                    - <attribute to change>
                        - 'discovered': <discovered value>
                        - 'existing': <existing value>
    - discovered-only
        - [list of (SyscatIface, [<list of ipaddress.IPvNInterface objects>]) tuples]
    - syscat-only
        - [<list of interface names>]
    '''
    logger.debug('Comparing interface lists: discovered vs syscat.')
    logger.debug('Discovered interfaces:\n%s', jsonify(discovered))
    logger.debug('Syscat interfaces:\n%s', jsonify(syscat))
    diffs = {'discovered-only': [],
             'syscat-only': [],
             'diffs': collections.defaultdict(dict)}
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
            logger.debug('Exploring diffs between version of interface %s', disc_key)
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
            logger.debug('Adding its details to the discovered-only section:\n%s',
                         jsonify(discovered[disc_key]))
            diffs['discovered-only'].append(discovered[disc_key])
    # Now take each interface from Syscat, and check whether it's missing from discovery
    for sysc_key in syscat.keys():
        if sysc_key not in discovered:
            logger.debug('Syscat interface %s was not discovered', sysc_key)
            diffs['syscat-only'].append(sysc_key)
    return diffs

def populate_interfaces_flat(host_uid, interfaces, syscat_url, logger, newdevice=False):
    '''
    Add interface details to a device.
    Just attach each interface directly to the device, without making any attempt
    to distinguish between subinterfaces and parents - hence "flat".
    Assumes v1 of the Syscat API, hence the _v1 suffix.
    Arguments:
    - host_uid: the name by which we're calling this device in Syscat
    - interfaces: the contents of the 'interfaces' sub-tree returned by Netdescribe
    - syscat_url: the base URL for the Syscat server
    - logger: a logging object
    - newdevice: are we adding interfaces to a newly-created device, or updating an existing one?
    '''
    logger.debug('Populating interfaces for device %s', host_uid)
    # Convert the discovered data into a Syscat-friendly layout
    discovered = discovered_ifaces_to_syscat_format(interfaces, logger)
    # Set common variables ahead of time
    ifurl = '{}/raw/v1/devices/{}/Interfaces/networkInterfaces'.format(syscat_url, host_uid)
    # New device: just go ahead and add the details
    if newdevice:
        for iface_uid, ifacetuple in discovered.items():
            add_interface_with_ip_addrs(host_uid, iface_uid, ifacetuple, syscat_url, logger)
        return True
    # Existing device: compare what's already there with what we have
    else:
        existing = get_iface_list_from_syscat(host_uid, syscat_url, logger)
        logger.debug('Existing interfaces in Syscat:\n%s', jsonify(existing))
        logger.debug('Discovered interfaces in Syscat:\n%s', jsonify(discovered))
        if existing:
            # A more nuanced report is warranted here.
            diffs = compare_iface_lists(discovered, existing, logger)
            # No differences found; nothing to do
            if (not diffs['discovered-only']) and (not diffs['syscat-only']) and (
                    not diffs['diffs']):
                logger.info('Discovered ifaces match existing ones; no change required')
                return True
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
                            # Add newly-discoovered interfaces
                            if 'discovered-only' in details['addresses']:
                                for addr in details['addresses']['discovered-only']:
                                    logger.info('Adding discovered address %s to interface %s',
                                                addr.with_prefixlen, iface)
                                    add_ip_address(host_uid, iface, addr, syscat_url, logger)
                            # Remove addresses that have gone away
                            if 'syscat-only' in details['addresses']:
                                for addr in details['addresses']['syscat-only']:
                                    delete_ip_address(host_uid, iface, addr, syscat_url, logger)
                # Newly-discovered interfaces
                if diffs['discovered-only']:
                    for iface in diffs['discovered-only']:
                        iface_uid = iface[0].ifname    # Same assumption as above
                        logger.info('Adding interface %s:%s that has been newly discovered.',
                                    host_uid, iface_uid)
                        add_interface_with_ip_addrs(host_uid, iface_uid, iface, syscat_url, logger)
                # Interfaces that have gone away
                if diffs['syscat-only']:
                    for iface in diffs['syscat-only']:
                        logger.info('Removing interface %s:%s because it doesn´t exist on the device.',
                                    host_uid, iface)
                        delete_interface(host_uid, iface, syscat_url, logger)
                return True
        logger.debug('Syscat has no network interfaces recorded for this device.')
        if discovered:
            for iface_uid, ifacetuple in discovered.items():
                logger.info('Adding interface %s to %s', iface_uid, host_uid)
                add_interface_with_ip_addrs(host_uid,
                                            iface_uid,
                                            ifacetuple,
                                            syscat_url,
                                            logger)
            return True
        logger.debug('No interfaces found on %s; how did we even query it?', host_uid)
        return False

def discover_into_syscat(address,        # IP address, FQDN or otherwise resolvable address
                         name=None,      # Name of target device, to override the discovered one
                         use_sysname=False,  # Use the discovered sysName as the Syscat UID
                         snmpcommunity="public",
                         syscat_url="http://localhost:4950", # Default base URL for Syscat
                         loglevel="info", # Default loglevel
                         logger_arg=None):
    """
    Ensure that there's an entry in Syscat for the device we just discovered.
    Update existing instances, and return a dict describing any updates.
    Return True if the result was a new entry; otherwise, return a dict describing the updates.
    Assumes version 1 of the Syscat API.
    Structure of the return value:
    - system
        - <attribute-name>
            - existing: <value currently in Syscat>
            - discovered: <value discovered just now>
    """
    # Establish logging
    if logger_arg:
        logger = logger_arg
    else:
        logger = create_logger(loglevel=loglevel)
        logger.info("Performing discovery on device at %s", address)
    # Perform discovery
    response = netdescribe.snmp.device_discovery.explore_device(address, logger, snmpcommunity)
    if not response:
        logger.error('Failed to perform discovery on device at address %s', address)
        return False
    logger.debug("Result of discovery was:\n%s", response.as_json())
    # Get the "raw" dict of namedtuples, not the JSON transformation
    device = response.as_dict()
    # Resolve the device's UID
    if name:
        uid = name
    elif use_sysname and device['system']['sysName'] and device['system']['sysName'] != "":
        uid = device['system']['sysName']
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
                   device['system']['sysName'],
                   device['system']['sysDescr'],
                   syscat_url,
                   logger)
        created_new_device = True
    # We already have one of these; log the fact and ensure it's up to date
    elif existing_response.status_code == 200:
        logger.debug("%s is already present in Syscat. Ensuring it's up to date...", uid)
        created_new_device = False
        # Compare the system attributes
        diffs = compare_discovered_device_to_syscat(device, existing_response.json(), logger)
        # Perform any necessary updates to the device's own attributes
        if diffs and 'system' in diffs:
            devices_url = "%s/raw/v1/devices" % syscat_url
            payload = {}
            for attr, vals in diffs['system'].items():
                payload[attr] = vals['discovered']
            logger.info('Updating system for %s with details %s', uid, payload)
            requests.put('%s/%s' % (devices_url, uid), data=payload)
        # No updates needed. Do mention this, so the user knows where we're up to
        else:
            logger.debug('No system updates needed.')
    # Something else happened.
    else:
        logger.critical("Syscat returned an unexpected result: %s %s",
                        existing_response.status_code, existing_response.text)
        sys.exit(1)
    # Now ensure its interfaces are correctly described
    populate_interfaces_flat(uid,
                             device['interfaces'],
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
    and update Syscat with the results.')
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
    parser.add_argument('--use-sysname',
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
    discover_into_syscat(args.address,
                         name=args.name,
                         use_sysname=args.use_sysname,
                         snmpcommunity=args.community,
                         loglevel=loglevel)

if __name__ == "__main__":
    process_cli()
