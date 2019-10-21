#!/usr/bin/env python3

#   Copyright [2017] [James Fleming <james@electronic-quill.net]
#
# Licensed under the GNU General Public License
# - for details, see LICENSE.txt in the top-level directory

"""
For migrating data from Device42 to Syscat
"""

# Third-party modules
import requests

# Built-in modules
import argparse
import collections
import getpass
import ipaddress
import json
import logging
import re


# Datatypes

D42Server = collections.namedtuple('d42_server', ['uri', 'user', 'passwd'])
SyscatServer = collections.namedtuple('syscat_server', ['url'])


# Utility functions

def jsonify(data):
    "Render data in human-friendly JSON format"
    json.dumps(data, indent=4, sort_keys=True)

def post(syscat_url, uri, data, logger, expected=201, api=False):
    """
    POST data to Syscat.
    """
    # Construct the API substring for the URL
    if api == "raw":
        api_string = "raw/v1"
    if api == "ipam":
        api_string = "ipam/v1"
    else:
        api_string = "raw/v1"
    # Construct the URL
    url = '{}/{}/{}'.format(syscat_url, api_string, re.sub('^/', '', uri))
    logger.debug('POSTing to {} with data {}'.format(url, data))
    if 'uid' in data and data['uid'] == "''":
        logger.debug("UID was specified as ''.")
        return False
    response = requests.post(url, data=data)
    # Report how it went
    if response.status_code != expected:
        logger.warning(
            'Status {rec} does not match expected {exp}. URL was {url}, data was {data}'.format(
                rec=response.status_code,
                exp=expected,
                url=url,
                data=data))
    else:
        logger.debug('Response status matched expected value.')
    # Return the response
    return response

def put(syscat_url, uri, uid, data, logger, expected=201, api=False):
    """
    PUT data to Syscat.
    Deliberately terse and minimal, because we do nothing with the output.
    """
    # Construct the API substring for the URL
    if api == "raw":
        api_string = "raw/v1"
    if api == "ipam":
        api_string = "ipam/v1"
    else:
        api_string = "raw/v1"
    # Construct the URL
    url = '{}/{}/{}/{}'.format(syscat_url, api_string, re.sub('^/', '', uri), uid)
    logger.debug('PUTting to {} with data {}'.format(url, data))
    if 'uid' in data and data['uid'] == "''":
        logger.debug("UID was specified as ''.")
        return False
    response = requests.put(url, data=data)
    # Report how it went
    if response.status_code != expected:
        logger.warning(
            'Status {rec} does not match expected {exp}. URL was {url}, data was {data}'.format(
                rec=response.status_code,
                exp=expected,
                url=url,
                data=data))
    else:
        logger.debug('Response status matched expected value.')
    # Return the response
    return response

def sanitise_uid(uid, logger):
    '''
    Sanitise a UID string in the same way Restagraph does
    '''
    logger.debug('Sanitising UID {}'.format(uid))
    return re.sub('[/ ]', '_', uid)


# Logging

LOGLEVELS = {'fatal': logging.FATAL,
             'critical': logging.CRITICAL,
             'error': logging.ERROR,
             'warning': logging.WARNING,
             'info': logging.INFO,
             'debug': logging.DEBUG}

def create_logger(loglevel, logfile=False, loglevel_file=False):
    """
    Create a basic logging object, which logs to both STDOUT and file.
    """
    # Create the logger
    logger = logging.getLogger('device42_migration')
    # Set defaults within the logger
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # This is the base level at which log-messages are handled; the handlers apply their own
    # filtering on top of this. I.e, all messages below this level will be discarded regardless.
    logger.setLevel(logging.DEBUG)
    # Standard output
    stdout = logging.StreamHandler()
    stdout.setFormatter(formatter)
    stdout.setLevel(LOGLEVELS[loglevel])
    logger.addHandler(stdout)
    # File
    if logfile and loglevel_file:
        logtofile = logging.FileHandler(logfile)
        logtofile.setFormatter(formatter)
        logtofile.setLevel(LOGLEVELS[loglevel_file])
        logger.addHandler(logtofile)
    # return the logger
    return logger


# Actual migration functions

def migrate_tags(device42, syscat, logger):
    "Migrate tags into Syscat"
    logger.info('Migrating tags into Syscat')
    tags_url = '{}/tags/'.format(device42.uri)
    logger.debug('Querying tags via URL {}'.format(tags_url))
    for tag in requests.get(tags_url, auth=(device42.user, device42.passwd)).json()['tags']:
        post(syscat.url, 'tags', {'uid': tag['name']}, logger)

def migrate_customers(device42, syscat, logger):
    "Copy customer definitions into Syscat."
    logger.info('Copying customer definitions into Syscat')
    customer_cache = {}   # Lookup table for Device42 customer IDs
    for cust in requests.get('{}/customers/'.format(device42.uri),
                             auth=(device42.user, device42.passwd)).json()['Customers']:
        # Add it to the cache
        customer_cache[str(cust['id'])] = cust['name']
        # Install it in Syscat
        post(syscat.url, 'organisations', {'uid': cust['name']}, logger)
        # Add its attributes
        put(syscat.url,
            '/organisations',
            sanitise_uid(cust['name'], logger),
            {'description': cust['notes']},
            logger)
    # Provide some useful feedback
    logger.debug('Customer cache:\n{}'.format(json.dumps(customer_cache, indent=4, sort_keys=True)))
    return customer_cache

def migrate_makes(device42, syscat, logger):
    "Copy brand definitions into Syscat."
    logger.info('Copying makes into Syscat')
    for vendor in requests.get('{}/vendors/'.format(device42.uri),
                               auth=(device42.user, device42.passwd)).json()['vendors']:
        post(syscat.url, 'makes', {'uid': vendor['name'], 'description': vendor['notes']}, logger)
        put(syscat.url,
            '/makes',
            sanitise_uid(vendor['name'], logger),
            {'description': vendor['notes']},
            logger)

def migrate_models(device42, syscat, logger):
    "Copy customer definitions into Syscat."
    logger.info('Copying customers into Syscat')
    for model in requests.get('{}/hardwares/'.format(device42.uri),
                              auth=(device42.user, device42.passwd)).json()['models']:
        if model['manufacturer'] and model['manufacturer'] != None:
            post(syscat.url,
                 'makes/{}/Produces/models'.format(sanitise_uid(model['manufacturer'], logger)),
                 {'uid': model['name']},
                 logger)

def migrate_operating_systems(device42, syscat, logger):
    "Migrate OS definitions into Syscat."
    logger.info('Copying operating systems into Syscat')
    for o_s in requests.get('{}/operatingsystems/'.format(device42.uri),
                            auth=(device42.user, device42.passwd)).json()['operatingsystems']:
        post(syscat.url,
             'makes/{}/Produces/operatingSystems'.format(o_s['manufacturer']),
             {'uid': o_s['name']},
             logger)

def migrate_buildings(device42, syscat, org, logger):
    '''
    Migrate building data into Syscat.
    Note that this creates a site with the same name as the building,
    then creates the building under it.
    '''
    logger.info('Copying sites into Syscat as both sites and buildings')
    for bldg in requests.get('{}/buildings/'.format(device42.uri),
                             auth=(device42.user, device42.passwd)).json()['buildings']:
        post(syscat.url, 'organisations/{}/Sites/sites'.format(org), {'uid': bldg['name']}, logger)
        post(syscat.url, 'buildings', {'uid': bldg['name']}, logger)
        post(syscat.url,
             'organisations/{}/Sites/sites/{}/Buildings'.format(org,
                                                                sanitise_uid(bldg['name'], logger)),
             {'target': '/buildings/{}'.format(bldg['name'])},
             logger)
        put(syscat.url,
            '/organisations/{}/Sites/sites/{}/Buildings/buildings'.format(
                org, sanitise_uid(bldg['name'], logger)),
            sanitise_uid(bldg['name'], logger),
            {'description': bldg['notes']},
            logger)

def migrate_rooms(device42, syscat, org, logger):
    "Migrate room data into Syscat."
    logger.info('Copying rooms into Syscat')
    for room in requests.get('{}/rooms/'.format(device42.uri),
                             auth=(device42.user, device42.passwd)).json()['rooms']:
        post(syscat.url,
             'organisations/{}/Sites/sites/{}/Buildings/buildings/{}/Rooms/rooms'.format(
                 org, room['building'], room['building']),
             {'uid': room['name']},
             logger)
        put(syscat.url,
            '/organisations/{org}/Sites/sites/{bldg}/Buildings/buildings/{bldg}/Rooms/rooms'.format(
                org=org, bldg=sanitise_uid(room['building'], logger)),
            sanitise_uid(room['name'], logger),
            {'description': room['notes']},
            logger)

def create_device(syscat, details, org, logger):
    "Insert a device definition into Syscat."
    # Catch failures early
    if ('name' not in details) or (details['name'] == "") or (details['name'] is None):
        logger.error('Attempted to create a device with a null/empty UID. Details: {}'.format(
            jsonify(details)))
        return False
    logger.debug('Copying device {} into Syscat'.format(details['name']))
    # Create the initial object
    logger.debug('Creating device {}'.format(details['name']))
    post(syscat.url, 'devices', {'uid': details['name']}, logger)
    # Add its details
    data = {'in_service': details['in_service']}
    # Serial number
    if 'serial_no' in details['serial_no'] and details['serial_no'] != None:
        data['serial_number'] = details['serial_no']
    else:
        data['serial_number'] = ''
    # Asset number
    if 'asset_no' in details['asset_no'] and details['asset_no'] != None:
        data['asset_number'] = details['asset_no']
    else:
        data['asset_number'] = ''
    # Now create it
    logger.debug('Updating device {} with details: {}'.format(details['name'], data))
    put(syscat.url, '/devices', sanitise_uid(details['name'], logger), data, logger)
    # Now link other things as we confirm we have them
    # Owner
    if details['customer'] and details['customer'] != None:
        logger.debug('Connecting device {} to customer {}'.format(
            details['name'], details['customer']))
        post(syscat.url,
             'devices/{}/BusinessOwner'.format(sanitise_uid(details['name'], logger)),
             {'target': '/organisations/{}'.format(sanitise_uid(details['customer'], logger))},
             logger)
    # Model
    if (details['hw_model']) and (details['hw_model'] != None) and (details['manufacturer']) and (
            details['manufacturer'] != None):
        logger.debug('Connecting device {} to model {}/{}'.format(
            details['name'], details['manufacturer'], details['hw_model']))
        post(syscat.url,
             'devices/{}/Model'.format(sanitise_uid(details['name'], logger)),
             {'target': '/makes/{}/Produces/models/{}'.format(
                 sanitise_uid(details['manufacturer'], logger),
                 sanitise_uid(details['hw_model'], logger))},
             logger)
    # OS
    if (details['os']) and (details['os'] != None):
        logger.debug('Connecting device {} to OS {}'.format(details['name'], details['os']))
        post(syscat.url,
             'devices/{}/OperatingSystem'.format(sanitise_uid(details['name'], logger)),
             {'target': '/operatingSystems/{}'.format(sanitise_uid(details['os'], logger))},
             logger)
    # Tags
    for tag in details['tags']:
        post(syscat.url,
             'devices/{}/Tags'.format(details['name']),
             {'target': '/tags/{}'.format(sanitise_uid(tag, logger))},
             logger)
    # Site
    if details['building'] != None and details['building'] != '':
        if details['room'] != None and details['room'] != '':
            # pylint: disable=line-too-long
            target = '/organisations/{org}/Sites/sites/{bldg}/Buildings/buildings/{bldg}/Rooms/rooms/{room}'.format(
                org=org,
                bldg=sanitise_uid(details['building'], logger),
                room=sanitise_uid(details['room'], logger))
        else:
            target = '/sites/{bldg}/Buildings/buildings/{bldg}'.format(
                bldg=sanitise_uid(details['building'], logger))
        logger.debug('Linking device {} to location {}'.format(details['name'], target))
        post(syscat.url,
             'devices/{}/Location'.format(sanitise_uid(details['name'], logger)),
             {'target': target},
             logger)
    # Keep pylint happy, and return something
    return True

def migrate_devices(device42, syscat, org, logger):
    "Migrate device definitions into Syscat."
    logger.info('Copying devices into Syscat')
    # Build an ID->devicename lookup table
    device_cache = {}
    # pylint: disable=line-too-long
    for device in requests.get('{}/devices/all/?include_cols=device_id,name,serial_no,asset_no,in_service,service_level,type,tags,customer,hw_model,manufacturer,room,building,location,os,blankasnull=true'.format(device42.uri),
                               auth=(device42.user, device42.passwd)).json()['Devices']:
        # Update the lookup table
        device_cache[device['device_id']] = device['name']
        # Create the device in Syscat
        create_device(syscat, device, org, logger)
    return device_cache

def migrate_interfaces(device42, syscat, device_cache, logger):
    "Migrate interfaces into Syscat"
    logger.info('Copying switchports from Device42 to interfaces in Syscat')
    interface_cache = {}
    for switchport in requests.get('{}/switchports/'.format(device42.uri),
                                   auth=(device42.user, device42.passwd)).json()['switchports']:
        # Is it allocated to a device?
        if 'switch' not in switchport:
            logger.warning('Switchport {} has no "switch" data'.format(switchport['switchport_id']))
            continue
        # Is it usable?
        if 'port' not in switchport or switchport['port'] == "":
            logger.warning('Switchport {} has an empty "port" field'.format(
                switchport['switchport_id']))
            continue
        # Carry on
        device_id = switchport['switch']['device_id']
        interface_cache[switchport['switchport_id']] = switchport['port']
        if device_id in device_cache:
            device = device_cache[device_id]
            path = '/devices/{}/Interfaces/networkInterfaces'.format(sanitise_uid(device, logger))
            uid = switchport['port']
            # Create the interface
            logger.info('Attempting to create {}/{}'.format(path, uid))
            post(syscat.url, path, {'uid': uid}, logger)
            # Add its attributes
            attrs = {}
            if 'description' in switchport and switchport['description'] != "":
                attrs['description'] = switchport['description']
            if 'macs' in switchport and switchport['macs'] != "":
                attrs['macaddress'] = switchport['macs']
            if attrs != {}:
                put(syscat.url, '{}'.format(path), sanitise_uid(uid, logger), attrs, logger)
            # Add any tags
            for tag in switchport['tags']:
                post(syscat.url,
                     '{}/{}'.format(path, sanitise_uid(uid, logger)),
                     {'target': '/tags/{}'.format(tag)},
                     logger)
    return interface_cache

def migrate_vms(device42, syscat, logger):
    """
    Migrate VM<->host mappings.
    Really needs to be done as a separate step after migrating all the devices,
    to ensure both sides of each mapping are present.
    """
    logger.info('Copying VM/host connections into Syscat')
    for device in requests.get(
            '{}/devices/all/?include_cols=name,virtual_host_name&blankasnull=true'.format(
                device42.uri),
            auth=(device42.user, device42.passwd)).json()['Devices']:
        logger.info('Device data: {}'.format(jsonify(device)))
        if not device:
            logger.warn('Null device data received; moving on.')
            continue
        # If this is a VM, map to its host
        if ('virtual_host_name' in device
                and isinstance(device['virtual_host_name'], str)
                and device['virtual_host_name'] != ""):
            post(syscat.url,
                 'devices/{}/Host'.format(sanitise_uid(device['name'], logger)),
                 {'target': '/devices/{}'.format(sanitise_uid(device['virtual_host_name'],
                                                              logger))},
                 logger)

def migrate_vrf_groups(device42, syscat, default_org, logger):
    "Migrate VRF-group definitions into Syscat. Assume they all belong to the default organisation."
    logger.info('Copying VRF groups into Syscat')
    # Now install the VRFs
    for vrf in requests.get('{}/vrf_group/'.format(device42.uri),
                            auth=(device42.user, device42.passwd)).json():
        post(syscat.url,
             'organisations/{org}/VrfGroups/vrfGroups'.format(org=default_org),
             {'uid': vrf['name']},
             logger)

def migrate_subnets(device42, syscat, customer_cache, default_org, logger):
    "Migrate subnet definitions into Syscat"
    logger.info('Copying subnets into Syscat')
    subnet_vrf_cache = {}   # Lookup table of subnets to VRFs
    for subnet in requests.get('{}/subnets/'.format(device42.uri),
                               auth=(device42.user, device42.passwd)).json()['subnets']:
        logger.info('Processing subnet {}/{}'.format(
            subnet['network'],
            subnet['mask_bits']))
        # Turn it into a python object
        addr_obj = ipaddress.ip_network('{}/{}'.format(
            subnet['network'],
            subnet['mask_bits']))
        # Get its VRF
        if 'vrf_group_name' in subnet and subnet['vrf_group_name']:
            vrf = subnet['vrf_group_name']
        else:
            vrf = None
        # Update the cache
        subnet_vrf_cache[subnet['subnet_id']] = vrf
        # Insert the subnet itself.
        logger.debug('Attempting to add subnet {}'.format(addr_obj.with_prefixlen))
        payload = {'org': default_org,
                   'subnet': addr_obj.with_prefixlen}
        if vrf:
            payload['vrf'] = vrf
        response = post(syscat.url, 'subnets', payload, logger, api="ipam")
        # Tags
        for tag in subnet['tags']:
            post(syscat.url,
                 '{}/Tags'.format(response.text),
                 {'target': '/tags/{}'.format(sanitise_uid(tag, logger))},
                 logger)
        # Look up the customer name from the ID
        # Will be used for linking subnets to customers
        logger.debug('Looking up name for customer ID {}'.format(subnet['customer_id']))
        if subnet['customer_id']:
            customer = customer_cache[str(subnet['customer_id'])]
        else:
            customer = default_org
        # Now link it to a customer,
        # using the cache to avoid a D42 lookup for every last subnet
        post(syscat.url,
             '{}/AllocatedTo'.format(response.text),
             {'target': '/organisations/{}'.format(sanitise_uid(customer, logger))},
             logger)
    return subnet_vrf_cache

def migrate_addresses(device42, syscat, org, subnet_vrf_cache, logger):
    "Migrate IPv4 and IPv6 addresses into Syscat"
    logger.info('Migrating IP addresses')
    for addr in requests.get('{}/ips/'.format(device42.uri),
                             auth=(device42.user, device42.passwd)).json()['ips']:
        logger.info('Processing address {}'.format(addr['ip']))
        # Create an object to represent the address
        addr_obj = ipaddress.ip_address(addr['ip'])
        # Insert the address itself
        payload = {'address': addr_obj.exploded,
                   'org': org}
        if addr['subnet_id'] in subnet_vrf_cache:
            payload['vrf'] = subnet_vrf_cache[addr['subnet_id']]
        post(syscat.url, 'addresses', payload, logger, api="ipam")
        # Associating them with devices and interfaces would be a good thing,
        # but will require more work to get right.
        # Ditto with tags.

def parse_cli_args():
    "Parse the CLI arguments."
    parser = argparse.ArgumentParser()
    parser.add_argument('--d42_user', action='store', default='admin', required=True)
    parser.add_argument('--d42_url', action='store', default='http://localhost',
                        help='E.g: http://localhost', required=True)
    parser.add_argument('--syscat_url', action='store', default='http://10.255.0.1')
    parser.add_argument('--default_asn', action='store', default='64512')
    parser.add_argument('--default_org', action='store', default='myCompany')
    parser.add_argument('--loglevel_stdout', action='store', default='info')
    parser.add_argument('--loglevel_file', action='store', default='debug')
    parser.add_argument('--logfile', action='store',
                        help='''Specify a filepath if you want the output saved to file.
                        Use --loglevel_file to control the level of detail sent to this file.''')
    return parser.parse_args()

def get_d42_password():
    "Interactively ask for the Device42 password, to avoid leaving it in the shell history."
    return getpass.getpass("Device42 password: ")

def migrate_all_the_things():
    "Pull it all together"
    # Script setup
    args = parse_cli_args()
    device42 = D42Server(uri='{}/api/1.0'.format(args.d42_url),
                         user=args.d42_user,
                         passwd=get_d42_password())
    syscat = SyscatServer(url=args.syscat_url)
    logger = create_logger(loglevel=args.loglevel_stdout,
                           logfile=args.logfile,
                           loglevel_file=args.loglevel_file)
    # Migrate the basic things
    # Create the default organisation
    post(syscat.url, 'organisations', {'uid': args.default_org}, logger)
    migrate_tags(device42, syscat, logger)
    customer_cache = migrate_customers(device42, syscat, logger)
    # Locations
    migrate_buildings(device42, syscat, args.default_org, logger)
    migrate_rooms(device42, syscat, args.default_org, logger)
    # Devices
    migrate_makes(device42, syscat, logger)
    migrate_models(device42, syscat, logger)
    migrate_operating_systems(device42, syscat, logger)
    device_cache = migrate_devices(device42, syscat, args.default_org, logger)
    migrate_interfaces(device42, syscat, device_cache, logger)
    migrate_vms(device42, syscat, logger)
    # IPAM
    migrate_vrf_groups(device42, syscat, args.default_org, logger)
    subnet_vrf_cache = migrate_subnets(device42,
                                       syscat,
                                       customer_cache,
                                       args.default_org,
                                       logger)
    migrate_addresses(device42,
                      syscat,
                      args.default_org,
                      subnet_vrf_cache,
                      logger)

if __name__ == '__main__':
    migrate_all_the_things()
