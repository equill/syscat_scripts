#!/usr/bin/env python3

"""
For migrating data from Device42 to Syscat
"""

# Third-party modules
import requests

# Built-in modules
import json
import logging
import re

# Device42
D42_USER = 'admin'
D42_PASSWD = 'adm!nd42'
D42_FQDN = 'device42.example.com'
# Derive it here, use it many times
D42_URI = 'https://{}/api/1.0'.format(D42_FQDN)

# Syscat
SYSCAT_URI = 'http://localhost:4950/raw/v1'

# Data defaults
DEFAULT_ASN = 'ournet'
DEFAULT_ORG = 'myCompany'

# Logging
LOGLEVEL_STDOUT = logging.WARNING
LOGLEVEL_FILE = logging.INFO
LOGFILE = '/tmp/device42_migration.log'


# Utility functions

def jsonify(data):
    "Render data in human-friendly JSON format"
    json.dumps(data, indent=4, sort_keys=True)

def post(uri, data, logger, expected=201):
    """
    Post data to Syscat.
    Deliberately terse and minimal, because we do nothing with the output.
    """
    url = '%s/%s' % (SYSCAT_URI, uri)
    logger.debug('POSTing to %s with data %s' % (url, data))
    response = requests.post(url, data=data)
    if response.status_code != expected:
        logger.warning(
            'Status {rec} does not match expected {exp}. URL was {url}, data was {data}'.format(
                rec=response.status_code,
                exp=expected,
                url=url,
                data=data))
    return response

def sanitise_uid(uid, logger):
    '''
    Sanitise a UID string in the same way Restagraph does
    '''
    logger.debug('Sanitising UID %s', uid)
    return re.sub('[/ ]', '_', uid)


# Logging

def create_logger(loglevel=logging.DEBUG):
    """
    Create a basic logging object, which logs to both STDOUT and file.
    """
    # Create the logger
    logger = logging.getLogger('device42_migration')
    # Set defaults within the logger
    logger.setLevel(loglevel)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Standard output
    stdout = logging.StreamHandler()
    stdout.setFormatter(formatter)
    stdout.setLevel(LOGLEVEL_STDOUT)
    logger.addHandler(stdout)
    # File
    logtofile = logging.FileHandler(LOGFILE)
    logtofile.setFormatter(formatter)
    logtofile.setLevel(LOGLEVEL_FILE)
    logger.addHandler(logtofile)
    # return the logger
    return logger


# Actual migration functions

# We'll need this for a lookup table, to avoid numerous HTTP calls to Device42.
# It's populated by migrate_customers().
CUSTOMER_CACHE = {}

def migrate_tags(logger):
    "Migrate tags into Syscat"
    logger.info('Migrating tags into Syscat')
    for tag in requests.get('%s/tags/' % D42_URI,
                            auth=(D42_USER, D42_PASSWD)).json()['tags']:
        post('tags', {'uid': tag['name']}, logger)

def migrate_customers(logger):
    "Copy customer definitions into Syscat."
    logger.info('Copying customer definitions into Syscat')
    for cust in requests.get('{}/customers/'.format(D42_URI),
                             auth=(D42_USER, D42_PASSWD)).json()['Customers']:
        # Add it to the cache
        CUSTOMER_CACHE[str(cust['id'])] = cust['name']
        # Install it in Syscat
        post('organisations', {'uid': cust['name'], 'comments': cust['notes']}, logger)
    # Add a default
    CUSTOMER_CACHE['unknown'] = 'Unknown'
    post('organisations', {'uid': 'Unknown', 'comments': 'Catch-all.'}, logger)
    # Provide some useful feedback
    logger.debug('Customer cache:\n%s', json.dumps(CUSTOMER_CACHE, indent=4, sort_keys=True))

def migrate_brands(logger):
    "Copy brand definitions into Syscat."
    logger.info('Copying brands into Syscat')
    for vendor in requests.get('%s/vendors/' % D42_URI,
                               auth=(D42_USER, D42_PASSWD)).json()['vendors']:
        post('brands', {'uid': vendor['name'], 'comments': vendor['notes']}, logger)
    # Add one for models with no known brand
    post('brands', {'uid': 'None', 'comments': 'Brand unknown'}, logger)

def migrate_models(logger):
    "Copy customer definitions into Syscat."
    logger.info('Copying customers into Syscat')
    for model in requests.get('%s/hardwares/' % D42_URI,
                              auth=(D42_USER, D42_PASSWD)).json()['models']:
        if model['manufacturer'] and model['manufacturer'] != None:
            post('brands/{}/Produces/models'.format(sanitise_uid(model['manufacturer'], logger)),
                 {'uid': model['name']},
                 logger)

def migrate_operating_systems(logger):
    "Migrate OS definitions into Syscat."
    logger.info('Copying operating systems into Syscat')
    for o_s in requests.get('%s/operatingsystems/' % D42_URI,
                            auth=(D42_USER, D42_PASSWD)).json()['operatingsystems']:
        post('brands/%s/Produces/operatingSystems' % (o_s['manufacturer']),
             {'uid': o_s['name']},
             logger)

def migrate_buildings(logger):
    '''
    Migrate building data into Syscat.
    Note that this creates a site with the same name as the building,
    then creates the building under it.
    '''
    logger.info('Copying sites into Syscat as both sites and buildings')
    for bldg in requests.get('%s/buildings/' % D42_URI,
                             auth=(D42_USER, D42_PASSWD)).json()['buildings']:
        post('sites',
             {'uid': bldg['name'],
              'comments': 'Automatically created during migration from Device42'},
             logger)
        post('sites/%s/Buildings/buildings' % bldg['name'],
             {'uid': bldg['name'],
              'comments': bldg['notes']},
             logger)

def migrate_rooms(logger):
    "Migrate room data into Syscat."
    logger.info('Copying rooms into Syscat')
    for room in requests.get('%s/rooms/' % D42_URI,
                             auth=(D42_USER, D42_PASSWD)).json()['rooms']:
        post('sites/%s/Buildings/buildings/%s/Rooms/rooms'
             % (room['building'], room['building']),
             {'uid': room['name'],
              'comments': room['notes']},
             logger)

def create_device(details, logger):
    "Insert a device definition into Syscat."
    # Catch failures early
    if ('name' not in details) or (details['name'] == "") or (details['name'] is None):
        logger.error('Attempted to create a device with a null/empty UID. Details: %s',
                     jsonify(details))
        return False
    logger.debug('Copying device %s into Syscat', details['name'])
    # Create the initial object
    data = {'uid': details['name'],
            'in_service': details['in_service']}
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
    logger.debug('Creating device with details: %s', details)
    post('devices', data, logger)
    # Now link other things as we confirm we have them
    # Owner
    if details['customer'] and details['customer'] != None:
        logger.debug('Connecting device %s to customer %s',
                     (details['name'], details['name']))
        post('devices/%s/BusinessOwner' % sanitise_uid(details['name'], logger),
             {'target': '/organisations/%s' % sanitise_uid(details['customer'], logger)},
             logger)
    # Model
    if (details['hw_model']) and (details['hw_model'] != None) and (details['manufacturer']) and (
            details['manufacturer'] != None):
        logger.debug('Connecting device %s to model %s/%s',
                     (details['name'], details['manufacturer'], details['hw_model']))
        post('devices/%s/Model' % sanitise_uid(details['name'], logger),
             {'target': '/brands/%s/Produces/models/%s'
                        % (sanitise_uid(details['manufacturer'], logger),
                           sanitise_uid(details['hw_model'], logger))},
             logger)
    # OS
    if (details['os']) and (details['os'] != None):
        logger.debug('Connecting device %s to OS %s', (details['name'], details['os']))
        post('devices/%s/OperatingSystem' % sanitise_uid(details['name'], logger),
             {'target': '/operatingSystems/%s' % (sanitise_uid(details['os'], logger))},
             logger)
    # Tags
    for tag in details['tags']:
        post('devices/%s/Tags' % details['name'], {'target': '/tags/%s' % tag}, logger)
    # Site
    if details['building'] != None and details['building'] != '':
        if details['room'] != None and details['room'] != '':
            target = '/sites/{bldg}/Buildings/buildings/{bldg}/Rooms/rooms/{room}'.format(
                bldg=sanitise_uid(details['building'], logger),
                room=sanitise_uid(details['room'], logger))
        else:
            target = '/sites/{bldg}/Buildings/buildings/{bldg}'.format(
                bldg=sanitise_uid(details['building'], logger))
        logger.debug('Linking device %s to location %s', details['name'], target)
        post('devices/%s/Location' % sanitise_uid(details['name'], logger),
             {'target': target},
             logger)
    # Keep pylint happy, and return something
    return True

def migrate_devices(logger):
    "Migrate device definitions into Syscat."
    logger.info('Copying devices into Syscat')
    for device in requests.get('%s/devices/all/?include_cols=name,serial_no,asset_no,in_service,service_level,type,tags,customer,hw_model,manufacturer,room,building,location,os,blankasnull=true'
                               % D42_URI, auth=(D42_USER, D42_PASSWD)).json()['Devices']:
        create_device(device, logger)

def migrate_vms(logger):
    """
    Migrate VM<->host mappings.
    Really needs to be done as a separate step after migrating all the devices,
    to ensure both sides of each mapping are present.
    """
    logger.info('Copying VM/host connections into Syscat')
    for device in requests.get(
            '%s/devices/all/?include_cols=name,vms,virtual_host_name&blankasnull=true'
            % D42_URI, auth=(D42_USER, D42_PASSWD)).json()['Devices']:
        logger.info('Device data: %s', jsonify(device))
        if not device:
            logger.warn('Null device data received; moving on.')
            continue
        # If this is a VM, map to its host
        if ('virtual_host_name' in device) and isinstance(device['virtual_host_name'], str) and device['virtual_host_name'] != "":
            post('devices/{}/HostedOn'.format(sanitise_uid(device['name'], logger)),
                 {'target': '/devices/{}'.format(sanitise_uid(device['virtual_host_name'], logger))},
                 logger)
        # If this is a host, map to its VMs
        if 'vms' in device and isinstance(device['vms'], str) and device['vms'] != "":
            for v_m in re.split(',', device['vms']):
                post('/devices/{}/Hosts'.format(sanitise_uid(device['name'], logger)),
                     {'target': '/devices/{}'.format(sanitise_uid(v_m, logger))},
                     logger)

def migrate_vrf_groups(logger):
    "Migrate VRF-group definitions into Syscat."
    logger.info('Copying VRF groups into Syscat')
    # Create the default organisation
    post('organisations', {'uid': DEFAULT_ORG}, logger)
    # Now install the VRFs
    for vrf in requests.get('%s/vrf_group/' % D42_URI, auth=(D42_USER, D42_PASSWD)).json():
        post('organisations/{org}/VrfGroups/vrfGroups'.format(org=DEFAULT_ORG),
             {'uid': vrf['name']},
             logger)

def migrate_subnets(logger):
    "Migrate subnet definitions into Syscat"
    logger.info('Copying subnets into Syscat')
    for subnet in requests.get('%s/subnets/'
                               % D42_URI, auth=(D42_USER, D42_PASSWD)).json()['subnets']:
        # Look up the customer name from the ID
        logger.debug('Looking up name for customer ID {}'.format(subnet['customer_id']))
        if subnet['customer_id']:
            customer = CUSTOMER_CACHE[str(subnet['customer_id'])]
        else:
            customer = 'Unknown'
        # Insert the subnet itself
        post('organisations/{}/VrfGroups/{}/Subnets/ipv4Subnets'.format(
            customer, subnet['vrf_group_name']),
             {'uid': subnet['network'],
              'prefixlength': subnet['mask_bits'],
              'description': subnet['description']},
             logger)
        # Now link it to a customer,
        # using the cache to avoid a D42 lookup for every last subnet
        #post('~A/Owner' % result.text, {'target': '/organisations/{}'.format(customer)}, logger)
        # Tags
        for tag in subnet['tags']:
            post('organisations/{}'.format(DEFAULT_ORG), {'target': '/tags/{}'.format(tag)}, logger)

def migrate_all_the_things():
    "Pull it all together"
    # Foundation things
    logger = create_logger()
    migrate_tags(logger)
    migrate_customers(logger)
    # Locations
    migrate_buildings(logger)
    migrate_rooms(logger)
    # Devices
    migrate_brands(logger)
    migrate_models(logger)
    migrate_operating_systems(logger)
    migrate_devices(logger)
    migrate_vms(logger)
    # IPAM
    migrate_vrf_groups(logger)
    #migrate_subnets(logger)

if __name__ == '__main__':
    migrate_all_the_things()
