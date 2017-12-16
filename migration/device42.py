#!/usr/bin/env python3

"""
For migrating data from Device42 to Syscat
"""

# Third-party modules
import requests

# Built-in modules
import json
import re

D42_FQDN = 'device42.example.com'
D42_USER = 'admin'
D42_PASSWD = 'adm!nd42'
# Derive it here, use it many times
D42_URI = 'https://{}/api/1.0'.format(D42_FQDN)

SYSCAT_URI = 'http://localhost:4950/raw/v1'

DEFAULT_ASN = 'ournet'
DEFAULT_ORG = 'myCompany'


# Utility functions

def post(uri, data, expected=201):
    """
    Post data to Syscat.
    Deliberately terse and minimal, because we do nothing with the output.
    """
    response = requests.post('%s/%s' % (SYSCAT_URI, uri), data=data)
    return response

def sanitise_uid(uid):
    '''
    Sanitise a UID string in the same way Restagraph does
    '''
    return re.sub('[/ ]', '_', uid)


# Actual migration functions

# We'll need this for a lookup table, to avoid numerous HTTP calls to Device42.
# It's populated by migrate_customers().
CUSTOMER_CACHE = {}

def migrate_customers():
    "Copy customer definitions into Syscat."
    for cust in requests.get('{}/customers/'.format(D42_URI),
                             auth=(D42_USER, D42_PASSWD)).json()['Customers']:
        # Add it to the cache
        CUSTOMER_CACHE[str(cust['id'])] = cust['name']
        # Install it in Syscat
        post('organisations', {'uid': cust['name'], 'comments': cust['notes']})
    # Add a default
    CUSTOMER_CACHE['unknown'] = 'Unknown'
    post('organisations', {'uid': 'Unknown', 'comments': 'Catch-all.'})
    # Provide some useful feedback
    print(json.dumps(CUSTOMER_CACHE, indent=4, sort_keys=True))

def migrate_brands():
    "Copy brand definitions into Syscat."
    for vendor in requests.get('%s/vendors/' % D42_URI,
                               auth=(D42_USER, D42_PASSWD)).json()['vendors']:
        post('brands', {'uid': vendor['name'], 'comments': vendor['notes']})
    # Add one for models with no known brand
    post('brands', {'uid': 'None', 'comments': 'Brand unknown'})

def migrate_models():
    "Copy customer definitions into Syscat."
    for model in requests.get('%s/hardwares/' % D42_URI,
                              auth=(D42_USER, D42_PASSWD)).json()['models']:
        if model['manufacturer'] and model['manufacturer'] != None:
            post('brands/{}/Produces/models'.format(sanitise_uid(model['manufacturer'])),
                 {'uid': model['name']})

def migrate_operating_systems():
    "Migrate OS definitions into Syscat."
    for o_s in requests.get('%s/operatingsystems/' % D42_URI,
                            auth=(D42_USER, D42_PASSWD)).json()['operatingsystems']:
        post('brands/%s/Produces/operatingSystems' % (o_s['manufacturer']),
             {'uid': o_s['name']})

def migrate_buildings():
    '''
    Migrate building data into Syscat.
    Note that this creates a site with the same name as the building,
    then creates the building under it.
    '''
    for bldg in requests.get('%s/buildings/' % D42_URI,
                             auth=(D42_USER, D42_PASSWD)).json()['buildings']:
        post('sites',
             data={'uid': bldg['name'],
                   'comments': 'Automatically created during migration from Device42'})
        post('sites/%s/Buildings/buildings' % bldg['name'],
             data={'uid': bldg['name'],
                   'comments': bldg['notes']})

def migrate_rooms():
    "Migrate room data into Syscat."
    for room in requests.get('%s/rooms/' % D42_URI,
                             auth=(D42_USER, D42_PASSWD)).json()['rooms']:
        post('sites/%s/Buildings/buildings/%s/Rooms/rooms'
             % (room['building'], room['building']),
             data={'uid': room['name'],
                   'comments': room['notes']})

def create_device(details):
    "Insert a device definition into Syscat."
    # Catch failures early
    if ('name' not in details) or (details['name'] == "") or (details['name'] is None):
        print('ERROR Attempted to create a device with a null/empty UID')
        return False
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
    print('DEBUG Creating device with details: %s' % details)
    post('devices', data)
    # Now link other things as we confirm we have them
    # Owner
    if details['customer'] and details['customer'] != None:
        print('DEBUG Connecting device %s to customer %s'
              % (details['name'], details['name']))
        post('devices/%s/BusinessOwner' % details['name'],
             {'target': '/organisations/%s' % details['customer']})
    # Model
    if (details['hw_model']) and (details['hw_model'] != None) and (details['manufacturer']) and (
            details['manufacturer'] != None):
        print('DEBUG Connecting device %s to model %s/%s'
              % (details['name'], details['manufacturer'], details['hw_model']))
        post('devices/%s/Model' % details['name'],
             {'target': '/brands/%s/Models/models/%s'
                        % (sanitise_uid(details['manufacturer']),
                           sanitise_uid(details['hw_model']))})
    # OS
    if (details['os']) and (details['os'] != None):
        print('DEBUG Connecting device %s to OS %s' % (details['name'], details['os']))
        post('devices/%s/OperatingSystem' % details['name'],
             {'target': '/operatingSystems/%s' % (sanitise_uid(details['os']))})
    # Tags
    for tag in details['tags']:
        print('DEBUG Connecting')
        post('tags', data={'uid': tag})
        post('devices/%s/Tags' % details['name'], data={'target': '/tags/%s' % tag})
    # Site
    if details['building'] != None and details['building'] != '':
        if details['room'] != None and details['room'] != '':
            target = '/sites/%s/Buildings/buildings/%s/Rooms/rooms/%s' % (
                details['building'], details['building'], sanitise_uid(details['room']))
        else:
            target = '/sites/%s/Buildings/buildings/%s' % (details['building'], details['building'])
        print('DEBUG: linking device %s to location %s' % (details['name'], target))
        post('devices/%s/Location' % details['name'], data={'target': target})

def migrate_devices():
    "Migrate device definitions into Syscat."
    for device in requests.get('%s/devices/all/?include_cols=name,serial_no,asset_no,in_service,service_level,type,tags,customer,hw_model,manufacturer,room,building,location,os,blankasnull=true'
                               % D42_URI, auth=(D42_USER, D42_PASSWD)).json()['Devices']:
        create_device(device)

def migrate_vrfs():
    "Migrate VRF-group definitions into Syscat."
    # Create the default ASN, because Device42 doesn't have this concept
    post('asn', {'uid': DEFAULT_ASN})
    # Now install the VRFs
    for vrf in requests.get('%s/vrf_group/' % D42_URI, auth=(D42_USER, D42_PASSWD)).json():
        post('organisations/{org}/VrfGroups/vrfGroups'.format(org=DEFAULT_ORG), {'uid': vrf['name']})

def migrate_tags():
    "Migrate tags into Syscat"
    for tag in requests.get('%s/tags/' % D42_URI,
                            auth=(D42_USER, D42_PASSWD)).json()['tags']:
        post('tags', {'uid': tag['name']})

def migrate_subnets():
    "Migrate subnet definitions into Syscat."
    for subnet in requests.get('%s/subnets/'
                               % D42_URI, auth=(D42_USER, D42_PASSWD)).json()['subnets']:
        # Look up the customer name from the ID
        print('Looking up name for customer ID {}'.format(subnet['customer_id']))
        if subnet['customer_id']:
            customer = CUSTOMER_CACHE[str(subnet['customer_id'])]
        else:
            customer = 'Unknown'
        # Insert the subnet itself
        result = post('organisations/{}/VrfGroups/{}/Subnets/ipv4Subnets'.format(
                      customer, subnet['vrf_group_name']),
                      {'uid': subnet['network'],
                       'prefixlength': subnet['mask_bits'],
                       'description': subnet['description']})
        # Now link it to a customer,
        # using the cache to avoid a D42 lookup for every last subnet
        #post('~A/Owner' % result.text, {'target': '/organisations/{}'.format(customer)})
        # Tags
        #for tag in subnet['tags']:
        #    post('organisations/%s', {'target': '/tags/{}'.format(tag)})

def migrate_all_the_things():
    "Pull it all together"
    migrate_tags()
    migrate_customers()
    migrate_brands()
    migrate_models()
    migrate_operating_systems()
    migrate_buildings()
    migrate_rooms()
    migrate_devices()
    migrate_vrfs()
    #migrate_subnets()
