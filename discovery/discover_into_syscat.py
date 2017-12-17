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
import netdescribe
import requests

# From this package
import netdescribe.snmp.device_discovery
from netdescribe.utils import create_logger

# Included batteries
import argparse
import json
import sys


def discover_into_syscat_v1(address,        # IP address, FQDN or otherwise resolvable address
                            name=None,      # Name of target device, to override the discovered one
                            snmpcommunity="public",
                            syscat_url="http://localhost:4950", # Default base URL for syscat
                            loglevel="info" # Default loglevel
                           ):
    """
    Ensure that there's an entry in Syscat for the device we just discovered.
    Does not update existing instances.
    Assumes version 1 of the Syscat API.
    """
    # Create the logger
    logger = create_logger(loglevel=loglevel)
    logger.info("Performing discovery on device at %s", address)
    # Resolve the device's UID
    if name:
        uid = name
    else:
        uid = address
    logger.debug("Using name '%s' for device", uid)
    # Perform discovery
    device = netdescribe.snmp.device_discovery.explore_device(address, logger, snmpcommunity)
    logger.debug("Result of discovery was:\n%s", json.dumps(device, indent=4))
    # Is it already there?
    response = requests.get("%s/raw/v1/devices/%s" % (syscat_url, uid))
    # No existing entry; create one
    if response.status_code == 404:
        creation_url = "%s/raw/v1/devices" % syscat_url
        logger.debug("%s is not present in Syscat; creating it at URL %s.", uid, creation_url)
        # Create the device entry itself
        c_response = requests.post(creation_url,
                                   data={'uid': uid,
                                         'sysName': device['sysinfo']['sysName'],
                                         'sysDescr': device['sysinfo']['sysDescr']})
        # Success!
        if c_response.status_code == 201:
            logger.info("Successfully created device %s", uid)
        # Not success!
        else:
            logger.error("Device not created: %s %s", c_response.status_code, c_response.text)
    # We already have one of these; log the fact and do nothing
    elif response.status_code == 200:
        logger.debug("%s is already present in Syscat", uid)
    # Something else happened.
    else:
        logger.critical("Syscat returned an unexpected result: %s %s",
                        response.status_code, response.text)
        sys.exit(1)


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
                            snmpcommunity=args.community,
                            loglevel=loglevel)

if __name__ == "__main__":
    process_cli()
