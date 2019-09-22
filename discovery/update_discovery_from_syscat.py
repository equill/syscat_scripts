#!/usr/bin/env python3

#   Copyright [2017] [James Fleming <james@electronic-quill.net]
#
# Licensed under the GNU General Public License
# - for details, see LICENSE.txt in the top-level directory

"""
Perform discovery on all devices in Syscat with a management address.
"""

# pylint: disable=wrong-import-order

# Third-party modules
from netdescribe.utils import create_logger
import requests

# Local modules
import discover_devices_into_syscat

# Included batteries
import argparse
import json
import logging


def jsonify(data):
    "Pretty-print a data structure in JSON, for output to logs."
    return json.dumps(data, indent=4, sort_keys=True)

def discover_device(syscat_url, community, logger, device):
    """
    Perform discovery on a single device
    """
    logger.debug('Attempting to perform discovery on {}'.format(jsonify(device)))
    response = requests.get('{url}/raw/v1/devices/{host}/ManagementAddress'.format(
        url=syscat_url, host=device['uid']))
    if response.status_code == 200:
        addr = response.json()[0]['uid']
        logger.info('Discovering {host} at address {addr}'.format(host=device['uid'],
                                                                  addr=addr))
        discover_devices_into_syscat.discover_into_syscat(addr,
                                                          device['uid'],
                                                          snmpcommunity=community,
                                                          logger_arg=logger)
    else:
        logger.debug('No admin address found for {}'.format(device['uid']))

def main(syscat_url, community, loglevel=logging.INFO):
    """
    Wrapper around discover_into_syscat.
    """
    logger = create_logger(loglevel=loglevel)
    logger.info('Beginning discovery')
    response = requests.get('{}/raw/v1/devices'.format(syscat_url))
    if response.status_code == 200:
        for device in response.json():
            discover_device(syscat_url, community, logger, device)
    else:
        logger.error('Initial query failed: {} - {}'.format(response.status_code,
                                                            response.text))

def process_cli():
    """
    Handle CLI invocation.
    """
    # Get the command-line arguments
    parser = argparse.ArgumentParser(description='Perform SNMP discovery on all hosts \
    in Syscat with a management address.')
    parser.add_argument('--syscat_url',
                        action='store',
                        type=str,
                        default='http://localhost:4950',
                        help='The base URL for Syscat, e.g. http://localhost:4950')
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
    main(args.syscat_url, args.community, loglevel=loglevel)

if __name__ == "__main__":
    process_cli()
