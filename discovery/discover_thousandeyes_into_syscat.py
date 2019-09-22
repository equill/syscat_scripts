#!/usr/bin/env python3

# Copyright 2019 James Fleming <james@electronic-quill.net>
#
# Licensed under the GNU General Public License
# - for details, see LICENSE.txt in the top-level directory

"""
Perform discovery on ThousandEyes agents and tests, and import them into Syscat.
"""

# pylint: disable=wrong-import-order

# Third-party modules
from netdescribe.utils import create_logger

# Local modules
from objects.syscat import Syscat
from objects.thousandeyes import ApiServer
from objects.thousandeyes import EnterpriseClusterMember, make_agent
from objects.thousandeyes import GenericTest
from objects import syscat_utils

# Included batteries
import argparse


## Assemble it all

def process_args():
    """
    Process the CLI args.
    """
    parser = argparse.ArgumentParser(description="Discover ThousandEyes resources via the TE API.")
    # ThousandEyes (mandatory arguments first)
    parser.add_argument('--te_user',
                        action='store',
                        type=str,
                        required=True,
                        help="Username for the TE API, e.g. 'noreply@thousandeyes.com'")
    parser.add_argument('--te_key',
                        action='store',
                        type=str,
                        required=True,
                        help='Authentication key for the TE API')
    # Syscat
    parser.add_argument('--syscat_fqdn',
                        action='store',
                        type=str,
                        default='localhost',
                        help="The domain name or IP address for Syscat. Default is 'localhost'")
    parser.add_argument('--syscat_port',
                        action='store',
                        type=int,
                        default=4953,
                        help="The port number on which Syscat is listening. Default is 4953.")
    # General
    parser.add_argument('--loglevel',
                        action='store',
                        type=str,
                        required=False,
                        default='info',
                        help="Syslog level for logging. Default is 'info'.")
    return parser.parse_args()

def main(args):
    "Replicate ThousandEyes data to Syscat"
    # Setup and configuration
    logger = create_logger(loglevel=args.loglevel)
    te_api = ApiServer(username=args.te_user, api_key=args.te_key)
    syscat = Syscat(fqdn=args.syscat_fqdn, port=args.syscat_port)
    ## Agents
    logger.info('Retrieving a list of agents from ThousandEyes')
    agents = map(lambda x: make_agent(x, logger),
                 te_api.get_list('agents')['agents'])
    # Individual agents
    for agent in agents:
        logger.info('Adding {} {} with agent ID {}'.format(agent.syscat_type,
                                                           agent.agentname,
                                                           agent.agentid))
        agent.store_in_syscat(syscat)
        if agent.syscat_type == 'thousandeyesEnterpriseClusters':
            # Add cluster members
            details = te_api.get_details('agents', agent.agentid)['agents'][0]
            logger.debug('agent details: {}'.format(details))
            logger.info('Enumerating members')
            for member in details['clusterMembers']:
                logger.debug('clusterMember details: {}'.format(member))
                logger.info('Adding clusterMember {}'.format(member['name']))
                EnterpriseClusterMember(name=member['name'],
                                        ipaddresses=member['ipAddresses'],
                                        publicipaddresses=member['publicIpAddresses'],
                                        prefix=member['prefix'],
                                        network=member['network'],
                                        agentstate=member['agentState']).store_in_syscat(
                                            syscat, agent)
            # Add tests
            logger.info('Enumerating tests')
            for test in details['tests']:
                logger.debug('Test details: {}'.format(test))
                logger.info('Adding test {}'.format(test['testName']))
                if 'modifiedBy' not in test:
                    test['modifiedBy'] = ''
                if 'modifiedDate' not in test:
                    test['modifiedDate'] = ''
                GenericTest(testname=test['testName'],
                            testid=test['testId'],
                            test_type=test['type'],
                            enabled=test['enabled'],
                            savedevent=test['savedEvent'],
                            interval=test['interval'],
                            modifiedby=test['modifiedBy'],
                            modifieddate=test['modifiedDate'],
                            createdby=test['createdBy'],
                            createddate=test['createdDate']).store_in_syscat(syscat)
                syscat.link_resources(
                    '/{ttype}/{tuid}/Agents'.format(
                        ttype='thousandeyesTests',
                        tuid=syscat_utils.sanitise_uid(test['testName'])),
                    '/{atype}/{auid}'.format(atype=agent.syscat_type,
                                             auid=syscat_utils.sanitise_uid(agent.agentname)))

if __name__ == '__main__':
    main(process_args())
