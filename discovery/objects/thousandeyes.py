#!/usr/bin/env python3

# Copyright 2019 James Fleming <james@electronic-quill.net>
#
# Licensed under the GNU General Public License
# - for details, see LICENSE.txt in the top-level directory

"""
Objects and methods for interacting with ThousandEyes.

Very primitive right now; no logging or real error-handling.
"""


# pylint: disable=wrong-import-order

# Third-party libraries
import requests
from objects.syscat import Syscat

# Local modules
from objects import syscat_utils

# Included batteries
import collections
from datetime import datetime


## Helpful data structures

ClusterDetails = collections.namedtuple('cluster_details',
                                        ['clustermembers',
                                         'tests'])


## Utility functions

def parse_te_datestring(datestr):
    """
    Convert a ThousandEyes datestamp into a dateutils object.
    Assumes the documented createddate/modifieddate format 2013-05-11 02:02:21
    """
    return datetime.strptime(datestr, "%Y-%m-%d %H:%M:%S").timestamp()


## API Server

class ApiServer:
    """
    The ThousandEyes API server, including authentication credentials.
    """
    def __init__(self, username, api_key):
        self.base_url = 'https://api.thousandeyes.com/v6'
        self.username = username
        self.api_key = api_key

    def get_list(self, endpoint):
        """
        Retrieve a list of items from a ThousandEyes endpoint, e.g. /tests.
        Return the parsed response as a Python object.
        On failure, return None.
        """
        response = requests.get('{}/{}.json'.format(self.base_url, endpoint),
                                auth=(self.username, self.api_key))
        if int(response.status_code) == 200:
            return response.json()
        return None

    def get_details(self, endpoint: str, uid: int):
        """
        Retrieve the details of an individual thing from the API Server.
        Return the parsed response as a Python object.
        On failure, return None.
        """
        response = requests.get('{}/{}/{}.json'.format(self.base_url, endpoint, uid),
                                auth=(self.username, self.api_key))
        if int(response.status_code) == 200:
            return response.json()
        return None


## Agents

class GenericAgent:
    """
    Base class for TE agents.
    """
    # The Syscat resourcetype for this class
    syscat_type = 'thousandeyesAgents'

    def __init__(self, agentid, agentname, countryid, location):
        self.agentid = agentid
        self.agentname = agentname
        self.countryid = countryid
        self.location = location

    def store_in_syscat(self, server: Syscat):
        """
        Store this object in the supplied Syscat server.
        """
        # Ensure there's an entry for it
        server.ensure_exists(self.syscat_type, self.agentname)
        # Ensure its attributes match the ones we have,
        # remembering that Syscat doesn't have an agentid attribute for these.
        server.update_attributes('/{}/{}'.format(self.syscat_type, self.agentname),
                                 self.__dict__)

class CloudAgent(GenericAgent):
    """
    ThousandEyes Cloud Agent.
    Attributes are already covered by GenericAgent.
    """
    syscat_type = 'thousandeyesCloudAgents'

class EnterpriseCluster(GenericAgent):
    """
    ThousandEyes Enterprise Cluster.
    """
    syscat_type = 'thousandeyesEnterpriseClusters'

    # pylint: disable=too-many-arguments
    def __init__(self,
                 agentid,
                 agentname,
                 countryid,
                 enabled,
                 location,
                 verifysslcertificates,
                 keepbrowsercache,
                 ipv6policy):
        super().__init__(agentid, agentname, countryid, location)
        self.enabled = enabled
        self.verifysslcertificates = verifysslcertificates
        self.keepbrowsercache = keepbrowsercache
        self.ipv6policy = ipv6policy

    def get_details(self, api: ApiServer):
        "Fetch detailed information about this cluster."
        response = api.get_details(endpoint='agents', uid=int(self.agentname))['agents'][0]
        return ClusterDetails(clustermembers=response['clusterMembers'],
                              tests=response['tests'])


class EnterpriseAgent(EnterpriseCluster):
    """
    ThousandEyes Enterprise Agent.
    """
    syscat_type = 'thousandeyesEnterpriseAgents'

    # pylint: disable=too-many-arguments
    def __init__(self,
                 agentid,
                 agentname,
                 countryid,
                 hostname,
                 prefix,
                 enabled,
                 location,
                 network,
                 agentstate,
                 verifysslcertificates,
                 keepbrowsercache,
                 ipv6policy):
        super().__init__(agentid,
                         agentname,
                         countryid,
                         enabled,
                         location,
                         verifysslcertificates,
                         keepbrowsercache,
                         ipv6policy)
        self.hostname = hostname
        self.prefix = prefix
        self.network = network
        self.agentstate = agentstate


def make_agent(agent, logger):
    """
    Create a ThousandEyes agent from data retrieved from the /agents endpoint.
    """
    # Cloud agents
    if agent['agentType'] == 'Cloud':
        return CloudAgent(agentid=agent['agentId'],
                          agentname=agent['agentName'],
                          countryid=agent['countryId'],
                          location=agent['location'])
    if agent['agentType'] == 'Enterprise Cluster':
        return EnterpriseCluster(agentid=agent['agentId'],
                                 agentname=agent['agentName'],
                                 countryid=agent['countryId'],
                                 enabled=agent['enabled'],
                                 location=agent['location'],
                                 verifysslcertificates=agent['verifySslCertificates'],
                                 keepbrowsercache=agent['keepBrowserCache'],
                                 ipv6policy=agent['ipv6Policy'])
    if agent['agentType'] == 'Enterprise':
        return EnterpriseAgent(agentid=agent['agentId'],
                               agentname=agent['agentName'],
                               countryid=agent['countryId'],
                               enabled=agent['enabled'],
                               location=agent['location'],
                               hostname=agent['hostname'],
                               prefix=agent['prefix'],
                               network=agent['network'],
                               agentstate=agent['agentState'],
                               verifysslcertificates=agent['verifySslCertificates'],
                               keepbrowsercache=agent['keepBrowserCache'],
                               ipv6policy=agent['ipv6Policy'])
    logger.error('Unrecognised agent type: {}'.format(agent['agentType']))
    return None


class EnterpriseClusterMember:
    """
    A member of a cluster, which has no agentid of its own
    """
    syscat_type = 'thousandeyesEnterpriseClusterMembers'

    # pylint: disable=too-many-arguments
    def __init__(self, name, ipaddresses, publicipaddresses, prefix, network, agentstate):
        self.name = name
        self.ipaddresses = ipaddresses
        self.publicipaddresses = publicipaddresses
        self.prefix = prefix
        self.network = network
        self.agentstate = agentstate

    def store_in_syscat(self, server: Syscat, parentcluster: EnterpriseCluster):
        "Store this clustermember in Syscat"
        pathroot = '/{parenttype}/{parentuid}/Member/{mytype}'.format(
            parenttype=parentcluster.syscat_type,
            parentuid=syscat_utils.sanitise_uid(parentcluster.agentname),
            mytype=self.syscat_type)
        server.store_dependent(pathroot, self.name)
        server.update_attributes('{pathroot}/{myuid}'.format(
            pathroot=pathroot,
            myuid=syscat_utils.sanitise_uid(self.name)),
                                 self.__dict__)


## Tests

# pylint: disable=too-many-instance-attributes
class GenericTest:
    """
    A basic type of TE test, to be used where we either don't know for sure what type it is,
    or don't yet have a class for that type of test.
    """
    syscat_type = 'thousandeyesTests'

    # pylint: disable=too-many-arguments
    def __init__(self,
                 testname,
                 testid,
                 test_type,
                 enabled,
                 savedevent,
                 interval,
                 modifiedby,
                 modifieddate,
                 createdby,
                 createddate):
        self.testname = testname
        self.testid = testid
        self.test_type = test_type
        self.enabled = enabled
        self.savedevent = savedevent
        self.interval = interval
        self.modifiedby = modifiedby
        self.modifieddate = modifieddate
        self.createdby = createdby
        self.createddate = createddate

    def store_in_syscat(self, server: Syscat):
        "Store this test in Syscat"
        result = server.ensure_exists(self.syscat_type, self.testname)
        if parse_te_datestring(self.createddate) > parse_te_datestring(result['createddate']):
            server.update_attributes('/{ttype}/{uid}'.format(
                ttype=self.syscat_type, uid=syscat_utils.sanitise_uid(self.testname)),
                                     self.__dict__)
