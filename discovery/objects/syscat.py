#!/usr/bin/env python3

# Copyright 2019 James Fleming <james@electronic-quill.net>
#
# Licensed under the GNU General Public License
# - for details, see LICENSE.txt in the top-level directory

"""
Objects and methods for interacting with a Syscat server.

Very primitive right now; no logging or real error-handling.
"""

# Third-party modules
import requests


# Local modules
from objects import syscat_utils


class Syscat:
    """
    A Syscat backend server object, with reasonable-looking defaults.
    Arguments:
    - protocol: should be either 'http' or 'https'. Default is 'http'.
    - fqdn: the Fully Qualified Domain Name (e.g. 'syscat.example.com' or 'localhost')
        or IP address for the Syscat server.
    - port: the port number on which Syscat is listening. Default is 4953.
    - uri_prefix: if Syscat is behind a proxy server and its URI is prefixed, e.g. by '/syscat',
        it goes here. If supplied, this must end in a trailing slash.
    - raw_api: the sub-uri for the raw API. Default is '/raw/v1'.
    - schema_api: the sub-uri for the schema API. Default is '/schema/v1'.
    """
    def __init__(self,
                 protocol='http',
                 fqdn='localhost',
                 port=4953,
                 uri_prefix='/',
                 raw_api='raw/v1',
                 schema_api='schema/v1'):
        self.protocol = protocol
        self.fqdn = fqdn
        self.port = port
        self.uri_prefix = uri_prefix
        self.raw_api = raw_api
        self.schema_api = schema_api


    def get_base_url(self):
        """
        Return the base URL for interacting with the backend.
        E.g: http://localhost:4953/
        """
        return self.protocol + '://' + self.fqdn + ':' + str(self.port) + self.uri_prefix


    def get_raw_api(self):
        """
        Return the URL for interacting with this server's raw API.
        E.g: http://localhost:4953/raw/v1
        """
        return self.get_base_url() + self.raw_api


    def get_schema_api(self):
        """
        Return the URL for interacting with this server's schema API.
        E.g: http://localhost:4953/schema/v1
        """
        return self.get_base_url() + self.schema_api


    def ensure_exists(self, resourcetype, uid):
        """
        Ensure that a resource exists in Syscat with that resourcetype and UID.
        Currently only deals with primary resourcetypes.
        If the resource already exists, return the parsed object.
        If it did not already exist, return None.
        """
        response = requests.get('{}/{}/{}'.format(self.get_raw_api(),
                                                  resourcetype,
                                                  syscat_utils.sanitise_uid(uid)))
        if int(response.status_code) == 200:
            return response.json()
        if int(response.status_code) == 404:
            requests.post('{}/{}'.format(self.get_raw_api(), resourcetype),
                          data={'uid': uid})
            return None
        raise RuntimeError('Backend connection failed! %s - %s' %
                           (response.status_code, response.text))


    def update_attributes(self, uri: str, attributes: dict):
        """
        Set the attributes of a resource.
        """
        requests.put('{}/{}'.format(self.get_raw_api(), uri),
                     data=attributes)


    def link_resources(self, source: str, target: str):
        "Create a link from one resource to another."
        requests.post('{}{}'.format(self.get_raw_api(), source),
                      data={'target': target})

    def store_dependent(self, uri: str, uid: str):
        "Store a dependent resource. It's up to the client to get the URI correct."
        requests.post('{}{}'.format(self.get_raw_api(), uri),
                      data={'uid': uid})
