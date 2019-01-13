#!/usr/bin/env python3

# Copyright 2019 James Fleming <james@electronic-quill.net>
#
# Licensed under the GNU General Public License
# - for details, see LICENSE.txt in the top-level directory

"""
Non-OO utility functions for interacting with Syscat
"""

# Built-in modules
import re

def sanitise_uid(uid):
    "Sanitise a UID string in the same way Restagraph does"
    return re.sub('[/ ]', '_', uid)
