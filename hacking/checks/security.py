#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from hacking import core
import re


@core.flake8ext
def hacking_no_pickle(logical_line):
    """Check for use of pickle

    S006
    """
    if 'import pickle' in logical_line:
        yield (0, "S006: use of pickle not allowed")


@core.flake8ext
def hacking_no_inline_passwords(logical_line):
    """
    S007
    Check for any default passwords, or where not: password='%s'
    """
    if re.compile(r".*password\s*=\s*['\"](?!%s)").match(logical_line):
        yield(0, "S007: use of default password is not allowed")


@core.flake8ext
def hacking_service_binding_all_interfaces(logical_line, physical_line):
    """Check for use of pickle

    S009
    """
    #TODO: Check for pecan default bind
    #TODO: Check for eventlet default bind
    if 'eventlet.listen' in logical_line:
        if '0.0.0.0' in physical_line:
            yield (0, "S009: binding to all interfaces")
    if 'host' in logical_line:
        if '0.0.0.0' in physical_line:
            yield (0, "S009: binding to all interfaces")
    if 'bind' in logical_line:
        if '0.0.0.0' in physical_line:
            yield (0, "S009: binding to all interfaces")
