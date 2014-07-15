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


wildcard_injection_os_command_re = re.compile(
      r".*?(?:system|popen|Popen).*?(?:chown|chmod|tar|rsync).*?\*")

promiscous_file_perm_oct_re = re.compile(
    r".*chmod\((.*0o{0,1}[0-7][0-7][2367])\)")

promiscous_file_perm_stat_re = re.compile(
    r".*chmod\(.*(stat.S_IWOTH|stat.S_IRWXO).*\)")


@core.flake8ext
def sec_shell_eq_true(logical_line):
    """Check for shell injection vulnerabilities in subprocess calls

    S001
    """
    line_no_sp = logical_line.replace(' ', '')
    if 'shell=True' in line_no_sp and 'Popen' in line_no_sp:
        yield(0, "S001: Security risk: use of shell=True in Popen call.")


@core.flake8ext
def sec_chmod_perms(logical_line):
    """Check for promiscuous file permissions in chmod calls

    S002
    """
    re_oct_check = promiscous_file_perm_oct_re.match(logical_line)
    re_stat_check = promiscous_file_perm_stat_re.match(logical_line)
    if re_oct_check:
        yield (0, "S002: Chmod with dangerous file permissions: " +
               re_oct_check.group() + ".")
    if re_stat_check:
        yield (0, "S002: Chmod with dangerous file permissions: " +
               re_stat_check.group() + ".")


@core.flake8ext
def hacking_creating_temp_file_or_dir(logical_line):
    """Check for use of tempfile or mktemp

    S004
    """
    if (('tempfile.mktemp' in logical_line) or
           ('mktemp' in logical_line)):
        yield (0, "S004: Creating temporary file or directory")


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
    Check for default passwords, or where not: password='%s'
    """
    blank = re.compile(r".*password\s*=\s*['\"]['\"].*")
    default = re.compile(r".*password\s*=\s*['\"](?!%s)")
    if not blank.match(logical_line) and default.match(logical_line):
        yield(0, "S007: use of default password is not allowed")


@core.flake8ext
def sec_wildcard_injection(logical_line, physical_line):
    """Check for wildcard injection vulnerabilities - OS commands with
    unexpected wildcard expansion behavior.  Please see link:
    http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt

    S008
    """
    line_no_sp = physical_line.replace(' ', '')
    res = wildcard_injection_os_command_re.match(line_no_sp)
    if res:
        yield (0, "S008: Wildcard injection vulnerability with OS command")


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


@core.flake8ext
def hacking_check_vulnerable_ssl(logical_line):
    """
    Check for vulnerable SSL
    """
    vuln_protos = ['PROTOCOL_SSLv2', 'PROTOCOL_SSLv23', 'PROTOCOL_SSLv3']
    for proto in vuln_protos:
        if proto in logical_line:
            yield(0, "S014: Vulnerable SSL Protocol")
