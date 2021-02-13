"""
bombast: currency checker

https://github.com/joocer/bombast

(C) 2021 Justin Joyce.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""
A simple script to determine the bill of materials in terms of installed
pypi packages and then compare the installed version to the latest 
version available on pypi and components with vulnerabilities from data
from pyup.
"""

import pkg_resources
import requests
from packaging import version
from pkg_resources import parse_version
import json
import sys


COMPARATORS = {
    '<':  lambda x, y: x < y,
    '<=': lambda x, y: x <= y,
    '>':  lambda x, y: x > y,
    '>=': lambda x, y: x >= y,
    '=':  lambda x, y: x == y
}

def get_known_vulns():
    """
    Look up known vulns from PyUp.io
    """
    try:
        url = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
        resp = requests.get(url)
        data = resp.json()
        return data
    except:
        return 'unknown'

def get_latest_version(package_name):
    try:
        url = "https://pypi.org/pypi/{}/json".format(package_name)
        resp = requests.get(url)
        data = resp.json()
        return (data.get('info').get('release_url').split('/')[-2])
    except:
        return 'unknown'

def compare_versions(version_a, version_b):
    # default to equals
    operator = COMPARATORS['=']

    # find if it's a different operator
    find_operator = [c for c in COMPARATORS if version_a.startswith(c)]
    if len(find_operator):
        s = find_operator[0]
        operator = COMPARATORS[s]
        version_a = version_a.lstrip(s)

    return operator(parse_version(version_b), parse_version(version_a))


def get_package_summary(package=None,
                installed_version=None,
                vuln_details={}):

    result = { 
        "package": package,
        "installed_version": installed_version,
        "state": "OKAY"
    }
    result['latest_version'] = get_latest_version(package_name=package)
    if result['latest_version'] != result['installed_version']:
        if result['latest_version'] != 'unknown':
            result['state'] = "STALE"
        else:
            result['state'] = "UNKNOWN"

    if vuln_details:
        for i in vuln_details:

                for version_pairs in i['specs']:
                    versions = version_pairs.split(',')
                    if len(versions) == 1:
                        versions = ['>0'] + versions

                    if compare_versions(versions[0], installed_version) and compare_versions(versions[1], installed_version):
                        result['state'] = "VULNERABLE"
                        result['cve'] = i.get('cve')
                        result['reference'] = i.get('id')

    return result

def main():

    results = []

    known_vulns = get_known_vulns()
    for package in pkg_resources.working_set:

        package_result = get_package_summary(package=package.project_name,
                    installed_version=package.version,
                    vuln_details=known_vulns.get(package.project_name))

        results.append(package_result['state'])
        if package_result['state'] != 'OKAY':
            print(package_result)


    print(F"\n{len(results)} Python components found")
    print(F"{results.count('VULNERABLE')} with security weaknesses")
    print(F"{results.count('STALE')} stale")
    print(F"{results.count('UNKNOWN')} unable to determine the state of")

    total_results = len(results)
    if results.count('VULNERABLE') > 0:
        print('MORE THAN ZERO COMPONENTS WITH SECURITY WEAKNESSES')
        sys.exit(1)

    if results.count('STALE') > (total_results * 0.2):
        print('MORE THAN 20% OF COMPONENTS ARE STALE')
        sys.exit(1)


main()
