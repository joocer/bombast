"""
A simple script to determine the bill of materials in terms of pypi
packages and then compare the installed version to the latest 
version available on pypi.
"""

import pkg_resources
import requests
from packaging import version
from pkg_resources import parse_version
import json


class colors:
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    GREY = '\033[90m'

    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
    #try:
    #url = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
    #resp = requests.get(url)
    #data = resp.json()
    data = json.load(open('insecure_full.json', 'r'))
    return data
    #except:
    #    return 'unknown'

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
        result['state'] = "STALE"

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

        #if package.project_name != 'lxml': continue
        package_result = get_package_summary(package=package.project_name,
                    installed_version=package.version,
                    vuln_details=known_vulns.get(package.project_name))

        print(package_result)

       # if installed_version == latest_version:
       #     print(colors.GREEN + "✓ PASS: {} ({})".format(package_name, installed_version) + colors.END)
       # else:
       #     print(colors.YELLOW   + "✗ STALE: {} ({}), latest: {}".format(package_name, installed_version, latest_version) + colors.END)

#    print(results)


main()
