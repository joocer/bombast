"""
A simple script to determine the bill of materials in terms of pypi
packages and then compare the installed version to the latest 
version available on pypi.
"""

import pkg_resources
try:
    import ujson as json
except ImportError:
    import json
from urllib.request import urlopen
from packaging import version

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


def get_latest_version(package_name):
    """
    Look up the current release from PyPi.
    """
    try:
        url = "https://pypi.org/pypi/{}/json".format(package_name)
        resp = urlopen(url)
        data = json.loads(resp.read().decode('utf8', errors='backslashreplace'))
        return (data.get('info').get('release_url').split('/')[-2])
    except:
        return 'unknown'


for package in pkg_resources.working_set:
    installed_version = package.version
    latest_version = get_latest_version(package.project_name)
    package_name = package.project_name

    if installed_version == latest_version:
        print(colors.GREEN + "✓ PASS: {} ({})".format(package_name, installed_version) + colors.END)
    else:
        print(colors.RED   + "✗ FAIL: {} ({}), latest: {}".format(package_name, installed_version, latest_version) + colors.END)