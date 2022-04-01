from setuptools import setup, find_packages
import io
import os
import sys

import xml.etree.ElementTree as ET

VERSION = '1.0.0'
NAME = 'script.akl.nvgamestream'
AUTHOR = 'chrisism'
AUTHOR_EMAIL = 'crizizz@gmail.com'
DESCRIPTION = 'Plugin and tools for connecting with Nvidia Gamestream'
PROJECT_URL = 'https://github.com/chrisism/script.akl.nvgamestream'
LICENSE = ''
LONG_DESCRIPTION = ''

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'addon.xml'), encoding='utf-8') as f:
    str_data = f.read()
    tree = ET.fromstring(str_data)
    
    NAME = tree.get('id')
    VERSION = tree.get('version').replace("~", "-")
    AUTHOR = tree.get('provider-name')
    AUTHOR_EMAIL = tree.findall('.//email')[0].text
    DESCRIPTION = tree.findall('.//description')[0].text
    PROJECT_URL = tree.findall('.//website')[0].text
    LICENSE = tree.findall('.//license')[0].text

with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()

setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    url=PROJECT_URL,
    license=LICENSE,
    package_dir={'script_akl_nvgamestream': './'},
    packages=[
        'script_akl_nvgamestream',
        'script_akl_nvgamestream.resources.lib',
        'script_akl_nvgamestream.resources.tools',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ],
    python_requires=">=3.8",
    entry_points = '''
        [console_scripts]
        create_certificates=script_akl_nvgamestream.resources.tools.create_certificates:main
        pair_with_gspc=script_akl_nvgamestream.resources.tools.pair_with_gspc:main
    '''
)