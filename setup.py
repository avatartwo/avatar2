from setuptools import setup
from sys import version_info


setup(
    name='avatar2',
    version='1.1.1',
    packages=['avatar2',
              'avatar2/archs',
              'avatar2/targets',
              'avatar2/protocols',
              'avatar2/peripherals',
              'avatar2/plugins',
              'avatar2/plugins/arm',
              'avatar2/installer'
              ],
    install_requires=[
        'pygdbmi>=0.7.3.1',
        'intervaltree',
        'posix_ipc>=1.0.0',
        'capstone>=3.0.4',
        'keystone-engine',
        'parse',
        'configparser',
        'npyscreen',
        'enum34',
        'bitstring'
    ],
    dependency_links=[
        'https://github.com/jonathanslenders/python-prompt-toolkit/tarball/2.0#egg=prompt-toolkit-2.0.0'
    ],
    url='http://www.s3.eurecom.fr/tools/avatar/',
    description='Dynamic firmware analysis'
)
