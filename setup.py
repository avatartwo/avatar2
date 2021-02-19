from setuptools import setup
from sys import version_info


setup(
    name='avatar2',
    version='1.4.1',
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
        'pygdbmi==0.9.0.2;python_version<="3.5"',
        'pygdbmi>=0.10.0.0;python_version>"3.5"',
        'intervaltree',
        'posix_ipc>=1.0.0',
        'capstone>=3.0.4',
        'keystone-engine',
        'parse',
        'configparser',
        'npyscreen',
        'enum34;python_version<"3.4"',
        'unicorn',
        'bitstring',
        'pylink-square',
        'pyusb',
    ],
    include_package_data=True,
    url='https://github.com/avatartwo/avatar2',
    description='A Dynamic Multi-Target Orchestration Framework',
    maintainer='Marius Muench',
    maintainer_email='marius.muench@eurecom.fr'
)
