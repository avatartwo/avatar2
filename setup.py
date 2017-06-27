from distutils.core import setup

setup(
    name='avatar2',
    version='1.0',
    packages=['avatar2',
              'avatar2/archs',
              'avatar2/targets',
              'avatar2/protocols',
              'avatar2/peripherals',
              'avatar2/plugins',
              'avatar2/plugins/arm'
              ],
    install_requires=[
        'pygdbmi>=0.7.3.1',
        'intervaltree',
        'ipython==5.3',
        'posix_ipc>=1.0.0',
        'capstone>=3.0.4'
    ],
    url='http://www.s3.eurecom.fr/tools/avatar/',
    description='Dynamic firmware analysis'
)
