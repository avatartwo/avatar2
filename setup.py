from distutils.core import setup, Extension

segment_registers = Extension('segment_registers',
                          sources=['avatar2/plugins/x86/segment_registers.c'],
                          extra_compile_args = ["-fno-stack-protector"]
                             )

setup(
    name='avatar2',
    version='1.01',
    packages=['avatar2',
              'avatar2/archs',
              'avatar2/targets',
              'avatar2/protocols',
              'avatar2/peripherals',
              'avatar2/plugins',
              'avatar2/plugins/arm',
              'avatar2/plugins/x86'
              ],
    install_requires=[
        'pygdbmi>=0.7.3.1',
        'intervaltree',
        'ipython==5.3',
        'posix_ipc>=1.0.0',
        'capstone>=3.0.4',
        'keystone-engine',
        'parse',
    ],
    package_data={'avatar2/plugins/x86': ['avatar_fs.so']},
    url='http://www.s3.eurecom.fr/tools/avatar/',
    description='Dynamic firmware analysis',
    ext_modules=[segment_registers]
)
