from configparser import ConfigParser
from distutils.dir_util import mkpath
from os.path import expanduser, realpath, dirname, exists
from distutils.spawn import find_executable as find
from collections import OrderedDict

CONFIG_FILE = expanduser('~/.avatar2/settings.cfg')

# Constant names for the different targets
OPENOCD = 'openocd'
QEMU = 'avatar-qemu'
PANDA = 'avatar-panda'
GDB_ARM = 'gdb (ARM)'
GDB_X86 = 'gdb (x86)' 


TARGETS = OrderedDict(
    [
    (OPENOCD, { 'git': 'https://git.code.sf.net/p/openocd/code',
               'configure': '',
               'make': '',
               'rel_path': 'src/openocd',
               'install_cmd': ['./bootstrap','./configure','make'],
               'apt_name': 'openocd'
             }),
    (QEMU, {  'git': 'https://github.com/avatartwo/avatar-qemu',
             'configure': '--disable-sdl --target-list=arm-softmmu',
             'make': '',
             'rel_path': 'arm-softmmu/qemu-system-arm',
             'install_cmd': ['git submodule update --init dtc',
                             './configure', 'make'],
          }),
    (PANDA, {'git': 'https://github.com/avatartwo/avatar-panda',
             'configure': '--disable-sdl --target-list=arm-softmmu',
             'make': '',
             'rel_path': 'arm-softmmu/qemu-system-arm',
             'install_cmd': ['git submodule update --init dtc',
                             './configure', 'make'],
           }),
    (GDB_X86, { 'apt_name': 'gdb' }),
    (GDB_ARM, { 'apt_name': 'gdb-arm-none-eabi',
               'sys_name': 'arm-none-eabi-gdb'})
    ]
)


class AvatarConfig(ConfigParser):
    

    def __init__(self):
        super(AvatarConfig, self).__init__()
        self.config_file = realpath(expanduser(CONFIG_FILE))
        self.config_path = dirname(self.config_file)

        mkpath(expanduser(self.config_path)) # create config dir if neccessary

        # Create a default config if there's no config file yet
        if self.read(expanduser(CONFIG_FILE)) == []:
            self.add_section('DIST')
            self.add_section('TARGETS')

            has_apt = 'True' if find('apt-get') else 'False'
            self.set('DIST', 'has_apt', has_apt)
            self.set('DIST', 'default_install_path', self.config_path+'/')

            for t_name, t_dict in TARGETS.items():
                path = t_dict.get('sys_name', t_dict.get('apt_name', 'None'))
                full_path = find(path) or 'None'
                self.set('TARGETS', t_name, full_path) 


    def write_config(self):
        with open(expanduser(CONFIG_FILE), 'w+') as cfgfile:
            self.write(cfgfile)


    def get_target_path(self, target):
        if self.has_section('TARGETS'):
            target_path = self.get('TARGETS', target)
            return None if target_path == 'None' else target_path
