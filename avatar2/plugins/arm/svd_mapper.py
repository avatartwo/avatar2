from types import MethodType

import logging

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2.archs import ARM, ARMBE

from cmsis_svd.parser import SVDParser

def load_svd(self, vendor, file):
    parser = SVDParser.for_packaged_svd(vendor, file)
    for peripheral in parser.get_device().peripherals:
        p_dict = peripheral.to_dict()
        base_addr = p_dict['base_address']
        size = int(p_dict['address_block']['size']) -1 #hackhack
        name = peripheral.name
        self.add_memory_range(base_addr, size)



def load_plugin(avatar):
    if avatar.arch not in [ARM, ARMBE]:
        log = logging.getLogger('avatar')
        log.warning("SVD-reader requires an ARM core")

    avatar.load_svd = MethodType(load_svd, avatar)
