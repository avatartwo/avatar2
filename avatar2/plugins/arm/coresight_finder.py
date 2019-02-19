from types import MethodType
from threading import Event
from enum import Enum
import logging

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2.archs import ARM, ARMBE
from avatar2 import TargetStates

# From the ARM CoreSight Architecture Specification v2.0
component_id_registers = {
    'CIDR0': 0xff0,
    'CIDR1': 0xff4,
    'CIDR2': 0xff8,
    'CIDR3': 0xffc
}

device_type_register_offset = 0xFCC

device_types = {
    0x0: ("Miscellaneus", {
        0x0: "Other, unidentified",
        0x1: "Validation component"}),
    0x1: ("Trace Sink", {
        0x0: "Other",
        0x1: "Trace port, for example TPIU",
        0x2: "Buffer, for example ETB",
        0x3: "Basic trace router"}),
    0x2: ("Trace Link", {
        0x0: "Other",
        0x1: "Trace funnel, Router",
        0x2: "Filter",
        0x3: "FIFO, Large Buffer"}),
    0x3: ("Trace Source", {
        0x0: "Other",
        0x1: "Associated with a processor core",
        0x2: "Associated with a DSP",
        0x3: "Associated with a Data Engine or Coprocessor",
        0x4: "Associated with a Bus, stimulus derived from bus activity",
        0x6: "Associated with software, stimulus derived from software activity"}),
    0x4: ("Debug Control", {
        0x0: "Other",
        0x1: "Trigger Matrix, for example ECT",
        0x2: "Debug Authentication Module",
        0x3: "Power requestor"}),
    0x5: ("Debug Logic", {
        0x0: "Other",
        0x1: "Processor core",
        0x2: "DSP",
        0x3: "Data Engine or Coprocessor",
        0x4: "Bus, stimulus derived from bus activity",
        0x5: "Memory, tightly coupled device such as Built In Self Test (BIST)"}),
    0x6: ("Performance monitor", {
        0x0: "Other",
        0x1: "Associated with a processor",
        0x2: "Associated with a DSP",
        0x3: "Associated with a Data Engine or Coprocessor",
        0x4: "Associated with a bus, stimulus derived from bus activity",
        0x5: ("Associated with a memory management unit that"
              + "conforms to the ARM System MMU Architecture")})
}


def read_id_registers(target, base_address):
    return dict((name, target.rm(base_address + offset, size=4)) for
                name, offset in component_id_registers.items())


def parse_coresight_type(device_type):
    maj_value = device_type & 0x7
    sub_value = (device_type >> 4) & 0x7
    return (device_types[maj_value][0],
            device_types[maj_value][1][sub_value])


def find_coresight_magic_value(avatar, message):
    if message.value != 0xC5ACCE55 or message.size != 4:
        return

    log = logging.getLogger('avatar')
    base_address = message.address & 0xfffff000
    log.info("Detected possible ARM Coresight Debug component" +
             "at address 0x%x" % base_address)
    target = avatar.get_memory_range(base_address).forwarded_to

    regs_value = read_id_registers(target, base_address)
    if (regs_value['CIDR0'] != 0xD
        or regs_value['CIDR1'] != 0x90
        or regs_value['CIDR2'] != 0x5
        or regs_value['CIDR3'] != 0xB1):
        log.info("Detecting Coresight component: False positive")
        return

    device_type = target.rm(base_address + device_type_register_offset, size=4)
    log.info("Device type 0x%x" % (device_type))
    (maj, sub) = parse_coresight_type(device_type)
    log.info("Detected Coresight component. Major type: %s. Sub type: %s"
             % (maj, sub))


def load_plugin(avatar):
    if avatar.arch not in [ARM, ARMBE]:
        log = logging.getLogger('avatar')
        log.warning("Coresight components are part of the ARM architecture.")

    avatar.watchmen.add_watchman('RemoteMemoryWrite', when=BEFORE,
                                 callback=find_coresight_magic_value,
                                 is_async=True)
