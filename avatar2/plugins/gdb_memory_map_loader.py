from types import MethodType
from threading import Event
from enum import Enum

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates, GDBTarget

def load_memory_mappings(avatar, target, forward=False):
    if not isinstance(target, GDBTarget):
        raise TypeError('The memory mapping can be loaded ony from GDBTargets')

    ret, resp = target.protocols.execution.get_mappings()
    lines = resp.split('\n')[4:]
    mappings = [{'start': int(x[0], 16), 'end': int(x[1], 16),
                 'size': int(x[2], 16), 'offset': int(x[3], 16),
                 'obj': x[4]}
                for x in [y.split() for y in lines]]
    for m in mappings:
        avatar.add_memory_range(m['start'], m['size'], name=m['obj'],
                                forwarded=forward,
                                forwarded_to=target if forward else None)

def load_plugin(avatar):
    avatar.load_memory_mappings = MethodType(load_memory_mappings, avatar)
