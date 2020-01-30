from intervaltree.intervaltree import IntervalTree
from types import MethodType
from threading import Event
from enum import Enum

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates, GDBTarget


def load_memory_mappings_target(target, *args, **kwargs):
    """
    Stub method for compatibility to be able to call load_memory_mappings on the
    target object.
    """
    return load_memory_mappings(target.avatar, target, *args, **kwargs)


def load_memory_mappings(avatar, target, forward=False, update=True):
    """
    Load memory maps from the specified target
    :param forward: Enable forwarding of memory to that target
    :param update:  If true, replaces avatars memory_ranges with the loaded ones
    :return:        An Intervaltree object containing the mappings
    """
    if not isinstance(target, GDBTarget):
        raise TypeError("The memory mapping can be loaded ony from GDBTargets")

    ret, resp = target.protocols.execution.get_mappings()
    lines = resp.split("\n")[4:]
    mappings = [
        {
            "start": int(x[0], 16),
            "end": int(x[1], 16),
            "size": int(x[2], 16),
            "offset": int(x[3], 16),
            "obj": x[4],
        }
        for x in [y.split() for y in lines]
    ]
    memory_ranges = IntervalTree()

    for m in mappings:
        avatar.add_memory_range(
            m["start"],
            m["size"],
            name=m["obj"],
            forwarded=forward,
            forwarded_to=target if forward else None,
            interval_tree=memory_ranges,
        )
    if update is True:
        avatar.memory_ranges = memory_ranges
    return memory_ranges


def add_methods(target):
    target.load_memory_mappings = MethodType(load_memory_mappings_target, target)


def target_added_callback(avatar, *args, **kwargs):
    target = kwargs["watched_return"]
    add_methods(target)


def add_methods(target):
    target.load_memory_mappings = MethodType(load_memory_mappings_target, target)


def target_added_callback(avatar, *args, **kwargs):
    target = kwargs["watched_return"]
    add_methods(target)


def load_plugin(avatar):
    avatar.watchmen.add_watchman(
        "AddTarget", when="after", callback=target_added_callback
    )
    avatar.load_memory_mappings = MethodType(load_memory_mappings, avatar)
    for target in avatar.targets.values():
        add_methods(target)
