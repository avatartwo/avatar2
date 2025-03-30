import logging

from intervaltree.intervaltree import IntervalTree
from types import MethodType
from threading import Event
from enum import Enum

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates, GDBTarget

l = logging.getLogger('avatar2.gdbplugin')


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

    memory_ranges = IntervalTree()
    try:
        lines = resp.split("\n")

        # First, find where the actual data starts
        header_index = None
        for i, line in enumerate(lines):
            if "Start Addr" in line:
                header_index = i
                break

        if header_index is None:
            l.critical("Could not find 'Start Addr' in GDB output")
            return memory_ranges

        data_start_index = header_index + 1  # Skip column names

        mappings = []
        for i in range(data_start_index, len(lines)):
            line = lines[i].strip()
            if not line:  # skip empty lines
                continue

            parts = line.split()
            if len(parts) >= 5:  # check we have all required fields
                try:
                    mapping = {
                        "start": int(parts[0], 16),
                        "end": int(parts[1], 16),
                        "size": int(parts[2], 16),
                        "offset": int(parts[3], 16),
                        "obj": parts[4],
                    }
                    mappings.append(mapping)
                except (ValueError, IndexError) as e:
                    l.warning(f"Failed to parse mapping line: {line} - Error: {e}")

        l.debug(f"Parsed {len(mappings)} memory mappings")

        for m in mappings:
            avatar.add_memory_range(
                m["start"],
                m["size"],
                name=m["obj"],
                forwarded=forward,
                forwarded_to=target if forward else None,
                interval_tree=memory_ranges,
            )
    except Exception as e:
        update = False
        l.error(f"Exception during memory mapping parsing: {e}")

    if update is True:
        avatar.memory_ranges = memory_ranges

    return memory_ranges


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
