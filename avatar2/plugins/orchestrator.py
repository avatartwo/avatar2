from types import MethodType
from threading import Event
from enum import Enum

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates

watched_events = {
    'OrchestrationTransitionAdd',
    'OrchestrationTransition',
    'OrchestrationStart',
    'OrchestrationResumed',
    'OrchestrationStop',
    'OrchestrationTransitionsDisabled',
    'OrchestrationTransitionsEnabled'
}


class OrchestrationStopReason(Enum):
    STOPPING_TRANSITION_HIT = 0
    UNKNOWN_BREAKPOINT_HIT = 1
    TARGET_EXITED = 2
    USER_REQUESTED = 3


class Transition(object):
    def __init__(self, address, from_target, to_target,
                 sync_regs, synced_ranges, enabled=True,
                 max_hits=0, stop=False, hw_bkpt=False):
        self.address = address
        self.from_target = from_target
        self.to_target = to_target
        self.sync_regs = sync_regs
        self.synced_ranges = synced_ranges
        self.enabled = enabled
        self.max_hits = max_hits
        self.num_hits = 0
        self.stop = stop
        self.hw_bkpt = hw_bkpt


def update_state_callback(avatar, message, **kwargs):
    if message.state == TargetStates.EXITED and \
                    message.origin == avatar.last_target:
        avatar.stop_orchestration(
            OrchestrationStopReason.TARGET_EXITED)


def transition_callback(avatar, message, **kwargs):
    from_target = message.origin
    address = message.address

    if avatar.transitions.get((address, from_target), None) is not None:
        trans = avatar.transitions[(address, from_target)]
        if trans.enabled:
            avatar.watchmen.trigger('OrchestrationTransition', BEFORE, trans)
            avatar.transfer_state(from_target, trans.to_target,
                                  trans.sync_regs, trans.synced_ranges)
            trans.num_hits += 1
            avatar.last_target = trans.to_target
            if trans.stop == True:
                avatar.stop_orchestration(
                    OrchestrationStopReason.STOPPING_TRANSITION_HIT)
            else:
                trans.to_target.cont()
            avatar.watchmen.trigger('OrchestrationTransition', AFTER, trans)
    elif avatar.orchestration_stopped.is_set() == False:
        avatar.stop_orchestration(
            OrchestrationStopReason.UNKNOWN_BREAKPOINT_HIT)


@watch('OrchestrationTransitionAdd')
def add_transition(self, address, from_target, to_target,
                   sync_regs=True, synced_ranges=None, stop=False,
                   hw_breakpoint=False):
    if synced_ranges is None:
        synced_ranges = []
    trans = Transition(address, from_target, to_target,
                       sync_regs=sync_regs,
                       synced_ranges=synced_ranges,
                       stop=stop, hw_bkpt=hw_breakpoint)

    self.transitions[(address, from_target)] = trans


@watch('OrchestrationTransitionsEnabled')
def enable_transitions(self):
    for t in self.targets.values():
        if t.state != TargetStates.STOPPED:
            raise Exception("%s has to be stopped to enable transitions" % t)
    for t in self.transitions.values():
        t.bkptno = t.from_target.set_breakpoint(t.address, hardware=t.hw_bkpt)


@watch('OrchestrationTransitionsDisabled')
def disable_transitions(self):
    for t in self.transitions.values():
        t.from_target.remove_breakpoint(t.bkptno)


def _orchestrate(self, target, blocking=True):
    self.enable_transitions()
    self.orchestration_stopped_reason = None
    self.orchestration_stopped.clear()
    self.last_target = target

    target.cont()
    if blocking == True:
        saved_handler = self.sigint_handler
        self.sigint_handler = self.stop_orchestration
        self.orchestration_stopped.wait()
        self.sigint_handler = saved_handler


@watch('OrchestrationStart')
def start_orchestration(self, force_init=False, blocking=True):
    if self.start_target is None:
        raise Exception("No starting target specified!")
    for t in self.targets.values():
        if t.state == TargetStates.CREATED or force_init:
            t.init()

    self._orchestrate(self.start_target, blocking)


@watch('OrchestrationResumed')
def resume_orchestration(self, blocking=True):
    if self.last_target == None:
        raise Exception("No Orchestration was running before!")
    self._orchestrate(self.last_target, blocking)


@watch('OrchestrationStop')
def stop_orchestration(self, reason=OrchestrationStopReason.USER_REQUESTED):
    for t in self.targets.values():
        if t.state == TargetStates.RUNNING:
            t.stop()
    self.disable_transitions()
    self.orchestration_stopped.set()
    self.orchestration_stopped_reason = reason


def load_plugin(avatar):
    avatar.transitions = {}
    avatar.orchestration_stopped = Event()
    avatar.orchestration_stopped.set()
    avatar.orchestration_stopped_reason = None

    avatar.start_target = None
    avatar.last_target = None

    avatar.watchmen.add_watch_types(watched_events)
    avatar.watchmen.add_watchman('BreakpointHit', when=AFTER,
                                 callback=transition_callback)
    avatar.watchmen.add_watchman('UpdateState', when=AFTER,
                                 callback=update_state_callback)

    avatar.add_transition = MethodType(add_transition, avatar)
    avatar.enable_transitions = MethodType(enable_transitions, avatar)
    avatar.disable_transitions = MethodType(disable_transitions, avatar)
    avatar.start_orchestration = MethodType(start_orchestration, avatar)
    avatar.resume_orchestration = MethodType(resume_orchestration, avatar)
    avatar.stop_orchestration = MethodType(stop_orchestration, avatar)
    avatar._orchestrate = MethodType(_orchestrate, avatar)
