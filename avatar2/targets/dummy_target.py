# Author: Davide Balzarotti <davide.balzarotti@eurecom.fr>
# Creation Date: 04-04-2017

import random
import threading
import time

from avatar2.message import RemoteMemoryReadMessage, BreakpointHitMessage, UpdateStateMessage
from avatar2.targets import Target, TargetStates


class _TargetThread(threading.Thread):
    """Thread that mimics a running target"""

    def __init__(self, target):
        threading.Thread.__init__(self)
        self.target = target
        self.please_stop = False
        self.steps = 0

    def run(self):
        self.please_stop = False
        # Loops until someone (the Dummy Target) tells me to stop by 
        # externally setting the "please_stop" variable to True 
        while not self.please_stop:
            self.target.log.info("Dummy target doing Nothing..")
            time.sleep(1)
            self.steps += 1
            # 10% chances of triggering a breakpoint
            if random.randint(0, 100) < 10:
                # If there are not breakpoints set, continue
                if len(self.target.bp) == 0:
                    continue
                # Randomly pick one of the breakpoints
                addr = random.choice(self.target.bp)
                self.target.log.info("Taking a break..")
                # Add a message to the Avatar queue to trigger the
                # breakpoint 
                self.target.avatar.queue.put(BreakpointHitMessage(self.target, 1, addr))
                break
            # 90% chances of reading from a forwarded memory address
            else:
                # Randomly pick one forwarded range
                mem_range = random.choice(self.target.mranges)
                # Randomly pick an address in the range
                addr = random.randint(mem_range[0], mem_range[1] - 4)
                # Add a message in the Avatar queue to read the value at
                # that address
                self.target.avatar.queue.put(RemoteMemoryReadMessage(self.target, 55, addr, 4))
        self.target.log.info("Avatar told me stop..")


class DummyTarget(Target):
    """ 
    This is a Dummy target that can be used for testing purposes.
    It simulates a device that randomly reads from forwarded memory ranges
    and triggers breakpoints.    
    """

    def __init__(self, avatar, **kwargs):
        super(DummyTarget, self).__init__(avatar, **kwargs)
        # List of breakpoints
        self.bp = []
        # List of forwarded memory ranges 
        self.mranges = []
        self.thread = None

        # Avatar will try to answer to our messages (e.g., with the value
        # the Dummy Target tries to read from memory). To handle that
        # we need a memory protocol. However, here we set the protocol to
        # ourself (its a dirty trick) and later implement the sendResponse 
        # method
        self.protocols.remote_memory = self

    # This is called by Avatar to initialize the target
    def init(self):
        self.log.info("Dummy Target Initialized and ready to rock")
        # Ack. It should actually go to INITIALIZED but then the protocol
        # should change that to STOPPED 
        self.avatar.queue.put(UpdateStateMessage(self, TargetStates.STOPPED))
        # We fetch from Avatar the list of memory ranges that are
        # configured to be forwarded
        for mem_range in self.avatar.memory_ranges:
            mem_range = mem_range.data
            if mem_range.forwarded:
                self.mranges.append((mem_range.address, mem_range.address + mem_range.size))
        self.wait()

    # If someone ones to read memory from this target, we always return
    # the same value, no matter what address it is requested
    def read_memory(*args, **kwargs):
        return 0xdeadbeef

    # This allow Avatar to answer to our memory read requests.
    # However, we do not care about it
    def send_response(self, id, value, success):
        if success:
            self.log.debug("RemoteMemoryRequest with id %d returned 0x%x" %
                           (id, value))
        else:
            self.log.warning("RemoteMemoryRequest with id %d failed" % id)

    # We let Avatar writes to our memory.. well.. at least we let it
    # believe so
    def write_memory(self, addr, size, val, *args, **kwargs):
        return True

    # We keep tracks of breakpoints
    def set_breakpoint(self, line, hardware=False, temporary=False, regex=False, condition=None, ignore_count=0,
                       thread=0):
        self.bp.append(line)

    def remove_breakpoint(self, breakpoint):
        # FIXME.. how do you remove a breakpoint?
        # sle.bp.remove(breakpoint) does not work
        pass

        # def wait(self):
        # self.thread.join()

    def cont(self):
        if self.state != TargetStates.RUNNING:
            self.avatar.queue.put(UpdateStateMessage(self, TargetStates.RUNNING))
            self.thread = _TargetThread(self)
            self.thread.daemon = True
            self.thread.start()

    def get_status(self):
        if self.thread:
            self.status.update({"state": self.state, "steps": self.thread.steps})
        else:
            self.status.update({"state": self.state, "steps": '-'})
        return self.status

    # Since we set the memory protocol to ourself, this is important to avoid 
    # an infinite recursion (otherwise by default a target would call
    # shutdown to all its protocols)
    def shutdown(self):
        pass

    def stop(self):
        if self.state == TargetStates.RUNNING:
            self.thread.please_stop = True
            self.avatar.queue.put(UpdateStateMessage(self, TargetStates.STOPPED))
        return True
