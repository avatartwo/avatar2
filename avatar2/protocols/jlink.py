import sys
import string
import binascii
import pylink
from time import sleep
from threading import Thread, Event, Condition
import logging
import re

if sys.version_info < (3, 0):
    import Queue as queue
    # __class__ = instance.__class__
else:
    import queue

from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage


class JLinkProtocol(Thread):
    """Main class for the JLink bprotocol, via pylink-square
    :ivar serial: The serial number of the JLink to connect to
    :ivar device: The JLink device name for the target
    :ivar avatar:   the avatar object
    :ivar origin:   the target utilizing this protocol
    """

    def __init__(self, serial=None, device="ARM7", interface="swd", avatar=None, origin=None):
        self._shutdown = Event()
        self.avatar = avatar
        self._origin = origin
        self.jlink = pylink.JLink()
        self.jlink.open(serial_no=serial)
        if interface == "swd": # swd is more generic than jtag
            self.jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)
        Thread.__init__(self)
        self.connect(device=device)

    def __del__(self):
        self.shutdown()

    def connect(self, device="ARM7"):
        # Todo add a time out here
        while True:
            try:
                self.jlink.connect(device, verbose=True)
                self.jlink.ir_len()
                break
            except pylink.errors.JLinkException:
                self.log.info("Connection failed, trying again...")
                sleep(0.25)
        self.log.info("Connected to JLink target")
        self.start()
        return True

    def reset(self, halt=True):
        self.log.info("Resetting target")
        return self.jlink.reset(halt=halt)

    def shutdown(self):
        self._shutdown.set()
        
    def update_target_regs(self):
        """
        This function will try to update the TargetRegs based on the list of
        registers known to gdb.
        """
        regs = {}
        for idx in self.jlink.register_list():
            name = self.jlink.register_name(idx)
            regs[name] = idx

        if hasattr(self._origin, 'regs'):
            self._origin.regs._update(regs)

    def run(self):
        # Target state management thread
        # This thread needs to poll for the halted state
        # of the target
        # JLink is lame and doesn't let you do this asynch
        # Also, not all targets produce a "moe" (Mode of Entry) 
        # so we have to actually do that here.
        try:
            while not self._shutdown.is_set():
                is_halted = self.jlink.halted()
                if is_halted and self._origin.state == TargetStates.RUNNING:
                    # We just halted
                    # But did we hit a BP?
                    self.log.debug("JLink Target is halting...")
                    avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
                    self.avatar.fast_queue.put(avatar_msg)
                    self._origin.wait()
                    self.log.debug("JLink target has halted")
                    pc = self.get_pc()
                    if self.jlink.breakpoint_find(pc):
                        self.log.debug("JLink Target hit breakpoint %d" % self.jlink.breakpoint_find(pc))
                        avatar_msg = BreakpointHitMessage(self._origin, self.jlink.breakpoint_find(pc), pc)
                        self.avatar.queue.put(avatar_msg)

                elif not is_halted and self._origin.state == TargetStates.STOPPED:
                    self.log.info("About to resume target.")
                    avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)
                    self.avatar.fast_queue.put(avatar_msg)
                    while self._origin.state != TargetStates.RUNNING:
                        pass
                    self.log.debug("JLink target has resumed")
        except:
            self.log.exception("JLink target errored")
        finally:
            self.log.info("JLink target exiting")
            self.jlink.close()

    def set_breakpoint(self, line,
                       hardware=False,
                       temporary=False,
                       regex=False,
                       condition=None,
                       ignore_count=0,
                       thread=0,
                       pending=False):
        """Inserts a breakpoint

        :param bool hardware: Hardware breakpoint
        :param bool temporary:  Tempory breakpoint
        :param str regex:     If set, inserts breakpoints matching the regex
        :param str condition: If set, inserts a breakpoint with specified condition
        :param int ignore_count: Amount of times the bp should be ignored
        :param int thread:    Threadno in which this breakpoints should be added
        :returns:             The number of the breakpoint
        """
        # TODO: Hw/Sw breakpoint control
        self.log.info("Setting breakpoint at %#08x" % line)
        ret = self.jlink.breakpoint_set(line)
        self.log.info("Got BP ID %d" % ret)
        return ret

    def set_watchpoint(self, variable, write=True, read=False):
        return self.jlink.watchpoint_set(variable, write=write, read=read)

    def remove_breakpoint(self, bkpt):
        """Deletes a breakpoint"""
        # TODO: Check this
        return self.jlink.breakpoint_clear(bkpt)

    def write_memory(self, address, wordsize, val, num_words=1, raw=False):
        """Writes memory

        :param address:   Address to write to
        :param wordsize:  the size of the write (1, 2, 4)
        :param val:       the written value
        :type val:        int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :returns:         True on success else False
        """
        if raw:
            new_val = []
            if not len(val):
                raise ValueError("val had zero length")
            new_val = [ord(v) for v in val]
            val = new_val
        if not isinstance(val, list):
            val = [val]
        try:
            self.jlink.memory_write(address, data=val, nbits=wordsize * 8)
            return True
        except pylink.JLinkException:
            return False

    def read_memory(self, address, wordsize=1, num_words=1, raw=False):
        """reads memory

        :param address:   Address to write to
        :param wordsize:  the size of a read word (1, 2, 4). 
                          nbits if provided, must be either 8, 16, or 32.
                          If not provided, always reads num_units bytes.
                          Ref https://pylink.readthedocs.io/en/latest/pylink.html
        :param num_words: the amount of read words
        :param raw:       Whether the read memory should be returned unprocessed
        :return:          The read memory
        """

        ret = self.jlink.memory_read(address, num_units=num_words, nbits=wordsize * 8) # nbits indicate bits of each unit

        if raw:
            raw_mem = b''
            for i in ret:
                raw_mem += i.to_bytes(wordsize, "little")
            return raw_mem
        if num_words==1:
            return ret[0]
        else:
            return ret

    def read_register(self, reg):
        """read_register
        jlink supported registers: ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13 (SP)', 'R14', 'R15 (PC)', 'XPSR', 'MSP', 'PSP', 'APSR', 'EPSR', 'IPSR', 'PRIMASK', 'BASEPRI', 'FAULTMASK', 'CONTROL', 'BASEPRI_MAX', 'IAPSR', 'EAPSR', 'IEPSR', 'FPSCR', 'FPS0', 'FPS1', 'FPS2', 'FPS3', 'FPS4', 'FPS5', 'FPS6', 'FPS7', 'FPS8', 'FPS9', 'FPS10', 'FPS11', 'FPS12', 'FPS13', 'FPS14', 'FPS15', 'FPS16', 'FPS17', 'FPS18', 'FPS19', 'FPS20', 'FPS21', 'FPS22', 'FPS23', 'FPS24', 'FPS25', 'FPS26', 'FPS27', 'FPS28', 'FPS29', 'FPS30', 'FPS31', 'CycleCnt', 'MSP_NS', 'PSP_NS', 'MSP_S', 'PSP_S', 'MSPLIM_S', 'PSPLIM_S', 'MSPLIM_NS', 'PSPLIM_NS', 'CFBP_S', 'CFBP_NS', 'PRIMASK_NS', 'BASEPRI_NS', 'FAULTMASK_NS', 'CONTROL_NS', 'BASEPRI_MAX_NS', 'PRIMASK_S', 'BASEPRI_S', 'FAULTMASK_S', 'CONTROL_S', 'BASEPRI_MAX_S', 'MSPLIM', 'PSPLIM', 'BASEPRI_BASE0', 'FAULTMASK_BASE0', 'CONTROL_BASE0', 'BASEPRI_MAX_BASE0']
        :param reg: register name string
        :return: register value
        """
        the_reg = reg.upper() # all register names are upper, not lower
        # jlink has no reg named ip, lr, cpsr. So transfer them
        if the_reg == 'IP': 
            the_reg = 'R12'
        if the_reg == 'LR':
            the_reg = 'R14'
        if the_reg == 'CPSR':
            the_reg = 'XPSR'
        the_idx = -1
        for idx in self.jlink.register_list():
            if(idx == 13 or idx == 15): # R13 (SP) and R15 (PC) need special operation
                if the_reg in self.jlink.register_name(idx):
                    the_idx = idx
                    break
            else:
                if the_reg == self.jlink.register_name(idx): 
                    the_idx = idx
                    break
        if(the_idx == -1):
            self.log.exception("Do not find target register")
        return self.jlink.register_read(the_idx)

    def get_pc(self):
        # Get PC a shitty way
        for idx in self.jlink.register_list():
            if "PC" in self.jlink.register_name(idx):
                return self.jlink.register_read(idx)

    def write_register(self, reg, val):
        """Set one register on the target
        :returns: True on success"""
        the_reg = reg.upper()
        the_idx = -1
        for idx in self.jlink.register_list():
            if(idx == 13 or idx == 15): # R13 (SP) and R15 (PC) need special operation
                if the_reg in self.jlink.register_name(idx):
                    the_idx = idx
                    break
            else:
                if the_reg == self.jlink.register_name(idx): 
                    the_idx = idx
                    break
        if(the_idx == -1):
            self.log.exception("Do not find target register")
        return self.jlink.register_write(the_idx, val)
        
    def step(self):
        """Step one instruction on the target
        :returns: True on success"""
        return self.jlink.step()

    def cont(self):
        """Continues the execution of the target
        :returns: True on success"""
        self.log.info("Resuming target...")
        return self.jlink.restart()

    def stop(self):
        """Stops execution of the target
        :returns: True on success"""
        self.log.info("Stopping target...")
        return self.jlink.halt()

    def set_endianness(self, endianness='little'):
        if 'little' in endianness:
            self.jlink.set_little_endian()
        elif "big" in endianness:
            self.jlink.set_big_endian()

		
