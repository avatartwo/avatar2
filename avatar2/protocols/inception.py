import sys
import logging
import struct
import ctypes

if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

from math import ceil
from collections import OrderedDict
from os.path import abspath

# Python USB package used to interact with Inception-debugger
# Could be replace by the Inception driver
import usb.core
import usb.util

from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage


class InceptionProtocol(object):
    """
    This class implements the Inception protocol.
    It enables communication with the Inception-debugger hardware.

    :param additional_args:    Additional arguments delivered to Inception.
    :type  additional_args:    list
    :param device_vendor_id:   The usb device vendor id to connect to.
    :param device_product_id:  The usb device product id to connect to.
    """

    def __init__(self, additional_args=[], 
                 avatar=None, origin=None,
                 device_vendor_id=0x04b4, device_product_id=0x00f1,
                 output_directory='/tmp'):

        # USB device information
        self._device = None
        self._device_vendor_id = device_vendor_id
        self._device_product_id = device_product_id

        # pyusb device handler
        self._ep_out = None
        self._ep_in_response = None
        self._ep_in_irq = None

        # internal variables
        self._bkpt_limit = 0
        self._bkpt_list = [None] * 1
        self._debug_enabled = False

        self._queue = queue.Queue() if avatar is None \
                else avatar.queue
        self._fast_queue = queue.Queue() if avatar is None \
                else avatar.fast_queue

        self._origin = origin
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def shutdown(self):
        """
        Shuts down Inception

        returns: True on success
        """

        usb.util.dispose_resources(self._device)
        return True

    def connect(self):
        """
        Connects to USB3 Inception-debugger for all subsequent communication

        returns: True on success
        """

        self._device = usb.core.find(idVendor=self._device_vendor_id,
                idProduct=self._device_product_id)

        if self._device is None:
            self.log.critical('Failed to connect to Inception-debugger')
            raise ConnectionRefusedError("Inception-debugger is not connected")

        try:
            self._device.set_configuration()
            self._device.reset()
        except usb.core.USBError as e:
            self.log.critical("Could not set configuration: %s" % str(e))
            raise ConnectionRefusedError("Could not set configuration: %s" % str(e))

        # get an endpoint instance
        intf = self._device[0][(0,0)]

        if self._device.is_kernel_driver_active(0):
          self._device.detach_kernel_driver(0)

        self._ep_out = usb.util.find_descriptor(intf, bEndpointAddress=0x01)
        if self._ep_out is None:
            self.log.critical("Inception-debugger is connected but no endpoint 0x01 found")
            raise ConnectionRefusedError("Inception-debugger is connected but no endpoint 0x01 found")

        self._ep_in_response = usb.util.find_descriptor(intf, bEndpointAddress=0x81)
        if self._ep_in_response is None:
            self.log.critical("Inception-debugger is connected but no endpoint 0x81 found")
            raise ConnectionRefusedError("Inception-debugger is connected but no endpoint 0x81 found")
        
        self._ep_in_irq = usb.util.find_descriptor(intf, bEndpointAddress=0x82)
        if self._ep_in_irq is None:
            self.log.critical("Inception-debugger is connected but no endpoint 0x82 found")
            raise ConnectionRefusedError("Inception-debugger is connected but no endpoint 0x82 found")

        self.log.info("Connected to Inception-debugger")

        UpdateStateMessage(self, TargetStates.INITIALIZED)

        return True

    #def is_breakpoint_hitten(self):
    #    """
    #    Check if the processor hit a breakpoint

    #    :return:  PC or None if no breakpoint is hitten
    #    """

    #    self.stop()
    #    pc = self.read_pc()
    #    for i, j in enumerate(self._bkpt_list):
    #        if j == pc:
    #            self.log.info("Breakpoint hit")
    #            avatar_msg = BreakpointHitMessage(self._origin, bktp_nb, pc)
    #            self._queue.put(avatar_msg)
    #            return i, j
    #    self.cont()

    #    return None

    def reset(self):
        """
        Resets the target

        returns: True on success
        """
        pass

    def cont(self):
        """
        Resume the execution of the target

        :returns: True on success
        """
        pass

    def stop(self):
        """
        Stops the execution of the target

        :returns: True on success
        """
        pass

    def step(self):
        """
        Steps one instruction

        :returns:  True on success
        """
        pass

    def wait(self, state):
        """
        Wait until CPU reach provided state.

        :state:  state of the CPU
        """
        pass

    def check_halt(self):
        """
        Return if the CPU is halted or running.

        :return: True for halted, False for running
        """
        pass

    def read_pc(self):
        """
        Read PC register value
        The target must be stopped before reading the pc.

        :return:  program counter
        """
        pass

    def write_register(self, register, value):
        """
        Writing a register to the target

        :param register:     The name of the register
        :param value:        The actual value written to the register
        :return:             True on success
        """
        pass

    def read_register(self, register):
        """
        Reading a register from the target

        :param register:     The name of the register
        :return:             The actual value read from the register
        """
        pass

    def read_memory(self, address, wordsize=4, num_words=1, raw=False):
        """
        Read from memory of the target

        :param address:     The address to read from
        :param wordsize:    The size of a read word (1, 2, 4 or 8)
        :param words:       The amount of words to read (default: 1)
        :param raw:         Whether the read memory is returned unprocessed
        :return:            The read memory
        """
        pass

    def write_memory(self, address, wordsize, value, num_words=1, raw=False):
        """
        Writing to memory of the target

        :param address:   The address to write to
        :param wordsize:  The size of the write (1, 2, 4 or 8)
        :param value:     The actual value written to memory
        :type value:      int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :returns:         True on success else False
        """
        pass

    def set_breakpoint(self, address,
                       hardware=True, 
                       temporary=False, 
                       regex=False,
                       condition=None,
                       ignore_count=0,
                       thread=0,
                       pending=False):
        """Inserts a breakpoint

        :param bool hardware: Hardware breakpoint
        :param bool tempory:  Tempory breakpoint
        :param str regex:     If set, inserts breakpoints matching the regex
        :param str condition: If set, inserts a breakpoint with the condition
        :param int ignore_count: Amount of times the bp should be ignored
        :param int thread:    Threadno in which this breakpoints should be added
        :return:              True on success
        """
        pass

    def remove_breakpoint(self, bkptnb):
        """
        Deletes a breakpoint

        :bkptnb:    Breakpoint number
        :return:    True on success
        """
        pass

    def set_watchpoint(self, variable, write=True, read=False):
        """Inserts a watchpoint

        :param variable:      The name of a variable or an address to watch
        :param bool write:    Write watchpoint
        :param bool read:     Read watchpoint
        :return:              True on success
        """
        pass


class IPCortexM3(InceptionProtocol):
    """
    Inception protocol for cortex-m3.
    """

    '''
    ARM documentation usefull for the Cortex M3 System Debug:
    * FPB: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0337e/ch11s04s01.html
    * Core debug registers: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0337e/ch11s04s01.html
    '''


    def __init__(self, additional_args=[], 
                 avatar=None, origin=None,
                 device_vendor_id=0x04b4, device_product_id=0x00f1,
                 output_directory='/tmp'):

        super(IPCortexM3, self).__init__(additional_args, 
                 avatar, origin, device_vendor_id, device_product_id, 
                 output_directory)

        self.regs = OrderedDict()
        self.regs.update({ "R0" :  0 })
        self.regs.update({ "R1" :  1 })
        self.regs.update({ "R2" :  2 })
        self.regs.update({ "R3" :  3 })
        self.regs.update({ "R4" :  4 })
        self.regs.update({ "R5" :  5 })
        self.regs.update({ "R6" :  6 })
        self.regs.update({ "R7" :  7 })
        self.regs.update({ "R8" :  8 })
        self.regs.update({ "R9" :  9 })
        self.regs.update({ "R10" : 10 })
        self.regs.update({ "R11" : 11 })
        self.regs.update({ "R12" : 12 })
        self.regs.update({ "SP" : 13 })
        self.regs.update({ "LR" : 14 })
        self.regs.update({ "PC" : 15 })
        self.regs.update({ "CPSR" : 16})

    def reset(self):
        """
        Resets the target

        returns: True on success
        """

        self.log.debug("Resetting target")

        # Reset JTAG
        data = '3000000030000000'
        self._ep_out.write(bytearray.fromhex(data))

        # Enable the FlashPatch module : breakpoint
        # FlashPatch Control Register (FP_CTRL)
        self.write_memory(0xE0002000, 4, 3)

        # Now we need to retrive the number of supported hw bkpt from the core
        FP_CTRL = self.read_memory(0xE0002000)

        # bits [7:4] are number of code slots field
        self._bkpt_limit = (FP_CTRL >> 4) & 0xF 
        self.log.debug(("Number of available breakpoints read %d") % (self._bkpt_limit))
        if self._bkpt_limit == 0:
            raise Exception("No hardware breakpoint found")

        # Watchpoint are located @ bits [11:8]
        #w = (FP_CTRL >> 8) & 0xF

        # Set SYSRESETREG bit at 1 in AIRCR register to request a system reset.
        # (system reset of all major components except for debug)
        self.write_memory(0xE000ED0C, 4, ((0xFA05 << 16) | (1 << 2)))

        return True

    def cont(self):
        """
        Resume the execution of the target

        :returns: True on success
        """

        self.log.debug("Attempted to continue execution on the target.")

        # Set C_HALT bit at 0 in the DHCSR register.
        self.write_memory(0xE000EDF0, 4, (0xA05F << 16) | 0b01)

        avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)
        self._fast_queue.put(avatar_msg)

        return True

    def stop(self):
        """
        Stops the execution of the target

        :returns: True on success
        """

        self.log.debug("Attempted to stop execution of the target.")
        #DHCSR = self.read_memory(0xE000EDF0, 4)

        # Set C_HALT and C_DEBUGEN bits at 1 in DHCSR register
        self.write_memory(0xE000EDF0, 4, (0xA05F << 16) | 0b11)
        self._debug_enabled = True

        # Check the core is halted 
        DHCSR = self.read_memory(0xE000EDF0, 4)
        if not ((DHCSR >> 1) & 1):
            self.log.warning("Core not halted after stop")
        # Check the core acknowledges by reading S_HALT bit in DHCSR
        if not ((DHCSR >> 17) & 1):
            self.log.warning("Core not in debug state after stop")
            self._debug_enabled = False

        avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
        self._fast_queue.put(avatar_msg)

        return True

    def step(self):
        """
        Steps one instruction

        :returns:  True on success
        """

        self.log.debug("Attempted to step on the target.")

        # Enable Debug mode if not activated
        if not self._debug_enabled:
            self.write_memory(0xE000EDF0, 4, ((0xA05F << 16) | 0b11))
            self._debug_enabled = True

        # Check the core acknowledges by reading S_HALT bit in DHCSR
        DHCSR = self.read_memory(0xE000EDF0, 4)
        if not ((DHCSR >> 17) & 1):
            self.log.warning("Core is not in debug state before stepping")

        # Execute a step by setting the C_STEP bit to 1 in DHCSR register
        self.write_memory(0xE000EDF0, 4, (0xA05F << 16) | 0b101)

        avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)
        self._fast_queue.put(avatar_msg)

        # Check the core is halted 
        DHCSR = self.read_memory(0xE000EDF0, 4)
        if not ((DHCSR >> 1) & 1):
            self.log.warning("Core is not halted after single step")

        avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
        self._fast_queue.put(avatar_msg)

        return True

    def wait(self, state):
        """
        Wait until CPU reach provided state.

        :state:  state of the CPU
        """

        halt = True if state == TargetStates.STOPPED else False
        
        self.log.debug("Wait until target reach %s state" % state)
        while (self.check_halt() != halt):
            pass

        avatar_msg = UpdateStateMessage(self._origin, state)
        self._fast_queue.put(avatar_msg)

    def read_register(self, register):
        """
        Reading a register from the target

        :param register:     The name of the register
        :return:             The actual value read from the register
        """

        self.log.debug("Read register %s" % register.upper())
        # Before reading the processor register value in DCRDR,
        # we must first ask to transfer it via DCRSR
        self.write_memory(0xE000EDF4, 4, self.regs[register.upper()])

        return self.read_memory(0xE000EDF8)

    def write_register(self, register, value):
        """
        Writing a register to the target

        :param register:     The name of the register
        :param value:        The actual value written to the register
        :return:    True on success
        """

        self.log.debug("Write register %s" % register.upper())
        # Write register value in DCRDR
        self.write_memory(0xE000EDF8, 4, value)
        # Ask DCRSR to transfer it to the processor register
        self.write_memory(0xE000EDF4, 4, (self.regs[register.upper()] |  (1 << 16)) )

        return True

    def read_memory(self, address, wordsize=4, num_words=1, raw=False):
        """
        Read from memory of the target

        :param address:     The address to read from
        :param wordsize:    The size of a read word (1, 2, 4 or 8)
        :param num_words:   The amount of words to read (default: 1)
        :param raw:         Whether the read memory is returned unprocessed
        :return:            The read memory
        """

        # Note: Inception does not support burst of read more than 4 bytes 

        # Command to order a read
        command = 0x24000001

        burst_size = 1
        start_addr = address

        # number of packets to be sent (header + payload)
        # 1 packet = 64 bits
        nb_packet = ceil((wordsize * num_words) / 4)
        nb_packet_init = nb_packet
        buf = ctypes.create_string_buffer(8 * burst_size)
        if raw:
            raw_ret = ctypes.create_string_buffer(nb_packet * 4)
        else:
            ret = []

        self.log.debug("Read_memory %s bytes starting from @=%s" % (nb_packet * 4, hex(address)))

        while (nb_packet > 0):

            burst = nb_packet if nb_packet < burst_size else burst_size
            nb_packet -= burst_size

            self.log.debug("Sending read for %s bytes from address @=%s" % (burst_size * 4, hex(start_addr)))
            # Create a burst
            for i in range(burst):
                struct.pack_into(">I", buf, (i * 8), command)
                struct.pack_into(">I", buf, (i * 8) + 4, start_addr)
                start_addr += 4

            self._ep_out.write(buf)

            # Unpack the bitstream of USB packets received
            for i in range(burst):

                response = self._ep_in_response.read(8, 0)
                # message is a bitstream of 64bits integer.
                # The highest 32bits are the status code
                if response[3] != 2:
                    raise Exception("Debugger returned an error")
                    
                value = struct.unpack_from(">I", response, 4)[0]
                self.log.debug("Read value: %s" % hex(value))

                if raw:
                    offset = (ceil((wordsize * num_words) / 4) - nb_packet - burst) * 4
                    struct.pack_into(">I", raw_ret, offset, value)
                else:
                    ret.append(value)

        if raw:
            return raw_ret.raw
        elif num_words == 1:
            return ret[0]
        else:
            return ret


    def write_memory(self, address, wordsize, value, num_words=1, raw=False):
        """
        Writing to memory of the target

        :param address:   The address to write to
        :param wordsize:  The size of the write (1, 2, 4 or 8)
        :param value:     The actual value written to memory
        :type value:      int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :returns:         True on success else False
        """

        # Command to order a write
        command = 0x14000001

        # Convert value to a list and compute the remainder bytes
        value, remainder = self._convert_to_list(wordsize, value, num_words, raw)

        # one packet is 12 bytes: 4 bytes commands, 
        # 4 bytes addresses and 4 bytes values
        nb_packet = len(value)
        buf = ctypes.create_string_buffer(12)
        struct.pack_into(">I", buf, 0, command)

        self.log.debug("Write_memory %s bytes starting from @=%s" % (nb_packet * 4, hex(address)))

        nb_full_packet = len(value) - 1 if remainder else nb_packet

        for i in range(0, nb_full_packet):
            val = value.pop(0)
            struct.pack_into(">I", buf, 4, address + i * 4)
            struct.pack_into(">I", buf, 8, val)

            self.log.debug("Write %s at address @=%s" % (hex(val), hex(address + i * 4)))
            self._ep_out.write(buf)

        # Write the remainder bytes when value is not multiple of 4 bytes
        if remainder:
            val = value.pop(0)
            self._write_remainder(remainder, address, val)

        return True

    def _convert_to_list(self, wordsize, value, num_words, raw=False):
        """
        Convert the value to be written into a list of 4 bytes and computes the remainder.

        :param wordsize:  The size of the write (1, 2, 4 or 8)
        :param value:     The actual value written to memory
        :type value:      int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :returns: The value in a list of integer and the remainder 
        """

        remainder = 0

        if raw:
            if not len(value):
                raise ValueError("value has zero length")
            data = []

            for i in range(0, len(value), 4):         
                data.append(struct.unpack_from(">I", value, i)[0])

            remainder = len(value) % 4            
            if remainder == 1:
                data.append(struct.unpack_from(">B", value, len(value))[0])
            if remainder == 2:
                data.append(struct.unpack_from(">H", value, len(value))[0])

        elif num_words == 1:
            data = []
            data.append(value)
            remainder = wordsize % 4

        else:
            data = value[:]
            remainder = (wordsize * num_words) % 4

        if remainder == 3:
            raise ValueError("value must be 1 or multiple of 2")

        return data, remainder

    def _write_remainder(self, remainder, address, value):
        """
        When the value to be written is not a multiple of 4 bytes, 
        we must write the remainder by reading first the previous value.

        :param remainder: the number of remainder bytes to write
        :param address: the address where to write
        :param value: the value to write
        :type value: int
        :returns: True on success
        """

        command = 0x14000001
        buf = ctypes.create_string_buffer(12)

        if remainder == 3:
            raise ValueError("value must be 1 or multiple of 2")

        read_value = self.read_memory(address, 4, 1, raw=True)

        struct.pack_into(">I", buf, 0, command)
        struct.pack_into(">I", buf, 4, address)

        if remainder == 1:
            read_value = struct.unpack_from(">BBB", read_value, 0)
            #rem_value = struct.unpack_from(">B", struct.pack(">I", value), 0)[0]
            rem_value = struct.unpack_from(">B", value.raw, 0)[0]

            struct.pack_into(">B", buf, 8, read_value[0])
            struct.pack_into(">B", buf, 9, read_value[1])
            struct.pack_into(">B", buf, 10, read_value[2])
            struct.pack_into(">B", buf, 11, rem_value)
         
        if remainder == 2:
            read_value = struct.unpack_from(">H", read_value, 0)
            #rem_value = struct.unpack_from(">H", struct.pack(">I", value), 0)[0]
            rem_value = struct.unpack_from(">H", value, 0)[0]

            struct.pack_into(">H", buf, 8, read_value[0])
            struct.pack_into(">H", buf, 10, rem_value)

        self._ep_out.write(buf)

        return True

    def set_breakpoint(self, address,
                       hardware=False, 
                       temporary=False, 
                       regex=False,
                       condition=None,
                       ignore_count=0,
                       thread=0,
                       pending=False):
        """Inserts a breakpoint

        :param bool hardware: Hardware breakpoint
        :param bool tempory:  Tempory breakpoint
        :param str regex:     If set, inserts breakpoints matching the regex
        :param str condition: If set, inserts a breakpoint with the condition
        :param int ignore_count: Amount of times the bp should be ignored
        :param int thread:    Threadno in which this breakpoints should be added
        :return:              True on success
        """

        #if hardware == False:
        #    raise Exception("Software breakpoint not implemented")

        # Update bkpt counter and update bkpt register address
        indexes = [i for i, j in enumerate(self._bkpt_list) if j == None]

        # If no bkpt are available, raise an exception
        if indexes == []:
            raise Exception("Breakpoint limitation reaches")

        # FP_CTRL bit must also be set to enable breakpoints
        self.write_memory(0xE0002000, 4, 3)

        # Compute a free comparator register address
        FPCRegAddress = 0xE0002008 + ( indexes[0] * 4 )

        #set the flash patch comparator register value (FP_COMPx)
        FPCRegValue = 0
        FPCRegValue += 0b11 << 30 # Breakpoint on match on lower halfword
        FPCRegValue += address << 2 # Address to compare against
        FPCRegValue += 0b11 # Enable the comparator

        self.write_memory(FPCRegAddress, 4, FPCRegValue)
        self._bkpt_list[indexes[0]] = address
        self.log.info("Breakpoint set")

        return True

    def set_watchpoint(self, variable, write=True, read=False):
        """Inserts a watchpoint
        Not implemented yet

        :param      variable: The name of a variable or an address to watch
        :param bool write:    Write watchpoint
        :param bool read:     Read watchpoint
        :return:    True on success
        """

        self.log.critical("Watchpoint not implemented")
        raise Exception("Watchpoint not implemented")
        return False

    def remove_breakpoint(self, bkptnb):
        """
        Deletes a breakpoint

        :bkptnb:    Breakpoint number
        :return:    True on success
        """

        if self._bkpt_limit < bkptnb :
            raise Execption("bkptnb higher than supported breakpoint")

        # Update bkpt counter and update bkpt register address
        FPCRegAddress = 0xE0002008 + ( bkptnb * 4 )

        #set the flash patch comparator register value (FP_COMPx)
        FPCRegValue += b'0x00' # Enable the comparator

        write_memory(self, FPCRegAddress, 4, FPCRegValue)

        self._bkpt_list[bkptnb] = None
        self.log.info("Breakpoint removed")

        return True

    def check_halt(self):
        """
        Return if the CPU is halted or running.

        :return: True for halted, False for running
        """

        halted = False

        # Check the C_HALT bit in the DHCSR register.
        DHCSR = self.read_memory(0xE000EDF0)
        if ((DHCSR >> 1) & 1):
              halted = True

        return halted

    def read_pc(self):
        """
        Read PC register value.
        The target must be stopped before reading the pc.

        :return:  pc
        """

        # Read pc
        DCRDR = self.read_register("PC")
        #PSR = self.read_register("CPSR")

        # We are always in Thumb mode with Cortex M3
        #return DCRDR - 4
        return DCRDR 

