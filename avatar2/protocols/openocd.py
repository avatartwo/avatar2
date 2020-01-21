import sys
import subprocess
import telnetlib
import logging
import distutils
from codecs import encode
import binascii
from threading import Thread, Lock, Event
from struct import pack, unpack
from time import sleep
import re
from os.path import abspath
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage

END_OF_MSG = u'\x1a'


class OpenOCDProtocol(Thread):
    """
    This class implements the openocd protocol.

    :param openocd_script:     The openocd scripts to be executed.
    :type openocd_script:      str or list
    :param openocd_executable: The executable
    :param additional_args:    Additional arguments delivered to openocd.
    :type  additional_args:    list
    :param tcl_port:        the port used for the telnet connection
    :param gdb_port:           the port used for openocds gdb-server
    """

    def __init__(self, avatar, origin, openocd_script, openocd_executable="openocd",
                 additional_args=[], host='127.0.0.1', tcl_port=6666, gdb_port=3333,
                 output_directory='/tmp', debug=False):
        """
        OpenOCD machine interface protocol
        :param avatar: The Avatar instance
        :param origin: The Target this protocol belongs to
        :param openocd_script: The OpenOCD script for starting and configuring the taret.  Should not call 'init'
        :param openocd_executable: The path to the OpenOCD you want to use
        :param additional_args: Additional args to openocd
        :param host: THe host of the running OpenOCD.  Probably localhost
        :param tcl_port: The port for OpenOCD's TCL machine interface.  Should be 6666
        :param gdb_port: The GDB port for OpenOCD's GDB interface
        :param output_directory: The directory where logfiles should go
        :param debug: Enable openocd debug output
        """
        if isinstance(openocd_script, str):
            self.openocd_files = [openocd_script]
        elif isinstance(openocd_script, list):
            self.openocd_files = openocd_script
        else:
            raise TypeError("Wrong type for OpenOCD configuration files")
        self.log = logging.getLogger('%s.%s' % (origin.log.name, self.__class__.__name__)) if origin else \
                                    logging.getLogger(self.__class__.__name__)
        self._tcl_port = tcl_port
        self._gdb_port = gdb_port
        self._host = host
        self.in_queue = queue.Queue()
        self.out_queue = queue.Queue()
        self.trace_queue = queue.Queue()
        self.trace_enabled = Event()
        self.avatar = avatar
        self.telnet = None
        self._close = Event()
        self.buf = u""
        self.cmd_lock = Lock()
        self._origin = origin

        self.output_directory = output_directory
        executable_path = distutils.spawn.find_executable(openocd_executable)
        self._cmd_line = [executable_path]
        if debug is True:
            self._cmd_line += ['--debug']

        self._cmd_line += [e for l
                           in [['-f', abspath(f)] for f in self.openocd_files]
                           for e in l]
        self._cmd_line += ['--command', 'tcl_port %d' % self._tcl_port,
                          '--command', 'gdb_port %d' % self._gdb_port]
        self._cmd_line += additional_args

        self._openocd = None

        with open("%s/openocd_out.txt" % output_directory, "wb") as out, \
                open("%s/openocd_err.txt" % output_directory, "wb") as err:
            self.log.debug("Starting OpenOCD with command line: %s" % (" ".join(self._cmd_line)))
            self._openocd = subprocess.Popen(self._cmd_line,
                                             stdout=out, stderr=err)#, shell=True)
        Thread.__init__(self)
        self.daemon = True


    def connect(self):
        """
        Connects to OpenOCDs TCL Server for all subsequent communication
        returns: True on success, else False
        """
        sleep(1)
        
        if self._openocd.poll() is not None:
            raise RuntimeError(("Openocd errored! Please check "
                                "%s/openocd_err.txt for details" %
                                self.output_directory))


        self.log.debug("Connecting to OpenOCD on %s:%s" % (self._host, self._tcl_port))
        try:
            self.telnet = telnetlib.Telnet(self._host, self._tcl_port)
            # mic check
            self.telnet.write("ocd_echo\x1a".encode('ascii'))
            self.log.debug("Connected to OpenOCD.  Saying hello...")
            stuff = self.telnet.read_until('\x1a'.encode('ascii'))
            self.log.debug("Got a hello back.  Starting background thread...")
            self.start()
            # One last thing, enable target notifications!
            self.log.debug("Enabling async target notifications...")
            self.execute_command("tcl_notifications on")
            return True
        except:
            self.log.exception("Error connecting to OpenOCD TCL port %d" % self._tcl_port)
            return False

    def enable_trace(self):
        """
        Enables OpenOCD's "target tracing" support.
        Requires a version of OpenOCD >= 0.10.0-dev
        (the absolute latest one is probably a good idea)
        This will log all the trace data to the special `trace_queue` member.
        Something else (like the CoreSightProtocol) should figure out what to do with that.
        :return:
        """
        self.log.debug("Enabling tracing...")
        resp = self.execute_command("ocd_tcl_trace on")
        if 'is enabled' in resp:
            self.trace_enabled.set()
            return True
        else:
            self.log.warning("Could not enable target tracing! Is your OpenOCD old?")
            return False

    def handle_target_notification(self, str):

        # Check if we should handle notifications
        if self != self._origin.protocols.execution:
            return

        # mode halt | run | init
        reset_re = re.compile("type target_reset mode (\w+)")
        # Trace data (from TPIU) Hex-encoded.
        trace_re = re.compile("type target_trace data ([0-9a-f]+)")
        # State change
        state_re = re.compile("type target_state state (\S+)")
        # Generic event
        event_re = re.compile("type target_event event (\S+)")

        mreset = reset_re.match(str)
        mtrace = trace_re.match(str)
        mstate = state_re.match(str)
        mevent = event_re.match(str)

        if mreset:
            reset_type = mreset.group(1)
            self.log.debug("Got reset event type %s" % reset_type)
            if reset_type == "halt":
                avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
                self.avatar.fast_queue.put(avatar_msg)
        elif mtrace:
            # DOn't log anything here.  If we do, our IO will be exhausted by the sheer volume of trace packets.
            self.trace_queue.put(str)
        elif mstate:
            # Do a state update!
            state = mstate.group(1)
            if "halted" in state:
                self.log.debug("Target has halted")
                avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
                self.avatar.fast_queue.put(avatar_msg)
            elif "running" in state:
                self.log.debug("Target is now running")
                avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)
                self.avatar.fast_queue.put(avatar_msg)
            else:
                self.log.warning("Weird target state %s" % state)
        elif mevent:
            #TODO handle these
            event = mevent.group(1)
            self.log.debug("Target event: %s " % event)
            # TODO handle these
            if event == 'halted':
                avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
                self.avatar.fast_queue.put(avatar_msg)
            elif event == 'resumed':
                avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)
                self.avatar.fast_queue.put(avatar_msg)

        else:
            self.log.warning("Unhandled event message %s" % str)


    def reset(self):
        """
        Resets the target
        returns: True on success, else False
        """
        self.log.debug("Resetting target")
        resp = self.execute_command('reset halt')
        if not 'Not halted' in str(resp):
            self.log.debug("Target reset complete")
            return True
        else:
            self.log.error('Failed to reset the target with OpenOCD')
            return False

    def shutdown(self):
        """
        Shuts down OpenOCD
        returns: True on success, else False
        """
        #self.execute_command('ocd_shutdown')
        self._close.set()
        if self.telnet:
            self.telnet.close()
        # Fix
        if self._openocd is not None:
            self._openocd.terminate()
            self._openocd = None

    def execute_command(self, cmd):
        try:
            self.cmd_lock.acquire()
            self.in_queue.put(cmd)
            ret = self.out_queue.get()
            if "FAILED" in ret:
                raise RuntimeError("Command '%s' failed!" % cmd)
            return ret
        except:
            raise
        finally:
            self.cmd_lock.release()

    def run(self):
        try:
            cmd = None
            self.log.debug("Starting OpenOCDSocketListener")
            while not self.avatar._close.is_set() and not self._close.is_set():
                if not self.in_queue.empty():
                    cmd = self.in_queue.get()
                    self.log.debug("Executing command %s" % cmd)
                    self.telnet.write((cmd + END_OF_MSG).encode('ascii'))
                try:
                    line = self.read_response()
                except EOFError:
                    self.log.warning("OpenOCD Connection closed!")
                    self.shutdown()
                    break
                if line is not None:
                    #print line
                    line = line.rstrip(END_OF_MSG)
                    # This is async target notification data.  Don't return it normally
                    if line.startswith("type"):
                        self.handle_target_notification(line)
                    # This is an error
                    elif "Error" in line:
                        self.log.error(line)
                        if cmd:
                            # tell the caller we failed
                            self.out_queue.put("FAILED")
                    else:
                        if not cmd:
                            # We didn't ask for it.  Just debug it
                            self.log.debug(line)
                        else:
                            self.log.debug("response --> " +  line)
                            self.out_queue.put(line)
                            cmd = None
                sleep(.001) # Have a heart. Give other threads a chance
        except Exception as e:
            self.log.exception("OpenOCD Background thread died with an exception")
        self.log.debug("OpenOCD Background thread exiting")

    def read_response(self):
        self.buf += self.telnet.read_eager().decode('ascii')
        #if buf is not '':
            #print(self.buf)
        if END_OF_MSG in self.buf:
            resp, self.buf = self.buf.split(END_OF_MSG, 1)
            return resp
        return None

    ### The Memory Protocol starts here

    def write_memory(self, address, wordsize, val, num_words=1, raw=False):
        """Writes memory

        :param address:   Address to write to
        :param wordsize:  the size of the write (1, 2, 4 or 8)
        :param val:       the written value
        :type val:        int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :returns:         True on success else False
        """
        #print "nucleo.write_memory(%s, %s, %s, %s, %s)" % (repr(address), repr(wordsize), repr(val), repr(num_words), repr(raw))
        if isinstance(val, str) and len(val) != num_words:
            self.log.debug("Setting num_words = %d" % (len(val) / wordsize))
            num_words = len(val) / wordsize
        for i in range(0, num_words, wordsize):
            if raw:
                write_val = '0x' + encode(val[i:i+wordsize], 'hex_codec').decode('ascii')
            elif isinstance(val, int) or isinstance(val, long):
                write_val = hex(val).rstrip("L")
            else:
                # A list of ints
                write_val = hex(val[i]).rstrip("L")
            write_addr = hex(address + i).rstrip("L")
            if wordsize == 1:
                self.execute_command('mwb %s %s' % (write_addr, write_val))
            elif wordsize == 2:
                self.execute_command('mwh %s %s' % (write_addr, write_val))
            else:
                self.execute_command('mww %s %s' % (write_addr, write_val))

        return True

    def read_memory(self, address, wordsize=4, num_words=1, raw=False):
        """reads memory

        :param address:   Address to write to
        :param wordsize:  the size of a read word (1, 2, 4 or 8)
        :param num_words: the amount of read words
        :param raw:       Whether the read memory should be returned unprocessed
        :return:          The read memory
        """
        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
        raw_mem = b''
        words = []
        for i in range(0, num_words, wordsize):
            read_addr = hex(address + i).rstrip('L')
            if wordsize == 1:
                resp = self.execute_command('mrb %s' % read_addr)
            elif wordsize == 2:
                resp = self.execute_command("mrh %s" % read_addr)
            else:
                resp = self.execute_command('mrw %s' % read_addr)
            if resp:
                val = int(resp)
                raw_mem += binascii.unhexlify(hex(val)[2:].zfill(wordsize * 2))
            else:
                self.log.error("Could not read from address %s" % read_addr)
                return None
        # OCD flips the endianness
        raw_mem = raw_mem[::-1]
        if raw:
            self.log.debug("Read %s from %#08x" % (repr(raw), address))
            return raw_mem
        else:
            # Todo: Endianness support
            fmt = '<%d%s' % (num_words, num2fmt[wordsize])
            mem = list(unpack(fmt, raw_mem))
            if num_words == 1:
                return mem[0]
            else:
                return mem

    ### The register protocol starts here

    def read_register(self, reg):

        try:
            resp = self.execute_command("ocd_reg %s" % reg)
            val = int(resp.split(":")[1].strip(), 16)
            return val
        except:
            self.log.exception("Failed to read from register " + repr(reg))
            return False

    def write_register(self, reg, value):
        """Set one register on the target
        :returns: True on success"""
        try:
            self.execute_command("ocd_reg %s %s" % (reg, hex(value)))
            return True
        except:
            self.log.exception(("Error writing register %s" % reg))
            return False

    def cont(self):
        """Continues the execution of the target
        :returns: True on success"""
        try:
            resp = self.execute_command("resume")
        except:
            self.log.exception("Error halting target")
            return False
        return True

    def stop(self):
        """Stops execution of the target
        :returns: True on success"""
        try:
            resp = self.execute_command("halt")
        except:
            self.log.exception("Error halting target")
            return False
        return True

    def step(self):
        """Step one instruction on the target
        :returns: True on success"""
        try:
            resp = self.execute_command("step")
            return True
        except:
            self.log.exception("Failed to step the target")

    def set_breakpoint(self, line,
                       hardware=False,
                       temporary=False,
                       regex=False,
                       condition=None,
                       ignore_count=0,
                       thread=0):
        """Inserts a breakpoint
        :param str line: the thing to break at.  An address.
        :param bool hardware: Hardware breakpoint
        :param bool temporary:  Tempory breakpoint
        :param str regex:     If set, inserts breakpoints matching the regex
        :param str condition: If set, inserts a breakpoint with specified condition
        :param int ignore_count: Amount of times the bp should be ignored
        :param int thread:    Threadno in which this breakpoints should be added
        :returns:             The number of the breakpoint
        """
        cmd = ["bp"]
        if regex:
            raise ValueError("OpenOCD doesn't support regex breakpoints!")
        if condition:
            raise ValueError("OpenOCD doesn't support conditional breakpoints!")
        if ignore_count:
            raise ValueError("OpenOCD doesn't support ignore counts")
        if thread:
            raise ValueError("OpenOCD doesn't support thread options!")

        if isinstance(line, int):
            cmd.append("%#08x" % line)
        else:
            cmd.append(str(line))
        cmd.append("2") # TODO: This isn't platform-independent, but i have no idea what it does
        if hardware:
            cmd.append("hw")
        try:
            resp = self.execute_command(" ".join(cmd))
            self.log.debug("Breakpoint set")
            return True
        except:
            self.log.exception("Error setting breakpoint")
            return False

    def set_watchpoint(self, variable, write=True, read=False):
        cmd = ["wp"]

        if isinstance(variable, int):
            cmd.append("%#08x" % variable)
        else:
            cmd.append(str(variable))
        cmd.append("2") # TODO FIXME
        if read and write:
            cmd.append("a")
        elif read:
            cmd.append("r")
        elif write:
            cmd.append("w")
        else:
            raise ValueError("At least one read and write must be True")
        try:
            resp = self.execute_command(" ".join(cmd))
            return True
        except:
            self.log.exception("Error setting watchpoint")
            return False

    def remove_breakpoint(self, bkpt):
        """Deletes a breakpoint"""
        cmd = ['rbp']
        if isinstance(bkpt, int):
            cmd.append("%#08x" % bkpt)
        else:
            cmd.append(str(bkpt))
        try:
            self.execute_command(" ".join(cmd))
            return True
        except:
            self.log.exception("Error removing breakpoint")

