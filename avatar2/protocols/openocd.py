import sys
import subprocess
import telnetlib
import logging
import distutils
import binascii
from threading import Thread, Lock, Event
from struct import pack, unpack

from os.path import abspath
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

END_OF_MSG = b'\x1a'


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

    def __init__(self, avatar, openocd_script, openocd_executable="openocd",
                 additional_args=[], host='127.0.0.1', tcl_port=6666, gdb_port=3333,
                 origin=None, output_directory='/tmp'):
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
        self.buf = ""
        self.cmd_lock = Lock()

        executable_path = distutils.spawn.find_executable(openocd_executable)
        self._cmd_line = [executable_path, '--debug']
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


    def connect(self):
        """
        Connects to OpenOCDs TCL Server for all subsequent communication
        returns: True on success, else False
        """
        from time import sleep
        sleep(1)
        self.log.debug("Connecting to OpenOCD on %s:%s" % (self._host, self._tcl_port))
        try:
            self.telnet = telnetlib.Telnet(self._host, self._tcl_port)
            # mic check
            self.telnet.write("ocd_echo\x1a")
            self.log.debug("Connected to OpenOCD.  Saying hello...")
            stuff = self.telnet.read_until('\x1a')
            self.log.debug("Got a hello back.  Starting background thread...")
            self.start()
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
            return True
        else:
            self.log.warning("Could not enable target tracing! Is your OpenOCD old?")
            return False

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
        self._close.set()
        if self.telnet:
            self.telnet.close()
        if self._openocd is not None:
            self._openocd.terminate()
            self._openocd = None

    def execute_command(self, cmd):
        try:
            self.cmd_lock.acquire()
            self.in_queue.put(cmd)
            return self.out_queue.get()
        except Exception, e:
            self.log.exception("Exception thrown executing command")
            raise e
        finally:
            self.cmd_lock.release()

    def run(self):
        try:
            self.log.debug("Starting OpenOCDSocketListener")
            while not self.avatar._close.is_set() and not self._close.is_set():
                if not self.in_queue.empty():
                    cmd = self.in_queue.get()
                    self.log.debug("Executing command %s" % cmd)
                    self.telnet.write((cmd + END_OF_MSG))
                try:
                    line = self.read_response()
                except EOFError:
                    self.log.warning("OpenOCD Connection closed!")
                    self.shutdown()
                    break
                if line is not None:
                    line = line.rstrip(END_OF_MSG)
                    if "trace_data" in line:
                        self.trace_queue.put(line)
                    else:
                        self.log.debug(line)
                        self.out_queue.put(line)
        except Exception, e:
            self.log.exception("OpenOCD Background thread died with an exception")
        self.log.debug("OpenOCD Background thread exiting")

    def read_response(self):
        self.buf += self.telnet.read_eager()
        if END_OF_MSG in self.buf:
            resp, self.buf = self.buf.split(END_OF_MSG, 1)
            return resp
        return None

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
        if isinstance(val, str) and len(val) != num_words:
            self.log.debug("Setting num_words = %d" % (len(val) / wordsize))
            num_words = len(val) / wordsize
        for i in range(0, num_words, wordsize):
            if raw:
                write_val = '0x' + binascii.hexlify(val[i:i+wordsize])
            elif isinstance(val, int) or isinstance(val, long):
                write_val = hex(val).rstrip("L")
            else:
                # A list of ints
                write_val = hex(val[i]).rstrip("L")
            write_addr = hex(address + i).rstrip("L")
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
            resp = self.execute_command('mrw %s' % read_addr)
            if resp:
                val = int(resp)
                raw_mem += binascii.unhexlify(hex(val)[2:].zfill(wordsize * 2))
            else:
                self.log.error("Could not read from address %s" % read_addr)
                return None
        # OCD flips the endianness
        raw_mem = "".join(reversed(raw_mem))
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

