import sys
import subprocess
import telnetlib
import logging
import distutils
import binascii
from struct import pack, unpack

from os.path import abspath
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

END_OF_MSG = b'\r\n\r>'


class OpenOCDProtocol(object):
    """
    This class implements the openocd protocol.
    Although OpenOCD itself is very powerful, it is only used as monitor
    protocol, since all other functionalities are also exposed via the 
    gdb-interface, which is easier to parse in an automatic manner.

    :param openocd_script:     The openocd scripts to be executed.
    :type openocd_script:      str or list
    :param openocd_executable: The executable
    :param additional_args:    Additional arguments delivered to openocd.
    :type  additional_args:    list
    :param telnet_port:        the port used for the telnet connection
    :param gdb_port:           the port used for openocds gdb-server
    """

    def __init__(self, openocd_script, openocd_executable="openocd",
                 additional_args=[], telnet_port=4444, gdb_port=3333,
                 origin=None, output_directory='/tmp'):
        if isinstance(openocd_script, str):
            self.openocd_files = [openocd_script]
        elif isinstance(openocd_script, list):
            self.openocd_files = openocd_script
        else:
            raise TypeError("Wrong type for OpenOCD configuration files")

        self._telnet = None
        self._telnet_port = telnet_port
        
        executable_path = distutils.spawn.find_executable(openocd_executable)

        self._cmd_line = [executable_path ,
                          '--command', 'telnet_port %d' % telnet_port,
                          '--command', 'gdb_port %d' % gdb_port]
        self._cmd_line += additional_args
        self._cmd_line += [e for l
                           in [['-f', abspath(f)] for f in self.openocd_files]
                           for e in l]

        self._openocd = None

        with open("%s/openocd_out.txt" % output_directory, "wb") as out, \
                open("%s/openocd_err.txt" % output_directory, "wb") as err:
            self._openocd = subprocess.Popen(self._cmd_line,
                                             stdout=out, stderr=err)#, shell=True)
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def execute_command(self, command, recv_response=False):
        try:
            self.log.debug("Executing command %s" % command)
            self._telnet.write((command + "\n").encode('ascii'))
            resp = ''

            if recv_response:
                resp = self._telnet.read_until(END_OF_MSG)
                self.log.debug("Got response %s" % resp)
            return resp
        except Exception, e:
            self.log.exception("Error executing OpenOCD command:")
            raise e

    def connect(self):
        """
        Connects to OpenOCDs telnet-server for all subsequent communication
        returns: True on success, else False
        """

        self._telnet = telnetlib.Telnet('127.0.0.1', self._telnet_port)
        resp = self._telnet.read_until(END_OF_MSG)
        if 'Open On-Chip Debugger' in str(resp):
            return True
        else:
            self.log.error('Failed to connect to OpenOCD')
            return False

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
            elif isinstance(val, int):
                write_val = hex(val)
            else:
                # A list of ints
                write_val = hex(val[i])
            write_addr = hex(address + i)
            self.execute_command('mww %s %s' % (write_addr, write_val), recv_response=True)
            # TODO: error handling
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
            read_addr = hex(address + i)
            resp = self.execute_command('mrw %s' % read_addr, recv_response=True)
            if resp:
                # Parse some shit
                # TODO: Fix execute_command
                val = int(resp.splitlines()[1])
                raw_mem += binascii.unhexlify(hex(val)[2:].zfill(wordsize * 2))
            else:
                self.log.error("Could not read from address %s" % read_addr)
                return None
        # OCD flips the endianness
        raw_mem = "".join(reversed(raw_mem))
        if raw:
            return raw_mem
        else:
            # Todo: Endianness support
            fmt = '<%d%s' % (num_words, num2fmt[wordsize])
            mem = list(unpack(fmt, raw_mem))
            if num_words == 1:
                return mem[0]
            else:
                return mem


    def reset(self):
        """
        Resets the target
        returns: True on success, else False
        """
        self._telnet.write('reset halt\n'.encode('ascii'))
        resp = self._telnet.read_until(END_OF_MSG)
        if 'target state: halted' in str(resp):
            return True
        else:
            self.log.error('Failed to reset the target with OpenOCD')
            return False

    def shutdown(self):
        """
        Shuts down OpenOCD
        returns: True on success, else False
        """
        if self._telnet:
            self._telnet.close()
        if self._openocd is not None:
            self._openocd.terminate()
            self._openocd = None
