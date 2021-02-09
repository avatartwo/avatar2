import sys
from threading import Thread, Event, Condition
from struct import pack, unpack
from codecs import encode

import logging
import re
import pygdbmi.gdbcontroller

import parse
if sys.version_info < (3, 0):
    import Queue as queue
    # __class__ = instance.__class__
else:
    import queue

from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage, SyscallCatchedMessage

GDB_PROT_DONE = 'done'
GDB_PROT_CONN = 'connected'
GDB_PROT_RUN = 'running'


class GDBResponseListener(Thread):
    """
    This class creates objects waiting for responses from the gdb-process
    Depending whether a synchronous or asynchronous message is received,
    it is either put in a synchronous dictionary or parsed/lifted
    to an AvatarMessage and added to the Queue of the according target
    """

    def __init__(self, gdb_protocol, gdb_controller, avatar_queue,
                 avatar_fast_queue,  origin=None):
        super(GDBResponseListener, self).__init__()
        self._protocol = gdb_protocol
        self._token = -1
        self._async_responses = queue.Queue() if avatar_queue is None \
            else avatar_queue
        self._async_fast_responses = queue.Queue() if avatar_fast_queue is None\
            else avatar_fast_queue
        self._sync_responses = {}
        self._gdb_controller = gdb_controller
        self._gdb = gdb_protocol
        self._close = Event()
        self._closed = Event()
        self._close.clear()
        self._closed.clear()
        self._sync_responses_cv = Condition()
        self._last_exec_token = 0
        self._origin = origin
        self._console_output = None
        self._console_enable = False
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def get_token(self):
        """Gets a token for a synchronous request
        :returns: An (integer) token
        """
        self._token += 1
        return self._token

    def parse_async_notify(self, response):
        """
        This functions converts gdb notify messages to an avatar message

        :param response: A pygdbmi response dictonary
        :returns:        An avatar message
        """

        # Make sure this is a notify-response
        if response['type'] != 'notify':
            raise RuntimeError()

        msg = response['message']
        payload = response['payload']
        avatar_msg = None

        self.log.debug("Received Message: %s", msg)

        if msg.startswith('thread'):
            if msg == 'thread-group-exited':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.EXITED)
        elif msg.startswith('tsv'):
            pass  # likewise tracing
        elif msg.startswith('library'):
            pass  # library loading not supported yet
        elif msg == 'breakpoint-modified':
            pass  # ignore breakpoint modified for now
        elif msg == 'breakpoint-created':
            pass  # ignore breakpoint created for now
        elif msg == 'memory-changed':
            pass  # ignore changed memory for now
        elif msg == 'stopped':
            if payload.get('reason') == 'breakpoint-hit':
                avatar_msg = BreakpointHitMessage(self._origin, int(payload['bkptno']),
                                                  int(payload['frame']['addr'], 16))
            elif payload.get('reason') == 'exited-normally':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.EXITED)
            elif payload.get('reason') == 'end-stepping-range':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'signal-received':
                if payload.get('signal-name') == 'SIGSEGV':
                    avatar_msg = UpdateStateMessage(
                        self._origin, TargetStates.EXITED)
                elif payload.get('signal-name') == 'SIGTRAP':
                    avatar_msg = BreakpointHitMessage(self._origin, -1,
                                                      int(payload['frame']['addr'], 16))
                else:
                    avatar_msg = UpdateStateMessage(
                        self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'watchpoint-trigger':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'access-watchpoint-trigger':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'read-watchpoint-trigger':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'syscall-entry':
                avatar_msg = SyscallCatchedMessage(self._origin, int(payload['bkptno']),
                                                  int(payload['frame']['addr'], 16), 'entry')
            elif payload.get('reason') == 'syscall-return':
                avatar_msg = SyscallCatchedMessage(self._origin, int(payload['bkptno']),
                                                  int(payload['frame']['addr'], 16), 'return')
            elif payload.get('reason') is not None:
                self.log.critical("Target stopped with unknown reason: %s" %
                                  payload['reason'])
                # raise RuntimeError
            else:
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
        elif msg == 'running':
            avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)

        else:
            self.log.critical('Catched unknown async message: %s' % response)

        return avatar_msg

    def parse_async_response(self, response):
        """
        This functions converts a async gdb/mi message to an avatar message

        :param response: A pygdbmi response dictonary
        """

        if response['type'] == 'console':
            self.collect_console_output(response)
        elif response['type'] == 'log':
            pass  # TODO: implement handler for log messages
        elif response['type'] == 'target':
            pass  # TODO: implement handler for target messages
        elif response['type'] == 'output':
            pass  # TODO: implement handler for output messages
        elif response['type'] == 'notify':
            return self.parse_async_notify(response)


        else:
            raise Exception("GDBProtocol got unexpected response of type %s" %
                            response['type'])

    def get_async_response(self, timeout=0):
        return self._async_responses.get(timeout=timeout)

    def get_sync_response(self, token, timeout=5):
        for x in range(timeout * 2):
            self._sync_responses_cv.acquire()
            ret = self._sync_responses.pop(token, None)
            if ret is None:
                self._sync_responses_cv.wait(timeout=0.5)

            self._sync_responses_cv.release()
            if ret is not None:
                return ret
        raise TimeoutError()

    def run(self):
        while 1:
            if self._close.is_set():
                break

            try:
                responses = self._gdb_controller.get_gdb_response(
                    timeout_sec=0.01
                )
            except:
                continue

            for response in responses:
                if response.get('token', None) is not None:
                    self._sync_responses_cv.acquire()
                    self._sync_responses[response['token']] = response
                    self._sync_responses_cv.notifyAll()
                    self._sync_responses_cv.release()
                else:
                    avatar_msg = self.parse_async_response(response)
                    if avatar_msg is not None:
                        self.log.debug("Parsed an avatar_msg %s", avatar_msg)
                        if self._gdb._async_message_handler is not None:
                            self._gdb._async_message_handler(avatar_msg)
                        else:
                            if isinstance(avatar_msg, UpdateStateMessage):
                                self._async_fast_responses.put(avatar_msg)
                            else:
                                self._async_responses.put(avatar_msg)
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()

    def start_console_collection(self):
        self._console_output = ""
        self._console_enable = True

    def stop_console_collection(self):
        self._console_enable = False

    def collect_console_output(self, msg):
        if self._console_enable:
            self._console_output += '\n'
            self._console_output += msg['payload']

class GDBProtocol(object):
    """Main class for the gdb communication protocol
    :ivar gdb_executable: the path to the gdb which should be executed
    :ivar arch:     the architecture
    :ivar additional_args: additional arguments for gdb
    :ivar avatar:   the avatar object
    :ivar origin:   the target utilizing this protocol
    """

    def __init__(
            self,
            gdb_executable="gdb",
            arch=ARM,
            additional_args=[],
            async_message_handler=None,
            avatar=None,
            origin=None,
            enable_init_files=False,
            binary=None,
            local_arguments=None,
            verbose=False):
        self._async_message_handler = async_message_handler
        self._arch = arch
        self._register_mapping = dict(arch.registers)

        gdb_args = []
        if not enable_init_files:
            gdb_args += ['--nx']
        gdb_args += ['--quiet', '--interpreter=mi2']
        gdb_args += additional_args
        if binary is not None:
            gdb_args += ['--args', binary]
            if local_arguments is not None:
                gdb_args += [local_arguments]


        if sys.version_info <= (3, 5):
            self._gdbmi = pygdbmi.gdbcontroller.GdbController(
                gdb_path=gdb_executable,
                gdb_args=gdb_args,
                verbose=verbose)  # set to True for debugging
        else:
            self._gdbmi = pygdbmi.gdbcontroller.GdbController(
                command=[gdb_executable] + gdb_args,
                time_to_check_for_additional_output_sec=0)
        queue = avatar.queue if avatar is not None else None
        fast_queue = avatar.fast_queue if avatar is not None else None
        self._communicator = GDBResponseListener(
            self, self._gdbmi, queue, fast_queue, origin)
        self._communicator.daemon = True
        self._communicator.start()
        self._origin = origin
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self._communicator is not None:
            self._communicator.stop()
            self._communicator = None
        if self._gdbmi is not None:
            self._gdbmi.exit()
            self._gdbmi = None

    def _sync_request(self, request, rexpect, timeout=5):
        """ Generic method to send a syncronized request

        :param request: the request as list
        :param rexpect: the expected response type
        :returns: Whether a response of type rexpect was received
        :returns: The response
        """

        token = self._communicator.get_token()
        request = [request] if isinstance(request, str) else request

        req = str(token) + ' '.join(request)
        self.log.debug("Sending request: %s" % req)

        self._gdbmi.write(req, read_response=False, timeout_sec=0)
        try:
            response = self._communicator.get_sync_response(token, timeout=timeout)
            ret = True if response['message'] == rexpect else False
        except:
            response = None
            ret = None
        return ret, response

    def set_abi(self, abi):
        req = ['-gdb-set', self._arch.gdb_name, 'abi', abi]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)

        if not ret:
            self.log.critical(
                "Unable to set abi to %s, received response: %s" %
                (abi, resp))
            raise Exception("GDBProtocol was unable to set ABI")

        return ret

    def remote_connect(self, ip='127.0.0.1', port=3333):
        """
        connect to a remote gdb server

        :param ip: ip of the remote gdb-server (default: localhost)
        :param port: port of the remote gdb-server (default: port)
        :returns: True on successful connection
        """

        req = ['-gdb-set', 'target-async', 'on']
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        if not ret:
            self.log.critical(
                "Unable to set GDB/MI to async, received response: %s" %
                resp)
            raise Exception("GDBProtocol was unable to switch to async")

        req = ['-gdb-set', 'architecture', self._arch.gdb_name]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)


        if not ret:
            self.log.critical(
                "Unable to set architecture, received response: %s" %
                resp)
            raise Exception(("GDBProtocol was unable to set the architecture\n"
                             "Did you select the right gdb_executable?"))

        # if we are on ARM, set abi to AAPPCS to avoid bugs due to
        # fp-derefencation (https://github.com/avatartwo/avatar2/issues/19)
        if self._arch.gdb_name == 'arm':
            self.set_abi('AAPCS')

        if hasattr(self._arch, 'endian'):
            req = ['-gdb-set', 'endian', self._arch.endian]
            ret, resp = self._sync_request(req, GDB_PROT_DONE)
            if not ret:
                self.log.critical(
                    "Unable to set endianness, received response: %s" %
                    resp)
                raise Exception("GDBProtocol was unable to set endianness")

        req = ['-target-select', 'remote', '%s:%d' % (ip, int(port))]
        ret, resp = self._sync_request(req, GDB_PROT_CONN)

        self.log.debug(
            "Attempted to connect to target. Received response: %s" %
            resp)
        if not ret:
            self.log.critical("GDBProtocol was unable to connect to remote target")
            raise Exception("GDBProtocol was unable to connect")

        self.update_target_regs()

        return ret

    def remote_connect_serial(self, device='/dev/ttyACM0', baud_rate=38400,
                              parity='none'):
        """
        connect to a remote gdb server through a serial device

        :param device: file representing the device (default: /dev/ttyACM0)
        :param baud_rate: baud_rate of the serial device (default: 38400)
        :param parity: parity of the serial link (default no parity)
        :returns: True on successful connection
        """

        req = ['-gdb-set', 'architecture', self._arch.gdb_name]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        if not ret:
            self.log.critical(
                "Unable to set architecture, received response: %s" %
                resp)
            raise Exception(("GDBProtocol was unable to set the architecture\n"
                             "Did you select the right gdb_executable?"))

        if parity not in ['none', 'even', 'odd']:
            self.log.critical("Parity must be none, even or odd")
            raise Exception("Cannot set parity to %s" % parity)

        req = ['-gdb-set', 'mi-async', 'on']
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        if not ret:
            self.log.critical(
                "Unable to set GDB/MI to async, received response: %s" %
                resp)
            raise Exception("GDBProtocol was unable to connect")

        req = ['-gdb-set', 'serial', 'parity', '%s' % parity]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        if not ret:
            self.log.critical("Unable to set parity")
            raise Exception("GDBProtocol was unable to set parity")

        req = ['-gdb-set', 'serial', 'baud', '%i' % baud_rate]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        if not ret:
            self.log.critical("Unable to set baud rate")
            raise Exception("GDBProtocol was unable to set Baudrate")

        req = ['-target-select', 'remote', '%s' % device]
        ret, resp = self._sync_request(req, GDB_PROT_CONN)

        self.log.debug(
            "Attempted to connect to target. Received response: %s" %
            resp)

        self.update_target_regs()

        return ret

    def remote_disconnect(self):
        """
        disconnects from remote target
        """

        ret, resp = self._sync_request('-target-disconnect', GDB_PROT_DONE)

        self.log.debug(
            "Attempted to disconnect from target. Received response: %s" %
            resp)
        return ret

    def get_register_names(self):
        """fetch all register names
        :returns:  a list with all registers names, in order as known to gdb
        """

        ret, resp = self._sync_request(
            '-data-list-register-names', GDB_PROT_DONE)

        self.log.debug(
            "Attempted to obtain register names. Received response: %s" % resp)
        return resp['payload']['register-names'] if ret else None

    def update_target_regs(self):
        """
        This function will try to update the TargetRegs based on the list of
        registers known to gdb.
        """
        if hasattr(self._origin, 'regs'):
            regs = self.get_register_names()
            regs_dict = dict([(r,i) for i, r in enumerate(regs) if r != ''])
            self._origin.regs._update(regs_dict)


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
                              Note: This allows only a single condition. For more
                                    complex ones, please use set_break_condition()
        :param int ignore_count: Amount of times the bp should be ignored
        :param int thread:    Threadno in which this breakpoints should be added
        :returns:             The number of the breakpoint
        """
        cmd = ["-break-insert"]
        if temporary:
            cmd.append("-t")
        if hardware:
            cmd.append("-h")
        if regex:
            assert ((not temporary) and (not condition) and (not ignore_count))
            cmd.append("-r")
            cmd.append(str(regex))
        if condition:
            cmd.append("-c")
            cmd.append(str(condition))
        if ignore_count:
            cmd.append("-i")
            cmd.append("%d" % ignore_count)
        if thread:
            cmd.append("-p")
            cmd.append("%d" % thread)
        if pending:
            cmd.append("-f")

        if isinstance(line, int):
            cmd.append("*0x%x" % line)
        else:
            cmd.append(str(line))

        ret, resp = self._sync_request(cmd, GDB_PROT_DONE)
        self.log.debug("Attempted to set breakpoint. Received response: %s" % resp)
        return int(resp['payload']['bkpt']['number']) if ret else -1

    def set_break_condition(self, bp_no, condition='1'):
        """
        Modifies the break condition for a given break-point
        :param bp_no: the breakpoint whose condition should be modified
        :param condition: The condition string to use.
                          The default value, '1', will make the bp unconditional
        """
        cmd = ["-break-condition", str(bp_no), condition]
        ret, resp = self._sync_request(cmd, GDB_PROT_DONE)
        self.log.debug("Attempted to set break-condition. Received response: %s" % resp)
        return ret

    def set_watchpoint(self, variable, write=True, read=False):
        cmd = ["-break-watch"]
        if read is True and write is True:
            cmd.append("-a")
        elif read is True:
            cmd.append("-r")
        elif write is True:
            pass
        else:
            raise ValueError("At least one read and write must be True")

        if isinstance(variable, int):
            cmd.append("*0x%x" % variable)
        else:
            cmd.append(str(variable))

        ret, resp = self._sync_request(cmd, GDB_PROT_DONE)
        self.log.debug("Attempted to set watchpoint. Received response: %s" % resp)

        if ret:
            # The payload contains different keys according to the
            # type of the watchpoint which has been set.
            # The possible keys are: [(hw-)][ar]wpt
            for k in resp['payload'].keys():
                if k.endswith('wpt'):
                    break
            else:
                return -1
            return int(resp['payload'][k]['number'])
        else:
            return -1

    def set_syscall_cachpoint(self, syscall):
        '''
        Set's up a syscall catchpoint.
        :param syscall: the syscall to catch; can be either its name or no
        '''
        # this command is not exported via gdb-mi, hence we need manual parsing
        ret = self.console_command('catch syscall %s' % syscall)
        if ret[0] is not True:
            return ret[0]
        # assume return message is in format of
        # '"\nCatchpoint 1 (syscall 'write' [4])\\n") '
        expected_bp_num = ret[1].split()[1]
        if not expected_bp_num.isdigit():
            self.log.warning("Couldn't extract bp_num for catchpoint!")
            return True
        return int(expected_bp_num)




    def remove_breakpoint(self, bkpt):
        """Deletes a breakpoint"""
        ret, resp = self._sync_request(
            ['-break-delete', str(bkpt)], GDB_PROT_DONE)

        self.log.debug(
            "Attempted to delete breakpoint. Received response: %s" %
            resp)
        return ret

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
        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}

        max_write_size = 0x100

        if raw:
            if not len(val):
                raise ValueError("val had zero length")
            for i in range(0, len(val), max_write_size):
                write_val = encode(val[i:max_write_size + i], 'hex_codec').decode('ascii')
                ret, resp = self._sync_request(
                    ["-data-write-memory-bytes", str(address + i), write_val],
                    GDB_PROT_DONE)

        else:
            fmt = '<%d%s' % (num_words, num2fmt[wordsize])
            if num_words == 1:
                contents = pack(fmt, val)
            else:
                contents = pack(fmt, *val)

            hex_contents = encode(contents, 'hex_codec').decode('ascii')
            ret, resp = self._sync_request(
                ["-data-write-memory-bytes", str(address), hex_contents],
                GDB_PROT_DONE)

        self.log.debug("Attempted to write memory. Received response: %s" % resp)
        return ret

    def read_memory(self, address, wordsize=4, num_words=1, raw=False):
        """reads memory

        :param address:   Address to write to
        :param wordsize:  the size of a read word (1, 2, 4 or 8)
        :param num_words: the amount of read words
        :param raw:       Whether the read memory should be returned unprocessed
        :return:          The read memory
        """

        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}

        max_read_size = 0x100
        raw_mem = b''
        for i in range(0, wordsize * num_words, max_read_size):
            to_read = max_read_size if wordsize * num_words > i + max_read_size - 1 else \
                wordsize * num_words % max_read_size
            res, resp = self._sync_request(["-data-read-memory-bytes", str(address + i),
                                            str(to_read)],
                                           GDB_PROT_DONE)

            self.log.debug("Attempted to read memory. Received response: %s" % resp)

            if not res:
                raise Exception("Failed to read memory!")

            # the indirection over the bytearray is needed for legacy python support
            read_mem = bytearray.fromhex(resp['payload']['memory'][0]['contents'])
            raw_mem += bytes(read_mem)

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

    def read_register(self, reg):
        if reg in self._arch.special_registers:
            return self._read_special_reg_from_name(reg)
        else:
            reg_nr = (
                self._origin.regs._get_nr_from_name(reg)
                if hasattr(self._origin, 'regs')
                else self._arch.registers[reg])
            return self.read_register_from_nr(reg_nr)

    def _read_special_reg_from_name(self, reg):
        """GDB does not return simple values for certain registers,
           such as SSE-registers on x86.
           This function tries to cover those cases by looking up an
           expression to access the register, and the resulting format,
           in the architecture description.
        """

        ret, resp = self._sync_request(
            ["-data-evaluate-expression", "%s" %
                self._arch.special_registers[reg]['gdb_expression']],
             GDB_PROT_DONE)
        fmt = self._arch.special_registers[reg]['format']
        res = parse.parse(fmt, resp['payload']['value'])
        if res is None:
            self.log.critical(
                "Unable to parse content of special register %s" % reg
            )
            raise Exception("Couldn't parse special register")
        return list(res)




    def read_register_from_nr(self, reg_num):
        """Gets the value of a single register

        :param reg_num: number of the register
        :returns:       the value as integer on success, else None
        :todo: Implement function for multiple registers
        """

        ret, resp = self._sync_request(
            ["-data-list-register-values", "x", "%d" % reg_num], GDB_PROT_DONE)

        self.log.debug(
            "Attempted to get register value. Received response: %s" %
            resp)
        return int(resp['payload']['register-values']
                   [0]['value'], 16) if ret else None

    def write_register(self, reg, value):
        """Set one register on the target
        :returns: True on success"""

        if reg in self._arch.special_registers:

            fmt = "{:s}=" \
                  + self._arch.special_registers[reg]['format'].replace(' ','')

            ret, resp = self._sync_request(
                ["-data-evaluate-expression", fmt.format(
                   self._arch.special_registers[reg]['gdb_expression'], *value)
                ], GDB_PROT_DONE
            )
        else:
            ret, resp = self._sync_request(
                ["-gdb-set", "$%s=0x%x" % (reg, value)], GDB_PROT_DONE)

        self.log.debug("Attempted to set register. Received response: %s" % resp)
        return ret

    def step(self):
        """Step one instruction on the target
        :returns: True on success"""
        ret, resp = self._sync_request(
            ["-exec-step-instruction"], GDB_PROT_RUN)

        self.log.debug(
            "Attempted to step on the target. Received response: %s" %
            resp)
        return ret

    def run(self):
        """Starts the execution of the target
        :returns: True on success"""
        ret, resp = self._sync_request(["-exec-run"], GDB_PROT_RUN)

        self.log.debug(
            "Attempted to start execution on the target. Received response: %s" %
            resp)
        return ret

    def cont(self):
        """Continues the execution of the target
        :returns: True on success"""
        ret, resp = self._sync_request(["-exec-continue"], GDB_PROT_RUN)

        self.log.debug(
            "Attempted to continue execution on the target. Received response: %s" %
            resp)
        return ret

    def stop(self):
        """Stops execution of the target
        :returns: True on success"""

        ret, resp = self._sync_request(
            ["-exec-interrupt", "--all"], GDB_PROT_DONE)

        self.log.debug(
            "Attempted to stop execution of the target. Received response: %s" %
            resp)
        return ret

    def set_file(self, elf=''):
        """Load an ELF file
        :returns: True on success"""
        ret, resp = self._sync_request(["-file-exec-and-symbols", elf], GDB_PROT_DONE)

        self.log.debug(
            "Attempted to load elf file. Received response: %s" %
            resp)
        return ret

    def download(self):
        """Download code to target
        :returns: True on success"""
        ret, resp = self._sync_request(["-target-download"], GDB_PROT_DONE, timeout=60)

        self.log.debug(
            "Attempted to download code to target. Received response: %s" %
            resp)
        return ret

    def set_endianness(self, endianness='little'):
        req = ['-gdb-set', 'endian', '%s' % endianness]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)

        self.log.debug("Attempt to set endianness of the target. Received: %s" %
                       resp)
        return ret

    def get_mappings(self):
        self._communicator.start_console_collection()
        req = ['info', 'proc', 'mappings']
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        self._communicator.stop_console_collection()
        self.log.debug("Attempt to read the memory mappings of the target. " +
                       "Received: %s" % resp)
        return ret, self._communicator._console_output

    def console_command(self, cmd, rexpect=GDB_PROT_DONE):
        self._communicator.start_console_collection()
        req = cmd.split()
        ret, resp = self._sync_request(req, rexpect)
        self._communicator.stop_console_collection()
        self.log.debug("Attempt to execute the console command: %s" % cmd)
        return ret, self._communicator._console_output

    def get_symbol(self, symbol):
        self._communicator.start_console_collection()
        req = ['info', 'address', '%s' % symbol]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        self._communicator.stop_console_collection()
        if ret:
            resp = self._communicator._console_output
            regex = re.compile("(0x[0-9a-f]*)[ .]")
            resp = regex.findall(resp)
            if len(resp) == 1:
                resp = int(resp[0], 16)
            else:
                resp = -1
                ret = False
        self.log.debug("Attempt to resolve the symbol %s. " +
                       "Received: %s" % resp)
        return ret, resp

    def set_gdb_variable(self, variable, value):
        req = ['-gdb-set', str(variable), str(value)]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)
        if ret:
            self.log.debug("Successfully set variable %s to %s" %
                           (str(variable), str(value)))
        else:
            self.log.debug("Unable to set variable %s to %s" %
                           (str(variable), str(value)))
        return ret

    def quit(self):
        req = ['-gdb-exit']
        ret = self._sync_request(req, GDB_PROT_DONE)
        return ret
