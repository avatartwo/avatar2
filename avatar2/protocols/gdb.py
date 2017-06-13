import sys
if sys.version_info < (3, 0):
    import Queue as queue
    #__class__ = instance.__class__
else:
    import queue

from threading import Thread, Event, Condition
from struct import pack, unpack
from codecs import encode
from string import hexdigits
import logging
import pygdbmi.gdbcontroller

from avatar2.archs.arm import ARM 
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage


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

    def __init__(self, gdb_protocol, gdb_controller, avatar_queue, origin=None):
        super(GDBResponseListener, self).__init__()
        self._protocol = gdb_protocol
        self._token = -1
        self._async_responses = queue.Queue() if avatar_queue is None\
            else avatar_queue
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
            raise RunTimeError()

        msg = response['message']
        payload = response['payload']
        avatar_msg = None

        self.log.debug("Received Message: %s", msg)

        if msg.startswith('thread'):
            pass  # Thread group handling is not implemented yet
        elif msg.startswith('tsv'):
            pass  # likewise tracing
        elif msg.startswith('library'):
            pass  # library loading not supported yet
        elif msg == 'breakpoint-modified':
            pass  # ignore breakpoint modified for now
        elif msg == 'memory-changed':
            pass  # ignore changed memory for now
        elif msg == 'stopped':
            if payload.get('reason') == 'breakpoint-hit':
                avatar_msg = BreakpointHitMessage(self._origin, payload['bkptno'], 
                                              int(payload['frame']['addr'], 16))
            elif payload.get('reason') == 'exited-normally':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.EXITED)
            elif payload.get('reason') == 'end-stepping-range':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'signal-received':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') == 'watchpoint-trigger':
                avatar_msg = UpdateStateMessage(
                    self._origin, TargetStates.STOPPED)
            elif payload.get('reason') is not None:
                self.log.critical("Target stopped with unknown reason: %s" %
                             payload['reason'])
                #raise RuntimeError
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
            pass  # TODO: implement handler for console messages
        elif response['type'] == 'log':
            pass  # TODO: implement handler for log messages
        elif response['type'] == 'target':
            pass  # TODO: implement handler for target messages
        elif response['type'] == 'output':
            pass # TODO: implement handler for output messages
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
        while(1):
            if self._close.is_set():
                break

            responses = None

            try:
                responses = self._gdb_controller.get_gdb_response(
                    timeout_sec=0.5
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
                    self.log.debug("Parsed an avatar_msg %s", avatar_msg)
                    if avatar_msg is not None:
                        if self._gdb._async_message_handler is not None:
                            self._gdb._async_message_handler(avatar_msg)
                        else:
                            self._async_responses.put(avatar_msg)
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()


class GDBProtocol(object):
    """Main class for the gdb communication protocol
    :ivar gdb_executable: the path to the gdb which should be executed
    :ivar arch:     the architecture
    :ivar additional_args: additional arguments for gdb
    :ivar avatar_queue : The queue serving as message sink for async messages
    """

    def __init__(
            self,
            gdb_executable="gdb",
            arch=ARM,
            additional_args=[],
            async_message_handler=None,
            avatar_queue=None,
            origin=None):
        self._async_message_handler = async_message_handler
        self._arch = arch
        self._gdbmi = pygdbmi.gdbcontroller.GdbController(
            gdb_path=gdb_executable,
            gdb_args=[
                '--nx',
                '--quiet',
                '--interpreter=mi2'] +
            additional_args,
            verbose=False)  # set to True for debugging
        self._communicator = GDBResponseListener(
            self, self._gdbmi, avatar_queue, origin)
        self._communicator.start()
        self._avatar_queue = avatar_queue
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


    def _sync_request(self, request, rexpect):
        """ Generic method to send a synchronized request

        :param request: the request as list
        :param rexpect: the expected response type
        :returns: Whether a response of type rexpect was received
        :returns: The response
        """

        token = self._communicator.get_token()
        request = [request] if isinstance(request, str) else request

        req = str(token) + ' '.join(request)
        self.log.debug("Sending request: %s" % req)

        self._gdbmi.write(req, read_response=False)
        try:
            response = self._communicator.get_sync_response(token)
            ret = True if response['message'] == rexpect else False
        except:
            response = None
            ret = None
        return ret, response

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
            raise Exception("GDBProtocol was unable to switch to asynch")

        req = ['-target-select', 'remote', '%s:%d' % (ip, int(port))]
        ret, resp = self._sync_request(req, GDB_PROT_CONN)

        self.log.debug(
            "Attempted to connect to target. Received response: %s" %
            resp)
        if not ret:
            self.log.critical("GDBProtocol was unable to connect to remote target")
            raise Exception("GDBProtocol was unable to connect")

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

        req = ['-target-select', 'remote', '%s' % (device)]
        ret, resp = self._sync_request(req, GDB_PROT_CONN)

        self.log.debug(
            "Attempted to connect to target. Received response: %s" %
            resp)
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

    def set_breakpoint(self, line,
                       hardware=False,
                       temporary=False,
                       regex=False,
                       condition=None,
                       ignore_count=0,
                       thread=0):
        """Inserts a breakpoint

        :param bool hardware: Hardware breakpoint
        :param bool tempory:  Tempory breakpoint
        :param str regex:     If set, inserts breakpoints matching the regex
        :param str condition: If set, inserts a breakpoint with specified condition
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
            assert((not temporary) and (not condition) and (not ignore_count))
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

        if isinstance(line, int):
            cmd.append("*0x%x" % line)
        else:
            cmd.append(str(line))

        ret, resp = self._sync_request(cmd, GDB_PROT_DONE)
        self.log.debug("Attempted to set breakpoint. Received response: %s" % resp)
        if ret == True:
            return int(resp['payload']['bkpt']['number'])
        else:
            return -1

    def set_watchpoint(self, variable, write=True, read=False):
        cmd = ["-break-watch"]
        if read == False and write == False:
            raise ValueError("At least one read and write must be True")
        elif read == True and write == False:
            cmd.append("-r")
        elif read == True and write == True:
            cmd.append("-a")

        if isinstance(variable, int):
            cmd.append("*0x%x" % variable)
        else:
            cmd.append(str(variable))

        ret, resp = self._sync_request(cmd, GDB_PROT_DONE)
        self.log.debug("Attempted to set watchpoint. Received response: %s" % resp)

        if ret == True:
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
        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8:'Q'}

        max_write_size = 0x100

        if raw == True:
            for i in range(0, len(val), max_write_size):
                write_val = encode(val[i:max_write_size+i], 'hex_codec').decode('ascii')
                ret, resp = self._sync_request(
                    ["-data-write-memory-bytes", str(address+i), write_val], 
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

        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8:'Q'}

        max_read_size = 0x100
        raw_mem = b''
        for i in range(0, wordsize*num_words, max_read_size):
            to_read = max_read_size if wordsize*num_words > i+max_read_size-1 else \
                      wordsize*num_words % max_read_size
            res, resp = self._sync_request(["-data-read-memory-bytes", str(address+i),
                                            str(to_read)], 
                GDB_PROT_DONE)

            self.log.debug("Attempted to read memory. Received response: %s" % resp)

            if not res:
                raise Exception("Failed to read memory!")

            # the indirection over the bytearray is needed for legacy python support
            read_mem = bytearray.fromhex(resp['payload']['memory'][0]['contents'])
            raw_mem += bytes(read_mem)

        if raw == True:
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
        return self.read_register_from_nr(self._arch.registers[reg])

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

    def set_endianness(self, endianness='little'):
        req = ['-gdb-set', 'endian', '%s' % endianness]
        ret, resp = self._sync_request(req, GDB_PROT_DONE)

        self.log.debug("Attempt to set endianness of the target. Received: %s" %
                       resp)
        return ret
