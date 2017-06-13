import sys
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

from threading import Thread, Event, Condition
import logging
import json
import telnetlib
import re


class QMPResponseListener(Thread):

    def __init__(self, gdb_protocol, gdb_controller, avatar_queue, origin=None):
        super(QMPResponseListener, self).__init__()
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


class QMPProtocol(object):
    
    def __init__(self, port, origin=None):
                 
        self.port = port
        self.log = logging.getLogger('%s.%s' % 
                                     (origin.log.name, self.__class__.__name__)
                                    ) if origin else \
                                     logging.getLogger(self.__class__.__name__)
        self.id = 0

        #self._communicator = QMPResponseListener(self, origin.avatar.queue, 
                                                 #origin)
        #self._communicator.start()

    def __del__(self):
        self.shutdown()

    def connect(self):
        self._telnet = telnetlib.Telnet('127.0.0.1', self.port)
        self._telnet.read_until('\r\n'.encode('ascii'))
        self.execute_command('qmp_capabilities')
        return True


    def execute_command(self, cmd, args=None):
        command = {}
        command['execute'] = cmd
        if args:
            command['arguments'] = args
        command['id'] = self.id
        self._telnet.write(('%s\r\n' % json.dumps(command)).encode('ascii'))

        while True:
            resp = self._telnet.read_until('\r\n'.encode('ascii'))
            resp = json.loads(resp.decode('ascii'))
            if 'event' in resp:
                continue
            if 'id' in resp:
                break
        if resp['id'] != self.id:
            raise Exception('Mismatching id for qmp response')
        self.id += 1
        if 'error' in resp:
            return resp['error']
        if 'return' in resp:
            return resp['return']
        raise Exception("Response contained neither an error nor an return")
        

    def reset(self):
        """
        Resets the target
        returns: True on success, else False
        """
        pass

    def shutdown(self):
        """
        returns: True on success, else False
        """
        #self._communicator.stop()
        pass
    
    def get_registers(self):
        """
        Gets the current register state based on the hmp info registers
        command. In comparison to register-access with the register protocol,
        this function can also be called while the target is executing.
        returns: A dictionary with the registers
        """
        regs_s = self.execute_command("human-monitor-command",
                                    {"command-line":"info registers"})
        regs_r = re.findall('(...)=([0-9a-f]{8})', regs_s)
        return dict([(r.lower(), int(v,16)) for r,v in regs_r])

