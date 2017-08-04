import sys

if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

import logging
import json
import telnetlib
import re


class QMPProtocol(object):
    def __init__(self, port, origin=None):

        self.port = port
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)
        self.id = 0

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
        # self._communicator.stop()
        pass

    def get_registers(self):
        """
        Gets the current register state based on the hmp info registers
        command. In comparison to register-access with the register protocol,
        this function can also be called while the target is executing.
        returns: A dictionary with the registers
        """
        regs_s = self.execute_command("human-monitor-command",
                                      {"command-line": "info registers"})
        regs_r = re.findall('(...)=([0-9a-f]{8})', regs_s)
        return dict([(r.lower(), int(v, 16)) for r, v in regs_r])


    def inject_interrupt(self, interrupt_number, cpu_number=0):
        self.execute_command('avatar-arm-irq', {'num_irq': interrupt_number,
                                                'num_cpu': cpu_number})
