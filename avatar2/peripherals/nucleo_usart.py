import socket

from threading import Thread, Lock, Event
from .avatar_peripheral import AvatarPeripheral

SR_RXNE = 0x20
SR_TXE = 0x80
SR_TC = 0x40


class NucleoRTC(AvatarPeripheral):
    def nop_read(self, offset, size):
        return 0x00

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        self.read_handler[0:size] = self.nop_read


class NucleoTIM(AvatarPeripheral):
    def nop_read(self, offset, size):
        return 0x00

    def nop_write(self, offset, size, value):
        return True

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        self.read_handler[0:size] = self.nop_read
        self.write_handler[0:size] = self.nop_write


class NucleoUSART(AvatarPeripheral, Thread):
    def read_status_register(self, offset, size):
        self.lock.acquire(True)
        ret = self.status_register
        self.lock.release()
        return ret

    def read_data_register(self, offset, size):
        self.lock.acquire(True)
        ret = self.data_buf[0]
        self.data_buf = self.data_buf[1:]
        if len(self.data_buf) == 0:
            self.status_register &= ~SR_RXNE
        self.lock.release()
        #print(">>> %s" % hex(ret))
        return ret

    def write_data_register(self, offset, size, value):
        if self.connected:
            self.conn.send(bytes((chr(value).encode('utf-8'))))
        #print("<<< %s" % hex(value))
        return True

    def nop_read(self, offset, size):
        return 0x00

    def nop_write(self, offset, size, value):
        return True

    def __init__(self, name, address, size, nucleo_usart_port=5656, **kwargs):
        Thread.__init__(self)
        AvatarPeripheral.__init__(self, name, address, size)
        self.port = nucleo_usart_port

        self.data_buf = bytearray()
        self.status_register = SR_TXE | SR_TC

        self.read_handler[0:4] = self.read_status_register
        self.read_handler[4:8] = self.read_data_register
        self.write_handler[0:4] = self.nop_write
        self.write_handler[4:8] = self.write_data_register

        self.read_handler[8:size] = self.nop_read
        self.write_handler[8:size] = self.nop_write

        self.connected = False

        self.lock = Lock()
        self._close = Event()
        self.sock = None
        self.conn = None
        self.daemon = True
        self.start()

    def shutdown(self):
        self._close.set()

        if self.conn:
            self.conn.close()

        if self.sock:
            self.sock.close()

    # Pretender compat layer.
    def read(self, address, size):
        return self.read_memory(address, size)

    def write(self, address, size, value):
        return self.write_memory(address, size, value)

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(0)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.settimeout(0.1)

        while not self._close.is_set():
            self.sock.listen(1)

            try:
                self.conn, addr = self.sock.accept()
                self.conn.settimeout(0.1)
                self.connected = True
            except socket.timeout:
                continue
            except OSError as e:
                if e.errno == 9:
                    # Bad file descriptor error. Only happens when we called
                    # closed on the socket, the continuing the loop will 
                    # terminate, which is the desired behaviour
                    continue
                else:
                    # Something terrible happened
                    raise (e)

            while not self._close.is_set():
                try:
                    chr = self.conn.recv(1)
                except socket.timeout:
                    continue
                if not chr:
                    break
                self.lock.acquire(True)
                self.data_buf += chr
                self.status_register |= SR_RXNE
                self.lock.release()
            self.connected = False
