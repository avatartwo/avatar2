import socket

from threading import Thread, Lock, Event
from .avatar_peripheral import AvatarPeripheral

REG_CTRL = 0x0
REG_STATUS = 0x4
REG_INTEN = 0x8
REG_INTFL = 0xC
REG_BAUD_INT = 0x10
REG_BAUD_DIF = 0x14
REG_TX_FIFO_OUT = 0x18
REG_FLOW_CTRL = 0x1C
REG_TX_RX = 0x20

ST_TX_BUSY       = 0b0000000000000001
ST_RX_BUSY       = 0b0000000000000010 
ST_RX_FIFO_EMPTY = 0b0000000000010000
ST_RX_FIFO_FULL  = 0b0000000000100000
ST_TX_FIFO_EMPTY = 0b0000000001000000
ST_TX_FIFO_FULL =  0b0000000010000000
ST_RX_FIFO_CHRS =  0b0000111100000000
ST_TX_FIFO_CHRS =  0b1111000000000000


class Max32UART(AvatarPeripheral, Thread):
    def read_status_register(self, size):
        self.lock.acquire(True)
        ret = self.status_register
        self.lock.release()
        return ret

    def read_data_register(self, size):
        self.lock.acquire(True)
        ret = self.data_buf[0]
        self.data_buf = self.data_buf[1:]
        if len(self.data_buf) == 0:
            self.status_register &= ~ST_RX_FIFO_FULL
            self.status_register |= ST_RX_FIFO_EMPTY
        elif len(self.data_buf) < 16:
            self.status_register &= ~ST_RX_FIFO_FULL
            self.status_register &= ~ST_RX_FIFO_EMPTY
        elif len(self.data_buf) == 16:
            self.status_register |= ~ST_RX_FIFO_FULL
            self.status_register &= ~ST_RX_FIFO_EMPTY
        self.status_register &= ~ST_RX_FIFO_CHRS
        self.status_register |= len(self.data_buf) << 8
        self.lock.release()
        #print( ">>> %s" % hex(ret))
        return ret

    def write_data_register(self, size, value):
        if self.connected:
            self.conn.send(bytes((chr(value).encode('utf-8'))))
        #print("<<< %s" % hex(value))
        return True
        

    def read_config_register(self, size):
        return self.config_register

    def write_config_register(self, size, value):
        self.config_register = value
        return True

    def nop_read(self, size):
        return 0x00

    def nop_write(self, size, value):
        return True

    def __init__(self, name, address, size, nucleo_usart_port=5656, **kwargs):
        Thread.__init__(self)
        AvatarPeripheral.__init__(self, name, address, size)
        self.port = nucleo_usart_port
        
        self.data_buf = bytearray()
        self.status_register = ST_TX_FIFO_EMPTY | ST_RX_FIFO_EMPTY
        
        self.read_handler[REG_CTRL:REG_CTRL+4] = self.read_config_register
        self.write_handler[REG_CTRL:REG_CTRL+4] = self.write_config_register
        
        self.read_handler[REG_STATUS:REG_STATUS+4] = self.read_status_register
        self.write_handler[REG_STATUS:REG_STATUS+4] = self.nop_write

        self.read_handler[REG_STATUS+4:0x20] = self.nop_read
        self.write_handler[REG_STATUS+4:0x20] = self.nop_write

        self.read_handler[0x20:0x24] = self.read_data_register
        self.write_handler[0x20:0x24] = self.write_data_register

        
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
                if len(self.data_buf) == 0:
                    self.status_register &= ~ST_RX_FIFO_FULL
                    self.status_register |= ST_RX_FIFO_EMPTY
                elif len(self.data_buf) < 16:
                    self.status_register &= ~ST_RX_FIFO_FULL
                    self.status_register &= ~ST_RX_FIFO_EMPTY
                elif len(self.data_buf) == 16:
                    self.status_register |= ~ST_RX_FIFO_FULL
                    self.status_register &= ~ST_RX_FIFO_EMPTY
                self.status_register &= ~ST_RX_FIFO_CHRS
                self.status_register |= len(self.data_buf) << 8
                self.lock.release()
            self.connected = False
