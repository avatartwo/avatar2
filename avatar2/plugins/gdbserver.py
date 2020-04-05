#/usr/bin/env 

import logging
import re
import socket
import binascii
import struct

import xml.etree.ElementTree as ET

from time import sleep
from struct import pack
from types import MethodType
from threading import Thread, Event
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from os.path import dirname

from avatar2.targets import TargetStates

l = logging.getLogger('avatar2.gdbplugin')

chksum = lambda x: sum(x) & 0xff
match_hex = lambda m, s: [int(x, 16) for x in re.match(m, s).groups()]

TIMEOUT_TIME = 1.0


class GDBRSPServer(Thread):

    def __init__(self, avatar, target, port=3333, xml_file=None,
                 do_forwarding=False):
        super().__init__()
        self.daemon=True
        self.sock = socket.socket(AF_INET, SOCK_STREAM)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        self.avatar = avatar
        self.target = target
        self.port = port
        self.xml_file = xml_file
        self.do_forwarding = do_forwarding

        self._packetsize=0x47FF
        self.running = False
        self.bps = {}
        self._do_shutdown = Event()
        

        xml_regs = ET.parse(self.xml_file).getroot().find('feature')
        self.registers = [reg.attrib for reg in xml_regs if reg.tag == 'reg']
        assert(len(self.registers))

        self.handlers = {
            'q' : self.query,
            'v' : self.multi_letter_cmd,
            'H' : self.set_thread_op,
            '?' : self.halt_reason,
            'g' : self.read_registers,
            'G' : self.reg_write,
            'm' : self.mem_read,
            'M' : self.mem_write,
            'c' : self.cont,
            'C' : self.cont, #cond with signal, we don't care
            's' : self.step,
            'S' : self.step,
            'S' : self.step_signal,
            'Z' : self.insert_breakpoint,
            'z' : self.remove_breakpoint,
            'D' : self.detach,
        }

    def shutdown(self):
        self._do_shutdown.set()
        sleep(TIMEOUT_TIME*2)

    def run(self):

        l.info(f'GDB server listening on port {self.port}, please connect')
        self.sock.bind(('', self.port))
        self.sock.settimeout(TIMEOUT_TIME)
        self.sock.listen(1)
        
        while not self._do_shutdown.isSet():
            try:
                self.conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            self.conn.settimeout(TIMEOUT_TIME)
            l.info(f'Accepted connection from {addr}')

            if not self.target.state & TargetStates.STOPPED:
                self.target.stop()
            while self.conn._closed is False:
                packet = self.receive_packet()
                if packet is None:
                    continue

                l.debug(f'Received: {packet}')
                self.send_raw(b'+') # send ACK

                handler = self.handlers.get(chr(packet[0]),
                                                self.not_implemented)
                resp = handler(packet)
                if resp is not None:
                    self.send_packet(resp)
        self.sock.close()


    ### Handlers
    def not_implemented(self, pkt):
        l.critical(f'Received not implemented packet: {pkt}')
        return b''

    def query(self, pkt):
        if pkt[1:].startswith(b'Supported') is True:
            feat = [b'PacketSize=%x' % self._packetsize,
                    b'qXfer:features:read+'
                   ]
            return b';'.join(feat)

        if pkt[1:].startswith(b'Attached') is True:
            return b'1'

        if pkt[1:].startswith(b'Xfer:features:read:target.xml') is True:
            off, length = match_hex('qXfer:features:read:target.xml:(.*),(.*)',
                                   pkt.decode())
            
            with open(self.xml_file, 'rb') as f:
                data = f.read()
            resp_data = data[off:off+length]
            if len(resp_data) < length:
                prefix = b'l'
            else:
                prefix = b'm'
            return prefix+resp_data

        if pkt[1:].startswith(b'fThreadInfo') is True:
            return b'm1'
        if pkt[1:].startswith(b'sThreadInfo') is True:
            return b'l'

        if pkt[1:].startswith(b'Rcmd') is True: # Monitor commands
            try:
                cmd = re.match('qRcmd,(.*)',pkt.decode())[1]
                cmd = binascii.a2b_hex(cmd) 
                l.debug(f'Receiced cmd: {cmd}')
                res = eval(cmd)
                
                self.send_packet(b'O' \
                            + binascii.b2a_hex(repr(res).encode()) \
                            + b'0a')
                return b'OK'
                
            except Exception as e:
                self.send_packet(b'O' + b'ERROR: '.hex().encode())
                
                if hasattr(e, 'msg'):
                    self.send_packet(b'O' \
                                + e.msg.encode().hex().encode() \
                                + b'0a')
                elif hasattr(e, 'args'):
                    self.send_packet(b'O' \
                                + e.args[0].encode().hex().encode() \
                                + b'0a')
                    
                return b'OK'

        return b''

    def multi_letter_cmd(self, pkt):
        if pkt[1:].startswith(b'vMustReplyEmpty') is True:
            return b''
        return b''

    def set_thread_op(self, pkt):
        return b'OK' # we don't implement threads yet

    def halt_reason(self, pkt):
        return b'S00' # we don't specify the signal yet

    def read_registers(self, pkt):
        resp = ''
        for reg in self.registers:
            
            bitsize = int(reg['bitsize'])
            assert( bitsize % 8 == 0)
            r_len = int(bitsize / 8)
            r_val = self.target.read_register(reg['name'])
            #l.debug(f'{reg["name"]}, {r_val}, {r_len}')

            resp += r_val.to_bytes(r_len, 'little').hex()
            
        return resp.encode()
    
    def reg_write(self, pkt):
        idx = 1 # ignore the first char of pkt
        for reg in self.registers:
            bitsize = int(reg['bitsize'])
            r_len = int(bitsize / 8)
            r_val = pkt[idx: idx + r_len*2]
            r_raw = bytes.fromhex(r_val.decode())
            int_val =  int.from_bytes(r_raw, byteorder='little')

            self.target.write_register(reg['name'], int_val)
            idx += r_len*2
        return b'OK'


    def mem_read(self, pkt):
        try:
            addr, n = match_hex('m(.*),(.*)', pkt.decode())

            if self.do_forwarding is True:
                mr = self.avatar.get_memory_range(addr)
                if mr is not None and mr.forwarded is True:
                    val = mr.forwarded_to.read_memory(addr, n)
                    val = val.to_bytes(n, byteorder='little')
                    return binascii.b2a_hex(val)

            val = self.target.read_memory(addr, n, raw=True).hex()
            return val.encode()
            
        except Exception as e:
            l.warn(f'Error in mem_read: {e}')
            return b'E00'


    def mem_write(self, pkt):
        try:
            addr, n, val = match_hex('M(.*),(.*):(.*)', pkt.decode())
            raw_val = val.to_bytes(n, byteorder='big') # wtf :/

            if self.do_forwarding is True:
                mr = self.avatar.get_memory_range(addr)
                if mr is not None and mr.forwarded is True:
                    int_val = int.from_bytes(raw_val,byteorder='little')
                    mr.forwarded_to.write_memory(addr, n, int_val)
                    return b'OK'

            self.target.write_memory(addr, n, raw_val, raw=True)
            return b'OK'
            
        except Exception as e:
            l.warn(f'Error in mem_write: {e}')
            return b'E00'


    def cont(self, pkt):
        self.target.cont()
        self.running = True
        return b'OK'

    def step(self, pkt):
        self.target.step()
        return b'S00'

    def step_signal(self, pkt):
        self.target.step()
        return pkt[1:]

    def insert_breakpoint(self, pkt):
        addr, kind = match_hex('Z0,(.*),(.*)', pkt.decode())
        bpno = self.target.set_breakpoint(addr)
        self.bps[bpno] = addr
        return b'OK'

    def remove_breakpoint(self, pkt):
        addr, kind = match_hex('z0,(.*),(.*)', pkt.decode())
        matches = []
        for n, a in self.bps.items():
            if a == addr:
                matches.append(n)
        if len(matches) == 0:
            l.warn(f'GDB tried to remove non existing bp for {addr}')
            l.info(self.bps)
            return b'E00'
        
        self.target.remove_breakpoint(n)
        self.bps.pop(n)
        return b'OK'

    def detach(self, pkt):
        l.info("Exiting GDB server")
        if not self.target.state & TargetStates.EXITED:
            for bpno in self.bps.items():
                self.target.remove_breakpoint(bpno)
            self.target.cont()
        if self.conn._closed is False:
            self.send_packet(b'OK')
            self.conn.close()
        
        return None

    ### Sending and receiving

    def send_packet(self, pkt):
        if type(pkt) == str:
            raise Exception("Packet require bytes, not strings")
        
        self.send_raw(b'$%b#%02x' % (pkt, chksum(pkt)))


    def send_raw(self, raw_bytes):
        l.debug(f'Sending data: {raw_bytes}')
        self.conn.send(raw_bytes)


    def check_breakpoint_hit(self):
        if self.target.state & TargetStates.STOPPED and self.running is True:
            if self.target.regs.pc in self.bps.values():
                self.running = False
                self.send_packet(b'S05')


    def receive_packet(self):
        pkt_finished = False
        pkt_receiving = False
        while pkt_finished is False:
            try:
                c = self.conn.recv(1)
            except socket.timeout:
                if self._do_shutdown.isSet():
                    self.send_packet(b'S03')
                    self.conn.close()
                    return

                if self.target.state & TargetStates.EXITED:
                    self.send_packet(b'S03')
                    self.conn.close()
                    return
                self.check_breakpoint_hit()
                continue

            if c == b'\x03':
                if not self.target.state & TargetStates.STOPPED:
                    self.target.stop()
                self.send_packet(b'S02')
            elif c == b'$': # start of package
                pkt = b''
                pkt_receiving = True
            elif c == b'#': # end of package
                checksum = self.conn.recv(2)
                if int(checksum, 16) == chksum(pkt):
                    return pkt
                else:
                    raise Exception('Checksum Error')
                
            elif pkt_receiving == True:
                pkt += c


def spawn_gdb_server(self, target, port, do_forwarding=True, xml_file=None):
    if xml_file is None:
        # default for now: use ARM
        xml_file = f'{dirname(__file__)}/gdb/arm-target.xml'
      
    server = GDBRSPServer(self, target, port, xml_file, do_forwarding)
    server.start()
    self._gdb_servers.append(server)
    return server

def exit_server(avatar, watched_target):

    for s in avatar._gdb_servers:
        if s.target == watched_target:
            s.shutdown()
            avatar._gdb_servers.remove(s)

def load_plugin(avatar):
    avatar.spawn_gdb_server = MethodType(spawn_gdb_server, avatar)
    avatar.watchmen.add_watchman('TargetShutdown', when='before',
                                 callback=exit_server)
    avatar._gdb_servers = []
