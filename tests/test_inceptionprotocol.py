from avatar2.protocols.inception import IPCortexM3
#import avatar2

import struct
import ctypes

from nose.tools import *

SLEEP_TIME = 1
MEM_ADDR = 0x12345678
i = None



class FakeCortexM3():

    def __init__(self):

        # constants
        self.write_cmd = 0x14000001
        self.read_cmd = 0x24000001
        self.burst_size = 1

        # Cortex M3 registers
        self.fake_regs = dict()
        # FP_CTRL reg
        self.fake_regs[0xE0002000] = 0b1001100011
        # DHCSR reg
        self.fake_regs[0xE000EDF0] = 0b11

        self.fake_write_addr = 0x0
        self.fake_write_val = 0x0
        self.fake_read_val = 0x0
        self.read_token = 0

    def write(self, buf):

        if len(buf) == 8:
            h_bits = struct.unpack_from('>I', buf, 0)[0]
            l_bits = struct.unpack_from('>I', buf, 4)[0]

            # Command to reset the JTAG
            if h_bits == 0x30000000 and l_bits == 0x30000000:
                return True

            # Read memory command
            elif h_bits == self.read_cmd:
                self.read_token += 1
                if l_bits in self.fake_regs:
                    self.fake_read_val = self.fake_regs[l_bits]
                else:
                    self.fake_read_val = 0xdeadbeef
                return True

            else:
                return False

        elif len(buf) == 12:
            cmd = struct.unpack_from('>I', buf, 0)[0]
            addr = struct.unpack_from('>I', buf, 4)[0]
            val = struct.unpack_from('>I', buf, 8)[0]

            # Write memory command
            if cmd == self.write_cmd:
                self.fake_write_addr = addr
                self.fake_write_val = val
                return True

        return False

    def read(self, size, na):
        resp = bytearray(8)
        struct.pack_into('>I', resp, 0, 0x00000002)
        struct.pack_into('>I', resp, 4, self.fake_read_val)

        self.read_token -= 1
        if self.read_token <= 0: 
            self.fake_read_val = 0x0

        return resp

class FakeIPCortexM3(IPCortexM3):
    '''
    Because IPCortexM3 rely on pyusb to communicate with the hardware 
    debugger, we need to overwrite some functions in order to test reads 
    and writes.
    '''

    def __init__(self, **kwargs):
        super(FakeIPCortexM3, self).__init__(**kwargs)
        self._fakecm3 = FakeCortexM3()

    def connect(self):
        
        self._device = None
        self._ep_in_irq = None

        # used to write
        self._ep_out = self._fakecm3
        # used to read
        self._ep_in_response = self._fakecm3

        return True

    def shutdown(self):
        self._ep_out = None
        self._ep_in_response = None
        return True


# ****************************************************************************

def setup():
   global i

   i = FakeIPCortexM3()
   i.connect()
   i.reset()


def teardown():
    i.shutdown()


@with_setup(setup, teardown)
def test_register_read_and_write():

    ret = i.write_register('R0', 2020)
    assert_equal(ret, True)

    ret = i.read_register('r0')
    assert_equal(ret, 0xdeadbeef)


@with_setup(setup, teardown)
def test_break_run_and_read_write_mem():

    ret = i.set_breakpoint(0x8000000)
    assert_equal(ret, True)

    ret = i.cont()
    assert_equal(ret, True)

    #time.sleep(SLEEP_TIME)

    ret = i.read_memory(MEM_ADDR, 4)
    assert_equal(ret, 0xdeadbeef)

    ret = i.write_memory(MEM_ADDR, 4, 0x8badf00d)
    assert_equal(ret, True)
    assert_equal(i._fakecm3.fake_write_addr, MEM_ADDR)
    assert_equal(i._fakecm3.fake_write_val, 0x8badf00d)


if __name__ == '__main__':
    setup()
    test_break_run_and_read_write_mem()
    teardown()
