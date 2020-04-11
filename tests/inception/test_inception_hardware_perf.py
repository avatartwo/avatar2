from avatar2 import *

import sys
import os
import logging
import serial
import time
import argparse
import pyudev

import struct
import ctypes
from random import randint
# For profiling
import pstats


logging.basicConfig(filename='/tmp/inception-tests.log', level=logging.INFO)


# ****************************************************************************
def single_step(target, nb_test):
    print("[*] Single step target %d times" % nb_test)

    for i in range(nb_test):
        pc = target.protocols.execution.read_pc()
        print(pc)
        target.step()
        print('stepped')
        next_pc = target.protocols.execution.read_pc()
        print(next_pc)

# ****************************************************************************
def read_full_mem(target, nb_test, raw=True, summary=True):
    print(" -  Read the full memory")
    nb_test = 1
    average_read = 0

    for i in range(nb_test):
        t0 = time.time()
        target.read_memory(ram.address, 1, ram.size, raw=raw)
        t1 = time.time()
        average_read += t1 - t0

    if summary:
        average_read = average_read / nb_test
        speed_read = ram.size / average_read / 1024
        print("   -> On average raw read of %s bytes takes %.2f sec, speed: %.2f KB/sec" % (ram.size, average_read, speed_read))

# ****************************************************************************
def write_full_mem(target, nb_test, raw=True, summary=True):
    print(" -  Write the full memory")
    nb_test = 1
    average_write = 0
    buf = ctypes.create_string_buffer(ram.size)
    for i in range(int(ram.size / 4)):
        struct.pack_into(">I", buf, i * 4, randint(0, 0xffffffff))

    for i in range(nb_test):
        t0 = time.time()
        target.write_memory(ram.address, 1, buf, raw=raw)
        t1 = time.time()
        average_write += t1 - t0

    if summary:
        average_write = average_write / nb_test
        speed_write = ram.size / average_write / 1024
        print("   -> On average raw write of %s bytes takes %.2f sec, speed: %.2f KB/sec" % (ram.size, average_write, speed_write))

# ****************************************************************************
def read_write_full_mem(target, nb_test, raw=True, summary=True):
    print(" -  Read and write the full memory")
    reads = []
    average_read_write = 0

    for i in range(nb_test):
        if raw:
            t0 = time.time()
            reads.append(target.read_memory(ram.address, 1, ram.size, raw=raw))
            target.write_memory(ram.address, 1, reads[i], raw=raw)
            t1 = time.time()
        else:
            t0 = time.time()
            reads.append(target.read_memory(ram.address, 1, ram.size, raw=raw))
            target.write_memory(ram.address, 1, reads[i], len(reads[i]), raw=raw)
            t1 = time.time()

        average_read_write += t1 - t0

    if summary:
        average_read_write = average_read_write / nb_test
        speed_read_write = ram.size / average_read_write / 1024
        print("   -> On average raw read&write of %s bytes takes %.2f sec, speed: %.2f KB/sec" % (ram.size, average_read_write, speed_read_write))

    # Verify all reads are identical
    for i in range(len(reads) - 1):
        assert(reads[i] == reads[i+1])
        #print("[!] Multiple reads produce different values !")

# ****************************************************************************
def random_read_write(target, nb_test, raw=True):
    print(" -  Random read / writes of random size in the ram")
    for i in range(0, nb_test):
        size = randint(0, int(ram.size / 8)) * 8
        #size = 2**4

        # Reset the board and wait to reach the breakpoint
        target.reset()
        target.wait()
    
        if raw:
            m1 = ctypes.create_string_buffer(size)
            for j in range(int(size / 4)):
                struct.pack_into(">I", m1, j * 4, randint(0, 0xFFFFFFFF))

            target.write_memory(ram.address, 1, m1, raw=True)
            m2 = target.read_memory(ram.address, 1, size, raw=True)

            n1, n2 = ([] for i in range(2))
            for j in range(int(size / 4)):
                n1.append(struct.unpack_from(">I", m1, j)[0])
                n2.append(struct.unpack_from(">I", m2, j)[0])
            assert(n1 == n2)
            #print("i=%s m1: %s m2: %s" % (i, m1.raw, m2))
            #print("[!] Multiple random reads produce different values !")

        else:
            m1 = []
            for j in range(int(size / 4)):
                m1.append(randint(0, 0xFFFFFFFF))

            target.write_memory(ram.address, 1, m1, size, raw=False)
            m2 = target.read_memory(ram.address, 1, size, raw=False)

            for j in range(int(size / 4)):
                assert(m1[j] == m2[j])
                #print("[!] Multiple random reads produce different values !")
                #print("i=%s j=%s m1[j]: %s m2[j]: %s" % (i, j, m1[j], m2[j]))

# ****************************************************************************
def random_4bytes_read_write(target, nb_test):
    print(" -  Random read / writes of 4 bytes in the ram")

    for i in range(nb_test):
        written_word = randint(0, 0xFFFFFFFF)
        address = randint(ram.address, ram.address + ram.size - 4)

        target.write_memory(address, 4, written_word, 1, raw=False)
        read_word = target.read_memory(address, 4, 1, raw=False)

        assert(written_word == read_word)

# ****************************************************************************
def read_write_registers(target, nb_test):
    print(" -  Read / write registers")

    regs = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10',
            'R11', 'R12', 'SP', 'LR', 'PC', 'CPSR']

    for i in range(nb_test):

        for j in range(17):
            written_reg = randint(0, 0xFFFFFFFF)
            saved_reg = target.read_register(regs[j])

            target.write_register(regs[j], written_reg)
            read_reg = target.read_register(regs[j])

            ''' 
            if read_reg != written_reg:
                print(i)
                print(j)
                print(hex(read_reg))
                print(hex(written_reg))
            '''

            target.write_register(regs[j], saved_reg)

        
# ****************************************************************************
def transfer_state(av, target_from, target_to, nb_test, summary=True):
    print(" -  Transfer state")
    average = 0

    for i in range(nb_test):

        t0 = time.time()
        av.transfer_state(target_from, target_to, synced_ranges=[ram])
        t1 = time.time()
        average += t1 - t0

    if summary:
        average = average / nb_test
        speed = ram.size / average / 1024
        print("   -> On average transfer state from %s to %s of %s bytes takes %.2f sec, speed: %.2f KB/sec" % (target_from.name, target_to.name, ram.size, average, speed))
    



if __name__ == '__main__':

    # Number each test is repeated
    n = 2

    avatar = Avatar(arch=ARMV7M, output_directory='/tmp/inception-tests')
    nucleo = avatar.add_target(InceptionTarget, name='nucleo')
    dum = avatar.add_target(DummyTarget, name='dum')
    #qemu = avatar.add_target(QemuTarget, gdb_port=1236)
    
    
    # Memory mapping of NUCLEO-L152RE
    rom = avatar.add_memory_range(0x08000000, 0x1000000, 'rom',
                                   file=firmware)
    ram = avatar.add_memory_range(0x20000000, 0x14000, 'ram')
    mmio = avatar.add_memory_range(0x40000000, 0x1000000,
                                   forwarded=True, forwarded_to=nucleo)
    
    ram = avatar.get_memory_range(0x20000000)
    
    avatar.init_targets()
    print("Targets initialized")
    
    nucleo.reset()
    nucleo.cont()
    nucleo.stop()
    print("Targets stopped, start tests for n = %s" % n)

    print("[*] Raw read / writes tests")
    read_full_mem(nucleo, n)
    write_full_mem(nucleo, n)
    read_write_full_mem(nucleo, n)
    random_read_write(nucleo, n)

    print("[*] !raw read / writes tests")
    read_full_mem(nucleo, n, raw=False, summary=False)
    write_full_mem(nucleo, n, raw=False, summary=False)
    read_write_full_mem(nucleo, n, raw=False, summary=False)
    random_read_write(nucleo, n, raw=False)

    random_4bytes_read_write(nucleo, 100 * n)

    print("[*] Read / Write registers")
    read_write_registers(nucleo, n)

    print("[*] Transfer state to dummy target")
    transfer_state(avatar, nucleo, dum, n)


    #Stop all threads for the profiler
    print("[*] Test completed")
    avatar.stop()

