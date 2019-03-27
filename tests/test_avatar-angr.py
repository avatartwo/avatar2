import subprocess
import os
import avatar2 as avatar2
import logging

GDB_SERVER_IP = "127.0.0.1"
GDB_SERVER_PORT = "2222"
binary_path = "%s/tests/binaries/" % os.getcwd()
binary = binary_path + "fauxware"
bp_func = "print_test"

ava = avatar2.Avatar(arch=avatar2.archs.X86_64,output_directory="/tmp/avatar_angr")
ava.load_plugin("gdb_memory_map_loader")
# Set log level
ava.log.setLevel(logging.DEBUG)
print("[+] Creating the GDBTarget")
gdb = ava.add_target(avatar2.GDBTarget, gdb_port=GDB_SERVER_PORT, local_binary=binary)

print("[+] Initializing the targets")
ava.init_targets()

gdb.disable_aslr()

print("[+] Running binary until breakpoint")
gdb.bp(bp_func)

# Equivalent to run, but only if not already running
gdb.cont()
gdb.wait()

# Insert angr memory tranfer code here...

