import subprocess
import os
import avatar2
import logging


import angr as a #this needs to be carried somewhere

binary_path = "%s/tests/binaries/" % os.getcwd()
binary = binary_path + "fauxware"
bp_func = "print_test"
bp_func = 0x4007D5 

ava = avatar2.Avatar(arch=avatar2.archs.X86_64,output_directory="/tmp/avatar_angr")
ava.load_plugin("gdb_memory_map_loader")
ava.load_plugin("x86.segment_registers")
# Set log level
#ava.log.setLevel(logging.DEBUG)
print("[+] Creating the GDBTarget")

angr = ava.add_target(avatar2.AngrTarget, binary=binary,
                      load_options={'main_opts': {'backend':'elf'}})


gdb = ava.add_target(avatar2.GDBTarget, local_binary=binary)

print("[+] Initializing the targets")
ava.init_targets()

gdb.disable_aslr()

print("[+] Running binary until breakpoint")
gdb.bp(bp_func)

# Equivalent to run, but only if not already running
gdb.cont()
gdb.wait()

#state = ava.transfer_state(gdb, angr)


ava.load_memory_mappings(gdb, forward=True)



options = a.options.common_options | set([a.options.STRICT_PAGE_ACCESS])
s = angr.angr.factory.avatar_state(angr, load_register_from=gdb, options=options)
#s = angr.angr.factory.avatar_state(angr, load_register_from=gdb)

sm = angr.angr.factory.simgr(s)

#sm.explore()
#while len(sm.active) > 0:
    #print(sm.active[0].regs.pc)
    #print(len(sm.active))
    #sm.step()

import IPython; IPython.embed()


ava.log.error("End of script")

# Insert angr memory tranfer code here...

