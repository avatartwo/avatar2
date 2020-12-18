import avatar2
import angr
import sys
import os
import traceback
import subprocess

try:

  # --- Init all objects

  os.system("rm -rf tmp");
  Avatar = avatar2.Avatar(arch=avatar2.archs.MIPS_BE,
    output_directory='tmp')
  Avatar.load_plugin('gdb_memory_map_loader')

  Gdb = Avatar.add_target(avatar2.GDBTarget, gdb_executable='gdb-multiarch',
    gdb_ip='127.0.0.1', gdb_port=1234)

  # we must load something, so load some bytes at some address
  # (we consider the case when we don't have nor binary neither memory map)
  # TODO: fix it inside Avatar
  with open("blob", "w") as fb: fb.write("BLOB")
  load_options = {
    'main_opts': {
      'backend' : 'blob',
      'custom_arch' : 'mips',
      'segments' : [ (0, 0x12345678, 4) ],
    },
  }
  Angr = Avatar.add_target(avatar2.AngrTarget, binary="blob",
                           load_options=load_options)

  qemu_process = subprocess.Popen("qemu-system-mips -kernel test.elf -nographic -m 256M -s -S".split())

  Avatar.init_targets()

  # reaching the initial state on the device
  Gdb.set_breakpoint(0x80100000) # the address of the 'fun' function
  Gdb.cont()
  Gdb.wait()
  
  # gets empty map
  Avatar.load_memory_mappings(Gdb, forward=True)

  Angr.set_gdb(Gdb)

  options = angr.options.modes['symbolic'] | set([angr.options.STRICT_PAGE_ACCESS])
  s = Angr.angr.factory.avatar_state(Angr, load_register_from=Gdb,
                                     options=options)

  # --- Symbolic with Angr
  
  print("INIT")

  sr = s.solver

  # info about symbolized memory bytes:
  # key - address, value - pair of symbolic variable 'S' and concrete value 'C'
  syms = dict()

  # 'symbolize' memory range 
  def sym_mem(addr, size, syms):
    for a in range(addr, addr + size):
      sym_var = sr.BVS("B_%08X" % a, 8)
      def rdC():
        return s.mem[a].byte.concrete
      con_val = sr.BVV(Angr.do_safe(rdC, s), 8)
      def wrS():
        s.mem[a].byte = sym_var
      Angr.do_safe(wrS, s)
      syms[a] = {'S' : sym_var , 'C' : con_val}

  a0 = s.regs.a0.args[0]
  ra = s.regs.ra.args[0]

  def set_input():
    # we could set arbitrary input data, for example:
    # s.mem[a0].byte = sr.BVV(123, 8)
    pass
  Angr.do_safe(set_input, s)
    
  sym_mem(a0, 1, syms)

  stop_addr = [ra]

  #   Implementation of classic concolic/DSE using Angr

  # alternatives (inverted branches)
  # - list of pairs - solution (values of sym. variables) and BB address
  alter = []
  st = s

  while True:
    pc = st.regs.pc.args[0]
    print("ADDR " + hex(pc))
    if pc in stop_addr:
      break
    # execute one basic block
    Angr.do_safe(lambda: st.mem[pc].byte.concrete, st) # fetch
    def one_step():
      return st.step()
    sts0 = Angr.do_safe(one_step, st)
    # sts0 - possible next blocks;
    # select sts - possible blocks with concrete values (must be only one block),
    # and check possibility of other blocks
    sts = []
    for s in sts0:
      extraco = []
      for key, val in syms.items():
        extraco.append(val['S']==val['C'])
      if s.solver.satisfiable(extra_constraints=extraco):
        sts.append(s)
      else:
        if s.solver.satisfiable():
          sols = []
          for key in sorted(syms.keys()):
            val = syms[key]
            sols.append((val['S'], s.solver.eval(val['S'])))
          alter.append((sols, hex(s.regs.pc.args[0])))
    if len(sts) != 1:
      print("ERROR")
      break
    st = sts[0]

  print("END")
  print(alter)
  # must contain the desirable value of the input byte - 5
  if (any([sols[0][1] == 5 for sols, _ in alter])):
      print("TEST OK")
  else:
      print("TEST FAIL")

  Avatar.shutdown()
  try: qemu_process.kill()
  except: pass
  sys.exit(0)

except Exception as ex:
  print("EXCEPTION!")
  traceback.print_exc()
  try: qemu_process.kill()
  except: pass
