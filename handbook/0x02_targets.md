# Targets

The first information that Avatar² requires is a set of targets required
for the analyst job. Let's have a look how to add a simple target:

```python
from avatar2 import *

avatar = Avatar()

qemu = avatar.add_target('qemu1', QemuTarget)
```

This instantiates a QemuTarget object and assign it a mnemonic name
("qemu1"). From now on we can interact with the target using the
_qemu_ variable, or we can ask avatar to work on it 
by specifying its name.

```python
>>> from avatar2 import *
>>> avatar = Avatar()
>>> qemu = avatar.add_target('qemu1', QemuTarget)
>>> avatar.targets['qemu1'] == qemu
True
```

It is important to note that while a target can be configured after it has been created,
this should **only** be performed before the _init()_ procedure of the target is called.

```python
from avatar2 import *

avatar = Avatar()

# add qemu and specify that its gdbserver should listen at address 1234
qemu = avatar.add_target('qemu1', QemuTarget, gdb_port=1234)

# do other things, initialize memory ranges and so on
[...]

# valid: change the gdbserver listening port to 2234
qemu.gdb_port = 2234

# This will initialize the qemu target
qemu.init()

# invalid: qemu and its gdbserver are already spawned, changing the gdb port
#          here will not have any effect.
qemu.gdb_port = 3234
```

To sum up, defining a target is seemingly simple at first, but the devil is
in the details: as a variety of different targets are supported and each
target accepts its own set of _target specific arguments_. So, let's look
at the different targets that are currently supported by Avatar², alongside
with the arguments they accept.

## GDBTarget
This is probably one of the most intuitive targets: It will simply connect to
an existing gdbserver instance, either via a TCP or a serial connection,
based on the value of it's _serial_ argment. Therefore, it is not important
whether the gdbserver runs on a remote physical target or is just locally
spawned on the Avatar² host system.
For a flexible configuration, he following keywords can be passed when adding a
GDBTarget:

| name                | type  | default        | purpose                                                                                                  |
|---------------------|-------|----------------|----------------------------------------------------------------------------------------------------------|
| gdb_executable      | str   | 'gdb'          | Path to the gdb-executable which shall be used                                                           |
| gdb_additional_args | [str] | []             | List with additional arguments which shall be passed to gdb                                              |
| gdb_port            | int   | 3333           | Port on which the gdbserver being connected to listens                                                   |
| serial              | bool  | False          | Whether to connect to a gdbserver via serial, than via tcp. Enables the gdb_serial parameters to be used |
| gdb_serial_device   | str   | '/dev/ttyACM0' | The serial device we want to connect to                                                                  |
| gdb_serial_baudrate | int   | 38400          | The serial baud rate                                                                                     |
| gdb_serial_parity   | str   | 'none'         | The serial parity settings to be used                                                                    |

## OpenOCDTarget
The purpose of the OpenOCDTarget is the possibility to connect to physical
targets over JTAG access by using [openocd](http://openocd.org/).

As an Avatar² host can control openocd, and, subsequently, its target using either
a connection to a gdbserver or a telnetinterface to openocd, the following
parameters can be specified on a OpenOCDTarget:

| name                | type  | default | purpose                                                                                         |
|---------------------|-------|---------|-------------------------------------------------------------------------------------------------|
| openocd_script      | str   | None    | *mandatory* path to an openocd script. This script normally controls the actual JTAG-connection |
| additional_args     | [str] | []      | List with additional arguments which shall be passed to openocd                                 |
| telnet_port         | int   | 4444    | Port for the openocd telnet server                                                              |
| gdb_executable      | str   | 'gdb'   | Path to the gdb-executable which shall be used                                                  |
| gdb_additional_args | [str] | []      | List with additional arguments which shall be passed to gdb                                     |
| gdb_port            | int   | 3333    | Port on which the gdbserver being connected to listens                                          |

## QemuTarget
Qemu is a full-system emulator which has beed modified for avatar² in order to
allow a complete free (hardware-) configuration of the system to be emulated and
in order to allow performant forwarding of memory from within qemu to other
targets. As these are quite impactful changes, several different configuration
options are available for QemuTargets:


| name                | type  | default        | purpose                                                                                                                                      |
|---------------------|-------|----------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| executable          | str   | 'qemu-system-' | Path to the qemu executable which will be used, without architecture suffix. The architecture suffix gets automatically detected by avatar² |
| additional_args     | [str] | []             | List with additional arguments which shall be passed to qemu                                                                                 |
| cpu_model           | str   | None           | A specific cpu-model to be used by qemu                                                                                                      |
| firmware            | str   | None           | (optional) path to a kernel or kernel-like firmware to be used by qemu                                                                       |
| qmp_port            | int   | 3334           | Port for the qemu monitor protocol                                                                                                           |
| entry_address       | int   | 0              | Address of the first instruction to be executed                                                                                              |
| gdb_executable      | str   | 'gdb'          | Path to the gdb-executable which shall be used                                                                                               |
| gdb_additional_args | [str] | []             | List with additional arguments which shall be passed to gdb                                                                                  |
| gdb_port            | int   | 3333           | Port on which the gdbserver being connected to listens       


## PandaTarget
[PANDA](https://github.com/panda-re/panda) is a dynamic binary analysis platform
with a lot of useful features, among others the record and replay of an
execution and a plugin-system for varios analysis tasks during execution and
replay.
As PANDA itself is based on qemu, the avatar² PandaTarget directly inherits
from the QemuTarget and accepts all of its arguments.
However, in comparison to the above described targets, it has a variety of 
_target specific methods_ for driving PANDA in the execution-phase:

| method-name   | arguments                           | purpose                                         |
|---------------|-------------------------------------|-------------------------------------------------|
| begin_record  | record_name                         | Advice PANDA to begin a record of the execution |
| end_record    | -                                   | Advice PANDA to end and ongoing record          |
| begin_replay  | replay_name                         | Replay a recorded execution                     |
| end_replay    | -                                   | End the ongoing replay                          |
| load_plugin   | plugin_name, plugin_args, file_name | Load a PANDA plugin with specified arguments    |
| unload_plugin | plugin_name                         | Unload plugin with the specified name           |
| list_plugins  | -                                   | List the already loaded PANDA plugins           |

For more information about these function, we suggest to have a look at our
[autodoc](https://avatartwo.github.io/avatar2-docs).
