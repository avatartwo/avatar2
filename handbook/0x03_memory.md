# Memory Configuration

The second piece of information required to create a Avatar² script is the specification of
a memory layout. Avatar keeps track of all memory ranges and pushes the resulting
memory mapping that combines all ranges down to the individual targets.

## Memory Range Definition

Adding a memory range is straightforward. Assuming the presence of an Avatar²
object named 'avatar', it's enough to add the following line to create a basic
memory area of size 0x1000 at address 0x40000000:

```python
dummy_range = avatar.add_memory_range(0x40000000, 0x1000)
```

Memory ranges are highly flexible and allow for a variety of additional
keywords during their creation, some of which may be used only by 
specific classes of targets. Below is a list of all target-independent
keyword arguments which can be used during the creation of a memory range.

| Keyword      | Description                                                               |
|--------------|---------------------------------------------------------------------------|
| name         | An optional name for the memory range                                     |
| permissions  | The permissions in textual representation. Default: 'rwx'                 |
| file         | Path to a file which holds the initial contents for the memory            |
| forwarded    | Whether memory accesses to the range needs to be forwarded to a specific target |
| forwarded_to | If forwarding is enabled, reference to the target that will handle the memory accesses |
| emulate      | Enable avatars peripheral emulation for the given memory range            |

## Memory Forwarding

One of the core features of Avatar² is the separation between execution and 
memory accesses. This yields the capability to forward memory accesses
among different targets. For instance, a firmware image can be executed
inside an emulator, while all memory access can be forwarded to the real
physical device.

The forwarding rules themselves are set up during the configuration of the 
memory ranges, by using the forwarded and forwarded_to arguments.
Let's assume we are analyzing in QEMU a physical device that contains memory-mapped peripherals.
An exemplary memory range configuration could look like the following:

```python
mmio = avatar.add_memory_range(0x4000000, 0x10000, name='mmio',
                               permissions='rw-'
                               forwarded=True, forwarded_to=phys_device)
ram  = avatar.add_memory_range(0x2000000, 0x1000000, name='ram',
                               permissions='rw-')
rom  = avatar.add_memory_range(0x0800000, 0x1000000, name='rom',
                               file='./firmware.bin',
                               permissions='r-x')
```


## Qemu-Target Peripheral Emulation Ranges

As QEmu is a full system emulator, it also capable of emulating a large set of peripherals.
Logically, Avatar² can take advantage of this feature 
by specifying the _target specific keywords_
'qemu\_name' and 'qemu\_properties' parameters on a memory range.

For instance, a very common device which can be emulated in QEmu
instead of forwarding its I/O accesses to the physical device is a serial
interface, as shown in the example below:

```python

# Properties as required by qemu
serial_qproperties = {'type' : 'serial', 'value': 0, 'name':'chardev'}

serial = avatar.add_memory_range(0x40004c00, 0x100, name='usart',
                                 qemu_name='stm32l1xx-usart',
                                 qemu_properties=serial_qproperties, 
                                 permissions='rw-')

# Provide serial I/O via tcp
qemu.additional_args = ["-serial", "tcp::1234,server,nowait"]
```

## Avatar² Peripheral Emulation Ranges

Unfortunately, QEmu does not support all existing peripherals nor will every 
Avatar² set-up utilize a Qemu target.
As a result Avatar² allows to specify user-defined peripheral implementations
using the AvatarPeripheral class.

To do so, two steps are required:

1. Create a child class from AvatarPeripheral which defines custom read and
write handler in its \_\_init\_\_ function.
2. Pass a reference of this class to the emulate keyword of a memory range.

The example below provides an implementation of a HelloWorldPeripheral, which
returns another part of the string 'Hello World' upon every read.

```python
from avatar2 import *

class HelloWorldPeripheral(AvatarPeripheral):

    def hw_read(self, offset, size):         
        ret = self.hello_world[:size]
        self.hello_world = self.hello_world[size:] + self.hello_world[:size]
        
        # Convert the return value to an integer (py2/py3-compatible)
        # Python >3.2 could just call int.from_bytes(ret, byteorder='little')
        s2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q')
        ret = struct.unpack('<' + s2fmt[size], ret)[0]

        return ret

    def nop_write(self, offset, size, value):
        return True    

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        
        self.hello_world=b'Hello World'
        
        self.read_handler[0:size] = self.hw_read 
        self.write_handler[0:size] = self.nop_write
        
[...]        

hw = avatar.add_memory_range(0x40004c00, 0x100, name='hello_world',
                             emulate=HelloWorldPeripheral, permissions='rw-')        
```
