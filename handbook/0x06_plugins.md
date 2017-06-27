# Plugins

Another important key feature of avatar² is its plugin system. Plugins allow
to modify or enhance the functionalities of the avatar or the different target
objects.
In this way, the core of avatar² itself stays slim and complex functionalities
can be enabled or added on demand.

Enabling a plugin is notoriously simple:
```python
from avatar2 import *

avatar = Avatar()
avatar.load_plugin('myPlugin')
```

In the following, we will have a look at two of the exemplary plugins which are
 coming together with avatar².

## Orchestrator
One of the most fundamental plugins is the orchestrator. While in normal
avatar²-scripts the execution plan has to be specified purely sequentially,
the orchestrator allows to automate the execution. In essence, instead of a
concrete execution plan, only a set of transitions and the first target used
for execution has to be specified.

```python
from avatar2 import *

avatar = Avatar()
avatar.load_plugin('orchestrator')

# Target and memory memory map definition
[...]

# Specify the starting target for the orchestration
avatar.start_target = target1

# Add transition from target_1 to target_2 as soon target_1 hits 0x8000b504
avatar.add_transition(0x800B504, target_1, target_2, sync_regs=True, 
                      synced_ranges=[ram])

# Add a 2nd transition from target_1 to target_2 at 0x800b570 and 
# mark it as the end for the automated orchestration
avatar.add_transition(0x800B570, target_2, target_1, sync_regs=True,
                      synced_ranges=[ram], stop=True)

# Begin the orchestration
avatar.start_orchestration()
```

## Disassembler

The disassembler plugin does exactly what the name suggests: It can be used to
disassemble machine code. Which is especially useful when using avatar²
interactively.
It uses capstone as disassembler-backend and adds two functions to every target
registered to an avatar object: `disassemble()` and `disassemble_pretty()`.
The first function returns a list of capstone-instructions, while the second
functions returns a human-readable string with the disassembly.

By default, both functions will try to disassemble one instruction right at the
location of the target's instruction pointer, using the information available
in avatar²'s architecture description. This behaviour can be influenced by
the following named arguments:

| Argument |                                       Meaning |
|----------|----------------------------------------------:|
| addr     |            The address to start disassembling |
| insns    | The number of instructions to be disassembled |
| arch     | The architecture, as passed to capstone       |
| mode     |   The disassemble mode, as passed to capstone |

