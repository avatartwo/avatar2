# Version 1.4.0 (February 10th, 2021)

* Major Updates:
    * Inception debugger target and protocol for Cortex-M3
    * PyPanda Target
    * MIPS support
    * Dropping support for Python 2.7
    * Docker file/image generation for avatar2
    * avatar-qemu updated to v5.1

* New Plugins:
    * GDB server
    * GDB memory_map_loader

* Improvements:
    * The two-tiered breakpoint approach
    * Add support of latest pygdbmi
    * Supporting Ubuntu 20.04 as default image
    * Defaulting to gdb-multiarch
    * New boolean `log_to_stdout` kwarg for main avatar object

* Bugfixes:
    * Removed 100% CPU resource usage on idle
    * Support new version of pygdbmi (while staying backwards compatible)


# Version 1.3.1 (January 28th, 2020)

* Major Updates:
    * Qemu Endpoint set to version 4.2.0-rc5
    * avatar-panda got mainlined into PANDA
* Improvements
    * set_break_condition for gdb-protocol
    * gdb protocol allows to catch syscalls
    * Using more performant gdb-protocol as default for openocd-target
    * Better error handling for OpenOCDTarget
* Bugfixes:
    * enum3.4 dependency conditional on python version (thanks @rhelmot)
    * EXIT is a valid transition for wait (thanks @Kyle-Kyle)
    * breakpointhitmessage uses int for breakpoint number
    * various fixes for CI

# Version 1.3.0 (September 17th, 2019)
* Major update: Pretender release (https://www.usenix.org/conference/raid2019/presentation/gustafson)
    * IRQ injection into Qemu
    * IRQ forwarding from cortex-m devices (plugins/arm/armv7_interrupts)
    * NVIC emulation for cortex-m3 mcus fo QemuTarget
    * Coresight protocol
    * armv7m_interrupt protocol
    * max32_usart.py peripheral
* Features:
    * Avatar object can now load or save configuration files, specifying
      targets and memory ranges
    * Enhancement for targets using GDBProtocol (set_file, download, get_symbol)
      (thanks @drizzin-novalabs)
* Improvements:
    * Allow avatar-qemu to build with -Werror -Wunused-function (#29)
    * Pyperipheral improvements
    * Sanity check of memory read/writes go to mapped memory
    * CI tests for python peripherals

# Version 1.2.2 (April 11, 2019)
* Features:
    * CHANGELOG for keeping track of changes
    * Jlink Target (thanks @subwire)
* Improvements:
    * log_items and log_file kwargs for Qemu-Target
    * Migration to Ubuntu 18.04 as test platform
    * Ask user before writing to /etc/apt/sources/list in install scripts
    * CI upgrades
    * Various bugfixes
