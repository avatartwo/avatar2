# Version 1.4.7 (February 10th, 2022)

* Improvements
    * Change CI to Github Actions
    * avatar-qemu updated to v6.2
    * Allow unix sockets for GDBProtocol (thanks @grant-h)

* Bugfixes:
    * JLink target and protocol, operational now (thanks @TheSilentDawn)
    * pygdbmi version checking (tanks @jcnauta)
    * Error messages (thanks @mborgerson and @lacraig2)

# Version 1.4.6 (June 21st, 2021)

* Improvements
    * Add build and unit tests to Github Actions
    * Add 'ip' alias for ARM register 12 

* Bugfixes:
    * Unlink RemoteMemory message queue after opened (thanks @grant-h)
    * Adjust API to recent pypanda version (0.1.1.2)
    * Handle ImportError with RemoteMemoryProtocol on darwin (thanks @fabianfreyer)
    * Allow OpenOCDTarget to pass a list of multiple scripts (thanks @fabianfreyer)
    * Override in config file the avatar cpu_model when QEmuTarget specify it

# Version 1.4.5 (March 29th, 2021)

* Bugfixes:
    * Bumped version to replace broken pypi version of v1.4.4

# Version 1.4.4 (March 28th, 2021)

* Improvements
    * Allow logging to be setup by external orchestration (thanks @grant-h)

* New Plugins:
    * GDB Core Dumper (thanks @AdamVanScyoc)

* Bugfixes:
    * Python version checking for selecting which version of pygdbmi to use
    * Proper shutdown of PyPanda target (thanks @grant-h)
    * Allow PyPanda to initialize without requiring Panda executable
    * Allow CI to run on PRs

# Version 1.4.3 (March 8th, 2021)

* Improvements
    * Remote Memory Accesses can now optionally forward the pc value if the
      backed forwarded_to-object supports it.
      (Currently, this is only PyPeripherals when all read/write handler have a
      pc kwarg.)

* Bugfixes:
    * Qemu's log_file argument is now treated as absolute path

# Version 1.4.2 (February 26th, 2021)

* Improvements
    * Allow automatic splittin/overwriting of memory ranges
    * Unicorn caller plugin
    * Inlined Pyperipherals
    * Add_hook for pypanda


# Version 1.4.1 (February 19th, 2021)

* Improvements:
    * local argument to load_plugin
    * Automated PyPi deploy for tagged commits (i.e. new versions)

* Bugfixes:
    * PyPandaTarget Write Memory command
    * Removed usage of "objects" in assembler plugin

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
