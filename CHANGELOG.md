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
