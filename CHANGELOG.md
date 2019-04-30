# Version 1.2.3 (TBD)
* Features:
    * Avatar object can now load or save configuration files, specifying
      targets and memory ranges
    * Enhancement for targets using GDBProtocol (set_file, download, get_symbol)
      (thanks @drizzin-novalabs)
* Improvements:
    * Allow avatar-qemu to build with -Werror -Wunused-function (#29)

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
