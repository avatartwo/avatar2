Avatar, GDB+Angr: classic concolic/DSE, simple MIPS 32 BE firmware

In this example, we perform concolic from the initial state
which is loaded on demand using the debugging interface.
We need to find the input byte value (5) to pass check in the code.

To run the test, just type 'python script.py'.
The script will run qemu-system-mips with the firmware
and use GDB+Angr to reach the initial state and perform concolic.
The script will print input values which produce new paths,
and it must contain the desirable value.

The compiled firmware (test.elf) is already present in this directory,
but it can also be compiled from the source (using build.sh).
