mips-linux-gnu-gcc -c -nostdlib test.c -o test.o -g && \
mips-linux-gnu-ld -T test.ld test.o -o test.elf && \
echo "OK"

