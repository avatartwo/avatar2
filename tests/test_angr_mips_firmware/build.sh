#ARCH='mipsel' # LE
ARCH='mips' # BE
${ARCH}-linux-gnu-gcc -c -nostdlib test.c -o test.o -g && \
${ARCH}-linux-gnu-ld -T test.ld test.o -o test.elf && \
echo "OK"

