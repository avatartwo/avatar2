#include <asm/prctl.h>
#include <sys/prctl.h>

long avatar_get_fs(void)
{
    long fs, ret;
    ret = arch_prctl(ARCH_GET_FS, &fs);
    return ret ? ret : fs;
}
