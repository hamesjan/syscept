#include <unistd.h>

int main(void) {
    const char msg[] = "x\n";
    write(1, msg, 2); // write(1, "x", 1) -> syscall to SYS_write
    write(1, msg, 2); // write(1, "x", 1) -> syscall to SYS_write
    getpid();           // SYS_getpid
    return 0;
}
