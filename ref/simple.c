#include <unistd.h>

int main(void) {
    const char msg[] = "x";
    write(1, msg, 1); // write(1, "x", 1) -> syscall to SYS_write
    return 0;
}
