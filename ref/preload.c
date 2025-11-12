#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
// ---------------- SIGSYS handler ----------------
static void sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    // (void)ctx; // unused
    // if (!info) return;

    fprintf(stderr,
        "[SIGSYS] signal=%d si_code=%d errno=%d syscall=%d\n",
        sig,
        info->si_code,
        info->si_errno,
        info->si_syscall
    );
}

// ---------------- Install handler ----------------
static void install_sigsys_handler(void) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = sigsys_handler;
    act.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSYS, &act, NULL) != 0) {
        perror("sigaction");
        exit(1);
    }
}

// ---------------- main ----------------
int main(void) {
    install_sigsys_handler();

    // Uncomment next line to actually trap disallowed syscalls
    // install_seccomp_filter();

    const char msg[] = "x\n";
    write(1, msg, 2);  // allowed

    // Uncomment this to trigger SIGSYS if seccomp_filter() installed:
    // syscall(SYS_getpid);

    return 0;
}
