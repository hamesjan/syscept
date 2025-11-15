
use std::path::PathBuf;
use fork::{fork, Fork};
use std::ffi::CString;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter,};
use std::convert::TryInto;
use libc::{self, c_void, siginfo_t, sigaction, c_int, pid_t, SIGTRAP, WIFEXITED, WEXITSTATUS, WSTOPSIG, WIFSTOPPED};

// For calling syscalls natively in Rust
// https://docs.rs/syscalls/0.6.18/syscalls/index.html
use syscalls::{syscall, Sysno, SyscallArgs, Errno};

// for CLI path
struct Cli {
    path: PathBuf,
}

fn install_seccomp_trap_filter() {
    // Only allow write syscall, everything else triggers Trap (SIGSYS)
    let filter: BpfProgram = SeccompFilter::new(
    vec![
//        (libc::SYS_accept4, vec![]),
        (libc::SYS_write, vec![]),
        // (libc::SYS_read, vec![]),
        (libc::SYS_getpid, vec![]),

        // Will have to define for all syscalls used by target binary
        // Where you define policy for each syscall on watchlist 
    ]
    .into_iter()
    .collect(),
    SeccompAction::Allow, // mismtach action
    SeccompAction::Trace(0), // natch action
    std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();

    seccompiler::apply_filter(&filter).unwrap();
}

fn main(){
    let path = std::env::args().nth(1).expect("no path to binary given");

    let args = Cli {
        path: PathBuf::from(path),
    };

    match fork() {
        Ok(Fork::Parent(child)) => {
            println!("Continuing execution in parent process, new child has pid: {}", child);
            /*
            long ptrace(enum __ptrace_request op, pid_t pid,
                   void *addr, void *data);

            Ptrace commands are always
                sent to a specific tracee using a call of the form

                    ptrace(PTRACE_foo, pid, ...)

                where pid is the thread ID of the corresponding Linux thread.
                   
            */
            unsafe {
                libc::ptrace(libc::PTRACE_SEIZE, child, 0, libc::PTRACE_O_TRACESECCOMP);
            }

            let mut status: c_int = 0; // c_int = signed 32 bit int

            let mut has_accepted_first = false;

            let mut route_syscall = true; 
            
            // Wait for seccomp traps from the child
            loop {
                unsafe {
                    // make parent wait for child state changes
                    let pid = libc::waitpid(child, &mut status as *mut c_int, 0);
                    if pid < 0 {
                        eprintln!("waitpid failed");
                        break;
                    }

                    if WIFEXITED(status) { // child has exited.
                        let code = WEXITSTATUS(status);
                        println!("[parent] child exited with {}", code);
                        break;
                    }

                    // status 
                    if WIFSTOPPED(status) { // child is stopped, waitpid returned
                        /*
                            sig = POSIX signal that caused the child to stop
                            sig = 5 => SIGTRAP
                        */
                        let sig = libc::WSTOPSIG(status); // number of signal that caused child to stop
                        println!("child stopped with signal {}", sig);

                        let event = (status as u32 >> 16) & 0xffff;
                        println!("ptrace event: {}, status: {}", event, status);
                        // status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))
                        
                        // libc::PTRACE_EVENT_SECCOMP = 7 

                        if sig == SIGTRAP{
                            if event == libc::PTRACE_EVENT_SECCOMP as u32 {

                                let mut regs: libc::user_regs_struct = std::mem::zeroed();
                                libc::ptrace(
                                    libc::PTRACE_GETREGS,
                                    child,
                                    0,
                                    &mut regs as *mut _
                                );

                                /*
                                For some reason, there are two sources of triggering seccomp. So just for initial workaround,
                                we ignore first event.
                                */

                                if has_accepted_first == false {
                                    has_accepted_first = true;
                                    libc::ptrace(libc::PTRACE_CONT, child, 0, 0);
                                    continue;
                                }
                                // https://docs.rs/libc/latest/libc/struct.user_regs_struct.html for registers

                                // println!("syscall = {}", regs.orig_rax);
                                // println!("arg1    = {:#x}", regs.rdi);
                                // println!("arg2    = {:#x}", regs.rsi);
                                // println!("arg3    = {:#x}", regs.rdx);
                                // println!("arg3    = {:#x}", regs.r10);
                                // println!("arg3    = {:#x}", regs.r8);
                                // println!("arg3    = {:#x}", regs.r9);

                                let args = SyscallArgs {
                                    // arg0 : regs.rdi as usize,
                                    // arg1 : regs.rsi as usize,
                                    // arg2 : regs.rdx as usize,
                                    // arg3 : regs.r10 as usize,
                                    // arg4 : regs.r8 as usize,
                                    // arg5 : regs.r9 as usize,
                                };

                                let sysno : Sysno;
                                match Sysno::try_from(regs.orig_rax as u32) {
                                    Ok(n) => {
                                        println!("Syscall: {}", n);
                                        sysno = n
                                    },
                                    Err(_) =>  {
                                        eprintln!("Unrecognized syscall number: {}", regs.orig_rax);
                                        break;
                                    }
                                }

                                /*
                                inspect arguments relative to whatever syscall it is, 

                                i.e. open(path, flags, mode)

                                check path if path is under process previlege level
                                */

                                let syscall_result : Result<usize, Errno>;
                                if route_syscall {
                                    syscall_result = syscall(sysno, &args);
                                }

                                /*


                                check sysctl and see if kernel parameters are all same
                                check privelge of child after executing syscall
                                check registers and modify childs based on what happened.

                                try to get exit of the syscall

                                */

                                // TODO: proper error handling for syscall return values

                                // Continue with syscall-stop
                                libc::ptrace(libc::PTRACE_CONT, child, 0, 0);
                                continue;
                            }
                        }
                        // else normal stop:
                        libc::ptrace(libc::PTRACE_CONT, child, 0, 0);
                    }
                }
            }
        }
        Ok(Fork::Child) => {
            install_seccomp_trap_filter(); // installs filter in child process
            println!("Child process: executing {:?}", args.path);


            let exec_path = CString::new(args.path.to_str().unwrap()).unwrap();
            
            unsafe {
                libc::execl(exec_path.as_ptr(), exec_path.as_ptr(), std::ptr::null::<i8>());
            }
            panic!("exec failed");
        },
        Err(_) => println!("Fork failed"),
    }
}
