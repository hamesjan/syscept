
use std::path::PathBuf;
use fork::{fork, Fork};
use std::ffi::CString;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter,
};
use std::convert::TryInto;
use libc::{self, c_void, siginfo_t, sigaction, c_int, pid_t, SIGTRAP, WIFEXITED, WEXITSTATUS, WSTOPSIG};
// use libc::execv;    

// for CLI path
struct Cli {
    path: PathBuf,
}

#[repr(C)]
struct SigSysFields {
    _call_addr: *mut libc::c_void,
    syscall: libc::c_int,
}

extern "C" fn sigsys_handler(sig: i32, info: *mut siginfo_t, _ctx: *mut c_void) {
    unsafe {
        // let sigsys_ptr = info as *const SigSysFields;

        eprintln!(
            "[SIGSYS] signal={} si_code={} errno={}",
            sig,
            (*info).si_code, 
            (*info).si_errno,
            // (*sigsys_ptr).syscall,
            // (*sigsys_ptr)._call_addr,

        );
    }
}

fn install_sigsys_handler() {
    unsafe {
        let mut act: sigaction = std::mem::zeroed();
        act.sa_sigaction = sigsys_handler as usize;
        act.sa_flags = libc::SA_SIGINFO;

        if libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut()) != 0 {
            eprintln!("Failed to install SIGSYS handler");
        }
    }
}


fn install_seccomp_trap_filter() {
    // Only allow write syscall, everything else triggers Trap (SIGSYS)
    let filter: BpfProgram = SeccompFilter::new(
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_write, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_getpid, vec![]),

        // Will have to define for all syscalls used by target binary
        // Where you define policy for each syscall on watchlist 
    ]
    .into_iter()
    .collect(),
    SeccompAction::Trace(0), // SeccompAction::Trap, // not in filter
    SeccompAction::Allow, // match
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

            // Wait for seccomp traps from the child
            let mut status: c_int = 0;

            loop {
                unsafe {
                    let pid = libc::waitpid(child, &mut status as *mut c_int, 0);
                    if pid < 0 {
                        eprintln!("waitpid failed");
                        break;
                    }

                    if WIFEXITED(status) {
                        let code = WEXITSTATUS(status);
                        println!("[parent] child exited with {}", code);
                        break;
                    }

                    // SIGTRAP indicates seccomp event (for SeccompAction::Trace)
                    if WSTOPSIG(status) == SIGTRAP {
                        println!("[parent] got SIGTRAP (seccomp event)");

                        // You can inspect registers here if you like
                        libc::ptrace(libc::PTRACE_SYSCALL, child, 0, 0);
                    } else {
                        // resume normally
                        libc::ptrace(libc::PTRACE_CONT, child, 0, 0);
                    }
                }
            }
        }
        Ok(Fork::Child) => {
            unsafe {
                libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            }

            install_sigsys_handler();
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
