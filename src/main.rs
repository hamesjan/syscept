
use std::path::PathBuf;
use fork::{fork, Fork};
use std::ffi::CString;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::convert::TryInto;

// use libc::execv;    

struct Cli {
    path: PathBuf,
}


extern "C" fn sigsys_handler(sig: i32, info: *mut siginfo_t, _ctx: *mut c_void) {
    unsafe {
        eprintln!(
            "[SIGSYS] Signal {}: syscall={} (bad syscall caught!)",
            sig,
            (*info)._reason._syscall
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
        // Where you define policy for each syscall on watchlist 
    ]
    .into_iter()
    .collect(),
    SeccompAction::Allow, // default action for not listed syscalls
    SeccompAction::Trap, // on error?
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
        }
        Ok(Fork::Child) => {
            install_sigsys_handler();
            install_seccomp_trap_filter(); // installs filter in child process
            println!("Child process: executing {:?}", args.path);

            let path = CString::new(target).unwrap();
            unsafe {
                libc::execl(path.as_ptr(), path.as_ptr(), std::ptr::null::<i8>());
            }
            panic!("exec failed");
        },
        Err(_) => println!("Fork failed"),
    }
}
