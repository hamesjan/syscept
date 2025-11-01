
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


let filter: BpfProgram = SeccompFilter::new(
    vec![
        (libc::SYS_accept4, vec![]),
        (
            libc::SYS_fcntl,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        libc::F_SETFD as u64,
                    )
                    .unwrap(),
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        libc::FD_CLOEXEC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
                SeccompRule::new(vec![SeccompCondition::new(
                    1,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    libc::F_GETFD as u64,
                )
                .unwrap()])
                .unwrap(),
            ],
        ),
    ]
    .into_iter()
    .collect(),
    SeccompAction::Allow,
    SeccompAction::Trap,
    std::env::consts::ARCH.try_into().unwrap(),
)
.unwrap()
.try_into()
.unwrap();

seccompiler::apply_filter(&filter).unwrap();

fn main(){
    let path = std::env::args().nth(1).expect("no path to binary given");

    let args = Cli {
        path: PathBuf::from(path),
    };

    // match fork() {
    //     Ok(Fork::Parent(child)) => {
    //         println!("Continuing execution in parent process, new child has pid: {}", child);
    //     }
    //     Ok(Fork::Child) => {
    //         println!("Child process: executing {:?}", args.path);

    //         // Convert Rust PathBuf to CString for execv
    //         let exec_path = CString::new(args.path.to_str().unwrap()).unwrap();
    //         // let argv = &[exec_path.clone()]; // No args passed to program

    //         // // Replace process image with new binary
    //         // execv(&exec_path, argv).expect("exec failed");
    //     },
    //     Err(_) => println!("Fork failed"),
    // }
}
