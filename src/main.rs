
use std::path::PathBuf;
use fork::{fork, Fork};
use std::ffi::CString;
// use libc::execv;    

struct Cli {
    path: PathBuf,
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
            println!("Child process: executing {:?}", args.path);

            // Convert Rust PathBuf to CString for execv
            let exec_path = CString::new(args.path.to_str().unwrap()).unwrap();
            // let argv = &[exec_path.clone()]; // No args passed to program

            // // Replace process image with new binary
            // execv(&exec_path, argv).expect("exec failed");
        },
        Err(_) => println!("Fork failed"),
    }
}
