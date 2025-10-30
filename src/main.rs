
use std::path::PathBuf;
use fork::{fork, Fork};

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
        Ok(Fork::Child) => println!("I'm a new child process"),
        Err(_) => println!("Fork failed"),
    }

    println!("path: {:?}", args.path)
}