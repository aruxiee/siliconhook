use std::process;
use std::thread;
use std::time::Duration;

#[no_mangle]
#[inline(never)]
pub fn target_function() {
    println!("executing target_function...");
}

fn main() {
    let pid = process::id();
    let addr = target_function as *const () as usize;

    println!("pid: {}", pid);
    println!("target address: 0x{:x}", addr);
    println!("waiting for hooks...");

    loop {
        target_function();
        thread::sleep(Duration::from_secs(2));
    }
}