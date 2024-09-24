/*
    shellcode : [u8; len]
    ZeroMemory(STARTUPINFOA)
    CreateProcessA -> flags(CREATE_SUSPENDED)
    VirtualAllocEx()
    WriteProcessMemory()
    QueueUserAPC()
    ResumeThread()
    CloseHandle()
*/

pub mod utils;
mod inject;

#[macro_export]
macro_rules! error_occured {
    ($obj_name : expr) => {
        println!("{} [{}] {}", "[-] An error occurred".red(), $obj_name.red(), 
    unsafe{ GetLastError() })
    }
}