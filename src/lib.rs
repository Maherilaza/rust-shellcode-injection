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