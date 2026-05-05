use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Memory::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("usage: siliconhook.exe <pid> <address>");
        return;
    }

    let pid: u32 = args[1].parse().expect("invalid pid");
    let addr = u64::from_str_radix(args[2].trim_start_matches("0x"), 16).expect("invalid address");

    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process_handle == 0 { panic!("[-] could not open process handle."); }

        if DebugActiveProcess(pid) == 0 { panic!("[-] DebugAttach failed."); }

        let thread_id = get_main_thread_id(pid);
        let thread_handle = OpenThread(THREAD_ALL_ACCESS, 0, thread_id);
        apply_hardware_breakpoint(thread_handle, addr);
        CloseHandle(thread_handle);

        println!("[!] monitor active...");

        let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
        loop {
            if WaitForDebugEvent(&mut debug_event, INFINITE) != 0 {
                if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                    let code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
                    
                    if code == EXCEPTION_SINGLE_STEP {
                        let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, debug_event.dwThreadId);
                        let mut ctx: CONTEXT = std::mem::zeroed();
                        ctx.ContextFlags = 0x100000 | 0x1 | 0x2 | 0x10;

                        if GetThreadContext(h_thread, &mut ctx) != 0 {
                            println!("\n[!] hook triggered.");
                            println!("    cpu at: 0x{:016x}", ctx.Rip);
                            println!("    rcx:    0x{:016x} | rax: 0x{:016x}", ctx.Rcx, ctx.Rax);

                            let mut buffer = [0u8; 64];
                            let mut bytes_rw = 0;
                            if ReadProcessMemory(process_handle, ctx.Rcx as *const _, buffer.as_mut_ptr() as _, buffer.len(), &mut bytes_rw) != 0 {
                                let hex_dump: String = buffer.iter().take(12).map(|b| format!("{:02X} ", b)).collect();
                                let utf16_data: Vec<u16> = buffer.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                                
                                println!("    >>> data at rcx (original):");
                                println!("        [hex]:  {}", hex_dump);
                                println!("        [utf8]: \"{}\"", String::from_utf8_lossy(&buffer).trim_matches(char::from(0)));
                                println!("        [wide]: \"{}\"", String::from_utf16_lossy(&utf16_data).trim_matches(char::from(0)));
                            }

                            let payload = "PWNED_BY_SILICON\0";
                            WriteProcessMemory(process_handle, ctx.Rcx as *const _, payload.as_ptr() as _, payload.len(), &mut bytes_rw);
                            println!("    [+] injected payload into rcx buffer.");

                            let mut stack = [0u64; 2];
                            if ReadProcessMemory(process_handle, ctx.Rsp as *const _, stack.as_mut_ptr() as _, 16, &mut bytes_rw) != 0 {
                                println!("    >>> stack peek: [rsp]: 0x{:x} | [rsp+8]: 0x{:x}", stack[0], stack[1]);
                            }

                            let original_dr7 = ctx.Dr7;
                            ctx.Dr7 = 0; 
                            ctx.EFlags |= 0x100; 
                            SetThreadContext(h_thread, &ctx);
                            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);

                            let mut step_ev: DEBUG_EVENT = std::mem::zeroed();
                            WaitForDebugEvent(&mut step_ev, INFINITE);

                            GetThreadContext(h_thread, &mut ctx);
                            println!("    [?] post-tamper status: rax = 0x{:x}", ctx.Rax);
                            
                            ctx.Dr7 = original_dr7;
                            ctx.EFlags &= !0x100;
                            SetThreadContext(h_thread, &ctx);
                        }
                        CloseHandle(h_thread);
                    }
                }
                ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
            }
        }
    }
}

unsafe fn apply_hardware_breakpoint(thread_handle: HANDLE, addr: u64) {
    SuspendThread(thread_handle);
    let mut context: CONTEXT = std::mem::zeroed();
    context.ContextFlags = 0x100000 | 0x10; 
    if GetThreadContext(thread_handle, &mut context) != 0 {
        context.Dr0 = addr;
        context.Dr7 = 0x1; 
        SetThreadContext(thread_handle, &context);
        println!("[+] hardware hook at 0x{:x}", addr);
    }
    ResumeThread(thread_handle);
}

unsafe fn get_main_thread_id(pid: u32) -> u32 {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    if Thread32First(snapshot, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                CloseHandle(snapshot);
                return te.th32ThreadID;
            }
            if Thread32Next(snapshot, &mut te) == 0 { break; }
        }
    }
    CloseHandle(snapshot);
    0
}