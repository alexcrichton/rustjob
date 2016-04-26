extern crate kernel32;
extern crate psapi;
extern crate winapi;

use std::env;
use std::ffi::OsString;
use std::io;
use std::mem;
use std::os::windows::prelude::*;
use std::process::Command;

macro_rules! status {
    ($fmt: expr) => {
        println!(concat!(">> rustjob: ", $fmt));
    };
    ($fmt: expr, $($args:tt)*) => {
        println!(concat!(">> rustjob: ", $fmt), $($args)*);
    }
}

fn main() {
    unsafe {
        let job = create_job();

        let args = env::args_os().skip(1).collect::<Vec<_>>();
        let status = Command::new(&args[0]).args(&args[1..]).status().unwrap();

        while kill_processes(&job) {
            // ...
        }
        close_job(job);

        std::process::exit(status.code().unwrap_or(1))
    }
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

struct Handle(winapi::HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            kernel32::CloseHandle(self.0);
        }
    }
}

unsafe fn create_job() -> Handle {
    use kernel32::*;
    use winapi::*;

    let job = CreateJobObjectW(0 as *mut _, 0 as *const _);
    if job.is_null() {
        panic!("failed to create job object: {}", last_err());
    }

    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let r = SetInformationJobObject(job,
                                    JobObjectExtendedLimitInformation,
                                    &mut info as *mut _ as LPVOID,
                                    mem::size_of_val(&info) as DWORD);
    if r == 0 {
        panic!("failed to set job info: {}", last_err());
    }
    let r = AssignProcessToJobObject(job, GetCurrentProcess());
    if r == 0 {
        panic!("failed to add to job object: {}", last_err());
    }
    Handle(job)
}

unsafe fn kill_processes(job: &Handle) -> bool {
    use kernel32::*;
    use psapi::*;
    use winapi::*;

    #[repr(C)]
    struct Jobs {
        header: JOBOBJECT_BASIC_PROCESS_ID_LIST,
        list: [ULONG_PTR; 1024],
    }

    let mut jobs: Jobs = mem::zeroed();
    let r = QueryInformationJobObject(job.0,
                                      JobObjectBasicProcessIdList,
                                      &mut jobs as *mut _ as LPVOID,
                                      mem::size_of_val(&jobs) as DWORD,
                                      0 as *mut _);
    if r == 0 {
        panic!("failed to query job object: {}", last_err());
    }

    let mut killed = false;

    let list = &jobs.list[..jobs.header.NumberOfProcessIdsInList as usize];
    assert!(list.len() > 0);
    status!("found {} remaining processes", list.len() - 1);
    for &id in list {
        // let's not kill ourselves
        if id as DWORD == GetCurrentProcessId() {
            continue
        }

        let p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE |
                                SYNCHRONIZE,
                            FALSE,
                            id as DWORD);
        // If we couldn't open the process, then perhaps it exited?
        if p.is_null() {
            continue
        }
        let p = Handle(p);

        let mut buf = [0; 1024];
        let r = GetProcessImageFileNameW(p.0, buf.as_mut_ptr(), buf.len() as DWORD);
        if r == 0 {
            panic!("failed to get image name of {}: {}", id, last_err());
        }
        let s = OsString::from_wide(&buf[..r as usize]);
        status!("found remaining: {} - {:?}", id, s);

        let mut res = 0;
        let r = IsProcessInJob(p.0, job.0, &mut res);
        if r == 0 {
            panic!("failed to test is process in job: {}", last_err());
        }
        if res != TRUE {
            status!("\tnot in this job");
            continue
        }

        if let Some(s) = s.to_str() {
            if s.contains("mspdbsrv") {
                status!("\toops, this is mspdbsrv");
                continue
            }
        }

        status!("\tkilling still-running process");
        let r = TerminateProcess(p.0, 1);
        if r == 0 {
            panic!("failed to terminate subprocess {}: {}", id, last_err());
        }
        let r = WaitForSingleObject(p.0, INFINITE);
        if r != 0 {
            panic!("failed to wait for process to die: {}", last_err());
        }
        killed = true;
    }

    return killed
}

unsafe fn close_job(job: Handle) {
    use kernel32::*;
    use winapi::*;

    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
    let r = SetInformationJobObject(job.0,
                                    JobObjectExtendedLimitInformation,
                                    &mut info as *mut _ as LPVOID,
                                    mem::size_of_val(&info) as DWORD);
    if r == 0 {
        panic!("failed to configure job object to defaults: {}", last_err());
    }
}
