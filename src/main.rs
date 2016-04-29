// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A small wrapper script used by the Rust project on the buildbots to isolate
//! builds.
//!
//! By default interrupting a build on buildbot doesn't actually kill the whole
//! process tree, just the process at the top. This means that process left
//! around (like compilers, linkers, etc) could continue to hold files open and
//! cause future builds to fail as they may be hung and fail to exit.
//!
//! The purpose of this script is to ensure that the entire process tree is
//! killed if this script is killed. This is done through the use of job objects
//! on Windows.

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
        // First up, create our job object.
        let job = create_job();

        // Next, actually execute what we're supposed to do.
        let args = env::args_os().skip(1).collect::<Vec<_>>();
        let status = Command::new(&args[0]).args(&args[1..]).status().unwrap();

        // This is a litte subtle. By default if we are terminated then all
        // processes in our job object are terminated as well, but we
        // intentionally want to whitelist some processes to outlive our job
        // object (see below).
        //
        // To allow for this, we manually kill processes instead of letting the
        // job object kill them for us. We do this in a loop to handle processes
        // spawning other processes.
        //
        // Finally once this is all done we know that the only remaining ones
        // are ourselves and the whitelisted processes. The `close_job` then
        // configures our job object to *not* kill everything on close, then
        // closes the job object.
        while kill_processes(&job) {
            status!("killed some processes, going back to look for more");
        }
        close_job(job);

        // Try to hav the same return code as the child we spawned.
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

/// Create a new job object, configure it to kill everything if the job object
/// is closed, and then add ourselves to the job object.
///
/// Once we've added ourselves to the job object we're guaranteed that if we are
/// abnormally terminated then our entire process tree is terminated. By default
/// all our spawned children are part of our job object as well.
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

/// Kill all active processes in a job object, except those in our whitelist.
///
/// There are a few processes we intentionally leak outside the job object (see
/// below for details), so this function will kill as much as possible in the
/// job object excluding ourselves and those on the whitelist.
///
/// Returns whether any processes were killed or not.
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

        // Open the process with the necessary rights, and if this fails then we
        // probably raced with the process exiting so we ignore the problem.
        let p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE |
                                SYNCHRONIZE,
                            FALSE,
                            id as DWORD);
        if p.is_null() {
            continue
        }
        let p = Handle(p);

        // Load the file which this process was spawned from. We then later use
        // this for identification purposes.
        let mut buf = [0; 1024];
        let r = GetProcessImageFileNameW(p.0, buf.as_mut_ptr(), buf.len() as DWORD);
        if r == 0 {
            panic!("failed to get image name of {}: {}", id, last_err());
        }
        let s = OsString::from_wide(&buf[..r as usize]);
        status!("found remaining: {} - {:?}", id, s);

        // Test if this process was actually in the job object or not. If it's
        // not then we likely raced with something else recycling this PID, so
        // we just skip this step.
        let mut res = 0;
        let r = IsProcessInJob(p.0, job.0, &mut res);
        if r == 0 {
            panic!("failed to test is process in job: {}", last_err());
        }
        if res != TRUE {
            status!("\tnot in this job");
            continue
        }

        // And here's where we find the whole purpose for this function!
        // Currently, our only whitelisted process is `mspdbsrv.exe`, and more
        // details about that can be found here:
        //
        //      https://github.com/rust-lang/rust/issues/33145
        //
        // The gist of it is that all builds on one machine use the same
        // `mspdbsrv.exe` instance. If we were to kill this instance then we
        // could erroneously cause other builds to fail.
        if let Some(s) = s.to_str() {
            if s.contains("mspdbsrv") {
                status!("\toops, this is mspdbsrv");
                continue
            }
        }

        // Ok, this isn't mspdbsrv, let's kill the process. After we kill it we
        // wait on it to ensure that the next time around in this function we're
        // not going to see it again.
        let r = TerminateProcess(p.0, 1);
        if r == 0 {
            status!("\tfailed to kill subprocess {}: {}", id, last_err());
            status!("\tassuming subprocess is dead...");
        } else {
            status!("\tterminated subprocess {}", id);
        }
        let r = WaitForSingleObject(p.0, INFINITE);
        if r != 0 {
            panic!("failed to wait for process to die: {}", last_err());
        }
        killed = true;
    }

    return killed
}

/// Prepare for closing the job object.
///
/// When we close this job object, it's by default configured to kill every
/// process that's a member of it. Note that processes on our whitelist,
/// however, are still in this job object, so closing it will cause them to go
/// away.
///
/// We intentionally want to "leak" those processes, so reconfigure our job
/// object to *not* kill anything when the job object is closed. After that we
/// just drop it and close it and nothing should get killed abnormally.
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
