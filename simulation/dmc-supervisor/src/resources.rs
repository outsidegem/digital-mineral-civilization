// Resource provider using sysinfo crate and fallback statvfs
use std::path::Path;
use std::os::unix::ffi::OsStrExt;
use sysinfo::{Disks, Pid, System};

#[allow(dead_code)]
pub trait ResourceProvider {
    fn memory_usage_mb(&self) -> u64;
    fn free_disk_mb(&self, path: &Path) -> u64;
    fn memory_mb_of_pid(&self, pid: u32) -> Option<u64>;
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SysInfoProvider {
    sys: System,
}

impl SysInfoProvider {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self { sys }
    }

    pub fn memory_mb_of_pid(&self, pid: u32) -> Option<u64> {
        let mut sys = System::new_all();
        let pid = Pid::from(pid as usize);
        sys.refresh_process(pid);
        sys.process(pid).map(|p| p.memory() / 1_048_576)
    }
}

impl Default for SysInfoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceProvider for SysInfoProvider {
    fn memory_usage_mb(&self) -> u64 {
        // used_memory returns bytes; convert to MiB
        self.sys.used_memory() / 1_048_576
    }

    fn free_disk_mb(&self, path: &Path) -> u64 {
        // Try sysinfo disks first
        let disks = Disks::new_with_refreshed_list();
        let mut best_match: Option<u64> = None;
        for disk in disks.iter() {
            let mount = disk.mount_point();
            if path.starts_with(mount) {
                best_match = Some(disk.available_space() / 1024 / 1024);
                break;
            }
        }
        // If sysinfo gave a non‑zero result, use it
        if let Some(avail) = best_match {
            if avail > 0 {
                return avail;
            }
        }
        // Fallback: use statvfs on the provided path (Unix only)
        #[cfg(target_family = "unix")]
        {
            use std::ffi::CString;
            use libc::statvfs;
            let c_path = match CString::new(path.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => return u64::MAX,
            };
            let mut stat: statvfs = unsafe { std::mem::zeroed() };
            let res = unsafe { statvfs(c_path.as_ptr(), &mut stat) };
            if res == 0 {
                let block_size = stat.f_bsize as u64;
                let avail_blocks = stat.f_bavail as u64;
                let bytes = block_size * avail_blocks;
                return bytes / 1024 / 1024;
            }
        }
        // If all else fails, treat as unknown (use max to avoid false success)
        u64::MAX
    }

    fn memory_mb_of_pid(&self, pid: u32) -> Option<u64> {
        SysInfoProvider::memory_mb_of_pid(self, pid)
    }
}
