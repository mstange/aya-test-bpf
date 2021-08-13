#![no_std]

#[repr(C)]
pub struct SwitchLog {
    pub prev_pid: i32,
    pub next_pid: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SwitchLog {}
