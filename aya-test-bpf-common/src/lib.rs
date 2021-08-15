#![no_std]

#[repr(C)]
pub struct LogEvent {
    pub tag: u64,
    pub field: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LogEvent {}

#[repr(C)]
pub struct Sample {
    pub timestamp: u64,
    pub cpu_delta: u64,
    pub pid: i32,
    pub tid: i32,
    pub is_on_cpu: u32,
    pub off_cpu_sample_count: u32,
    pub stack_id: i64,
    pub thread_name: [i8; 16],
}

#[cfg(feature = "user")]
unsafe impl Send for Sample {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Sample {}
