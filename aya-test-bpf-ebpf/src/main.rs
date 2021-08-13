#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(unused)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
mod bindings;

use core::convert::TryInto;
use aya_bpf::helpers::bpf_probe_read;
use aya_bpf::macros::map;
use aya_bpf::macros::tracepoint;
use aya_bpf::maps::PerfMap;
use aya_bpf::programs::TracePointContext;
use aya_bpf::BpfContext;
use aya_test_bpf_common::SwitchLog;
use bindings::{pid_t, task_struct};
use memoffset::offset_of;

#[map(name = "EVENTS")]
static mut EVENTS: PerfMap<SwitchLog> = PerfMap::<SwitchLog>::with_max_entries(1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[tracepoint(name = "sched_switch")]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match unsafe { try_sched_switch(ctx) } {
        Ok(ret) => ret,
        Err(_e) => 0,
    }
}

#[inline(always)]
pub unsafe fn try_sched_switch(ctx: TracePointContext) -> Result<u32, i64> {
    let prev_task: *const task_struct = bpf_probe_read(ctx.as_ptr().add(1) as *const _)?;
    let prev_pid = match
        bpf_probe_read(prev_task.offset(offset_of!(task_struct, pid) as isize) as *const pid_t) {
            Ok(pid) => pid,
            Err(e) => e.try_into().unwrap_or(-999),
        };

    // let next_task: *const task_struct = bpf_probe_read(ctx.as_ptr().add(2) as *const _)?;
    // let next_pid: u32 = bpf_probe_read(next_task.offset(offset_of!(task_struct, pid) as isize) as *const pid_t)?;
    // let val1: u64 = bpf_probe_read(ctx.as_ptr().add(0) as *const u64)?;
    // let val2: u64 = bpf_probe_read((val1 as *const u64).offset(offset_of!(task_struct, pid) as isize))?;
    // let mut val2: u64 = 0;
    // let ret = bpf_probe_read_kernel(&mut val2 as *const _ as *const c_void, 8, val1 as *const c_void);
    // let val2: u64 = ctx.read_at(2)?;

    let next_pid = ctx.pid() as i32;
    let switch_entry = SwitchLog { prev_pid, next_pid };
    EVENTS.output(&ctx, &switch_entry, 0);
    Ok(0)
}

/*
use aya_bpf::cty::{c_char, c_long, c_void};
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};

#[no_mangle]
#[link_section = "tp/sched_switch"]
// #[link_section = "tp_btf/sched_switch"]
fn sched_switch(ctx: *mut u64) -> u32 {
   let preempt = unsafe { bpf_probe_read(ctx.add(0)).unwrap_or(0) as *const ::core::ffi::c_void };
   let prev = unsafe { bpf_probe_read(ctx.add(1)).unwrap_or(0) as *const ::core::ffi::c_void };
//    let preempt: u32 = unsafe { bpf_probe_read(preempt as *const u32).unwrap_or(17) };
//    let stuff: *const task_struct = unsafe { bpf_probe_read((preempt as *const *const task_struct).add(1)).unwrap_or(17 as *const task_struct) };
//    let prev: *const task_struct = unsafe { bpf_probe_read((ctx as *const *const task_struct).add(1)).unwrap_or(::core::ptr::null_mut()) };
   let prev_pid: pid_t = unsafe { bpf_probe_read(prev.offset(offset_of!(task_struct, pid) as isize) as *const pid_t).unwrap_or(17) };
   let next_pid: pid_t = unsafe { bpf_get_current_pid_tgid() as u32 as i32 };
//    let next: *const task_struct = unsafe { bpf_probe_read((ctx as *const *const task_struct).add(2)).unwrap_or(::core::ptr::null_mut()) };
   let switch_entry = SwitchLog{
       prev_pid: prev_pid as u32,
       next_pid: next_pid as u32,
   };
   unsafe { EVENTS.output(&::aya_bpf::programs::TracePointContext::new(ctx as *mut ::core::ffi::c_void), &switch_entry, 0); }
   0
}
 */
