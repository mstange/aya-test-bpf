#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(unused)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
mod bindings;

use aya_bpf::bindings::BPF_F_USER_STACK;
use aya_bpf::helpers::{
    bpf_get_current_comm, bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_probe_read,
};
use aya_bpf::macros::map;
use aya_bpf::macros::{kprobe, perf_event, tracepoint};
use aya_bpf::maps::{HashMap, PerfMap, StackTrace};
use aya_bpf::programs::{PerfEventContext, ProbeContext, TracePointContext};
use aya_bpf::BpfContext;
use aya_test_bpf_common::{Sample, LogEvent};
use bindings::{
    bpf_perf_event_data, pid_t, pt_regs, task_struct, thread_struct, trace_event_raw_sched_switch,
};
use core::ptr::null;
use memoffset::offset_of;

#[derive(Clone)]
struct ThreadTimingData {
    active: u64,
    /// we sample every time this overflows sample_period
    off_cpu_wrapping_counter_ns: u64,
    /// set to zero after every sample
    cpu_delta_since_last_sample_ns: u64,
    /// set to the current timestamp on on/sample/off
    last_seen_ts: u64,
    /// set to the current stack when going off
    stack_when_going_off: i64,
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfMap<LogEvent> = PerfMap::<LogEvent>::with_max_entries(1024, 0);

#[map(name = "SAMPLES")]
static mut SAMPLES: PerfMap<Sample> = PerfMap::<Sample>::with_max_entries(1024, 0);

#[map(name = "STACKS")]
static mut STACKS: StackTrace = StackTrace::with_max_entries(102400, 0);

#[map(name = "THREAD_TIMING")]
static mut THREAD_TIMING: HashMap<i32, ThreadTimingData> = HashMap::with_max_entries(1024, 0);

static SAMPLE_PERIOD_NS: u64 = 1000000;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[inline(always)]
fn get_thread_timing(pid: i32, now: u64, active: bool) -> ThreadTimingData {
    match unsafe { THREAD_TIMING.get(&pid) } {
        Some(timing) => timing.clone(),
        None => ThreadTimingData {
            active: active as u64,
            off_cpu_wrapping_counter_ns: 0,
            cpu_delta_since_last_sample_ns: 0,
            last_seen_ts: now,
            stack_when_going_off: -1,
        },
    }
}

#[inline(always)]
fn set_thread_timing(pid: i32, timing: &ThreadTimingData) {
    let _ = unsafe { THREAD_TIMING.insert(&pid, timing, 0) };
}

#[inline(always)]
fn thread_goes_on(
    ctx: &impl BpfContext,
    pid: i32,
    tgid: i32,
    now: u64,
    comm: &[::aya_bpf_cty::c_char; 16usize],
) {
    let mut timing = get_thread_timing(pid, now, false);
    let sleep_time: u64 = now - timing.last_seen_ts;
    timing.off_cpu_wrapping_counter_ns += sleep_time;
    let off_cpu_sample_count = timing.off_cpu_wrapping_counter_ns / SAMPLE_PERIOD_NS;
    if off_cpu_sample_count > 0 {
        timing.off_cpu_wrapping_counter_ns -= off_cpu_sample_count * SAMPLE_PERIOD_NS;
        let sample = Sample {
            timestamp: now,
            cpu_delta: timing.cpu_delta_since_last_sample_ns,
            pid: tgid,
            tid: pid,
            is_on_cpu: 0,
            off_cpu_sample_count: off_cpu_sample_count as u32,
            stack_id: timing.stack_when_going_off,
            thread_name: comm.clone(),
        };
        unsafe { SAMPLES.output(ctx, &sample, 0) };
        timing.cpu_delta_since_last_sample_ns = 0;
    }
    timing.last_seen_ts = now;
    timing.active = 1;
    set_thread_timing(pid, &timing);
}

#[inline(always)]
fn thread_goes_off(ctx: &impl BpfContext, pid: i32, _tgid: i32, now: u64) {
    let mut timing = get_thread_timing(pid, now, true);
    let on_cpu_time_delta = now - timing.last_seen_ts;
    timing.cpu_delta_since_last_sample_ns += on_cpu_time_delta;
    timing.last_seen_ts = now;
    timing.active = 0;
    timing.stack_when_going_off = match unsafe { STACKS.get_stackid(ctx, BPF_F_USER_STACK.into()) }
    {
        Ok(stack) => stack,
        Err(e) => e,
    };
    set_thread_timing(pid, &timing);
}

#[inline(always)]
fn thread_gets_sampled_while_on(
    ctx: &impl BpfContext,
    pid: i32,
    tgid: i32,
    now: u64,
    comm: &[::aya_bpf_cty::c_char; 16usize],
) {
    let mut timing = get_thread_timing(pid, now, true);
    if timing.active == 0 {
        return;
    }
    let on_cpu_time_delta = now - timing.last_seen_ts;
    timing.cpu_delta_since_last_sample_ns += on_cpu_time_delta;
    let stack_id = match unsafe { STACKS.get_stackid(ctx, BPF_F_USER_STACK.into()) } {
        Ok(stack) => stack,
        Err(e) => e,
    };
    let sample = Sample {
        timestamp: now,
        cpu_delta: timing.cpu_delta_since_last_sample_ns,
        pid: tgid,
        tid: pid,
        is_on_cpu: 1,
        off_cpu_sample_count: 0,
        stack_id,
        thread_name: comm.clone(),
    };
    unsafe { SAMPLES.output(ctx, &sample, 0) };
    timing.cpu_delta_since_last_sample_ns = 0;
    timing.last_seen_ts = now;
    set_thread_timing(pid, &timing);
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
    // let regs: *const pt_regs = bpf_probe_read(ctx.as_ptr() as *const _)?;
    // let ax: u64 = bpf_probe_read(regs.offset(offset_of!(pt_regs, ax) as isize) as *const _)?;
    // let log_event = LogEvent {
    //     tag: 1,
    //     field: ax,
    // };
    // EVENTS.output(&ctx, &log_event, 0);

    let prev_pid = bpf_probe_read(
        ctx.as_ptr()
            .offset(offset_of!(trace_event_raw_sched_switch, prev_pid) as isize)
            as *const pid_t,
    )?;
    let next_pid = bpf_probe_read(
        ctx.as_ptr()
            .offset(offset_of!(trace_event_raw_sched_switch, next_pid) as isize)
            as *const pid_t,
    )?;
    let now = bpf_ktime_get_ns();

    if prev_pid != 0 {
        let prev_tgid = 0; // TODO
        thread_goes_off(&ctx, prev_pid, prev_tgid, now);
    }

    if next_pid != 0 {
        let next_comm = bpf_probe_read(
            ctx.as_ptr()
                .offset(offset_of!(trace_event_raw_sched_switch, next_comm) as isize)
                as *const [::aya_bpf_cty::c_char; 16usize],
        )?;
        let next_comm = [0; 16];
        let next_tgid = 0; // TODO
        thread_goes_on(&ctx, next_pid, next_tgid, now, &next_comm);
    }
    // // let stack_id = match STACKS.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
    // //     Ok(stack) => stack,
    // //     Err(e) => e,
    // // };
    // // let task: *const task_struct = bpf_get_current_task_btf() as *const task_struct;
    // // let current_pid = bpf_probe_read(task as *const u64)?;
    // let switch_entry = LogEvent {
    //     timestamp,
    //     prev_pid,
    //     next_pid,
    // };
    // EVENTS.output(&ctx, &switch_entry, 0);
    Ok(0)
}

#[perf_event(name = "cpu_clock")]
pub fn cpu_clock(ctx: PerfEventContext) -> u32 {
    if ctx.pid() == 0 {
        return 0;
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => return 0,
    };
    thread_gets_sampled_while_on(&ctx, ctx.pid() as i32, ctx.tgid() as i32, now, &comm);

    // let stack_id = match unsafe {
    //     bpf_probe_read(ctx.as_ptr().offset(offset_of!(pt_regs, ip) as isize) as *const u64)
    // } {
    //     Ok(val) => val as i64,
    //     Err(e) => e,
    // };
    // // let stack_id = match unsafe { STACKS.get_stackid(&ctx, BPF_F_USER_STACK.into()) } {
    // //     Ok(stack) => stack,
    // //     Err(e) => e
    // // };
    // let timestamp = unsafe { bpf_ktime_get_ns() };
    // let switch_entry = LogEvent {
    //     prev_pid: 13,
    //     next_pid: 5,
    //     timestamp,
    //     stack_id,
    // };
    // unsafe { EVENTS.output(&ctx, &switch_entry, 0) };
    0
}

#[kprobe(name = "finish_task_switch")]
pub fn finish_task_switch(ctx: ProbeContext) -> u32 {
    match unsafe { try_finish_task_switch(ctx) } {
        Ok(ret) => ret,
        Err(_e) => 0,
    }
}

#[inline(always)]
pub unsafe fn try_finish_task_switch(ctx: ProbeContext) -> Result<u32, i64> {
    // let regs = ctx.as_ptr() as *const pt_regs;
    // let prev_task = bpf_probe_read(&(*regs).ax as *const u64 as *const *const task_struct)?;
    // let prev_pid =
    //     bpf_probe_read(prev_task.offset(0).offset(offset_of!(task_struct, pid) as isize) as *const pid_t)?;
    // let regs = bpf_probe_read(ctx.as_ptr() as *const *const pt_regs)?;
    // let ip = if regs == null() { 0 } else { bpf_probe_read(&(*regs).ip)? };
    // let next_pid = ctx.pid() as i32;
    // let timestamp = bpf_ktime_get_ns();
    // // let stack_id = match STACKS.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
    // //     Ok(stack) => stack,
    // //     Err(e) => e,
    // // };
    // // let task: *const task_struct = bpf_get_current_task_btf() as *const task_struct;
    // // let current_pid = bpf_probe_read(task as *const u64)?;
    // let switch_entry = LogEvent {
    //     timestamp,
    //     prev_pid,
    //     next_pid,
    // };
    // EVENTS.output(&ctx, &switch_entry, 0);
    Ok(0)
}
