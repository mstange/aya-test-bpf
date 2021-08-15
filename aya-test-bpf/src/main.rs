use aya::{
    maps::{
        perf::{AsyncPerfEventArray, PerfBufferError},
        MapRefMut, StackTraceMap,
    },
    programs::{KProbe, PerfEvent, PerfEventScope, SamplePolicy, TracePoint},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use gecko_profile::{ProfileBuilder, ThreadBuilder};
use itertools::Itertools;
use object::{Object, ObjectSection, SectionKind};
use proc_maps::MapRange;
use serde_json::to_writer;
use std::cmp;
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    env,
    ffi::CStr,
    fs::{self, File},
    io::BufWriter,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    select, signal,
    sync::{mpsc, watch},
    task::{self, JoinHandle},
};
use uuid::Uuid;

use aya_test_bpf_common::{LogEvent, Sample};

mod gecko_profile;
mod proc_maps;

struct Thread {
    tid: i32,
    pid: Option<i32>,
    name: Option<String>,
    samples: Vec<Sample2>,
}

struct Sample2 {
    timestamp: u64,
    cpu_delta: u64,
    stack_id: i64,
    on_cpu: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(iface) => iface,
        None => panic!("not path provided"),
    };

    let data = fs::read(path)?;
    let mut bpf = Bpf::load(&data, None)?;
    for program in bpf.programs() {
        println!(
            "found program `{}` of type `{:?}`",
            program.name(),
            program.prog_type()
        );
    }

    let start_time = Instant::now();
    let start_timestamp_ns = get_timestamp_ns();

    let tp: &mut TracePoint = bpf.program_mut("sched_switch")?.try_into()?;
    tp.load()?;
    tp.attach("sched", "sched_switch")?;

    let kprobe: &mut KProbe = bpf.program_mut("finish_task_switch")?.try_into()?;
    kprobe.load()?;
    match kprobe.attach("finish_task_switch", 0) {
        Ok(_) => (),
        Err(_) => {
            kprobe.attach("finish_task_switch.isra.0", 0)?;
        }
    }

    let perf_event: &mut PerfEvent = bpf.program_mut("cpu_clock")?.try_into()?;
    perf_event.load()?;

    const SAMPLE_PERIOD: u64 = 1000000;

    for cpu_id in online_cpus()? {
        perf_event.attach(
            1, /* PERF_TYPE_SOFTWARE */
            0, /* PERF_COUNT_SW_CPU_CLOCK */
            PerfEventScope::AllProcessesOneCpu { cpu: cpu_id },
            SamplePolicy::Period(SAMPLE_PERIOD),
        )?;
    }

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("SAMPLES")?)?;
    let mut log_perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    let stacks = StackTraceMap::try_from(bpf.map_mut("STACKS")?)?;

    let (tx_pids, mut rx_pids) = mpsc::channel(32);
    let (termination_signal_sender, rx) = watch::channel(false);

    let mut rx_proc_maps_termination = rx.clone();

    let get_proc_maps = task::spawn(async move {
        let mut proc_maps_by_pid = HashMap::new();
        loop {
            select! {
                _termination_message = rx_proc_maps_termination.changed() => {
                    // Terminated.
                    break;
                }
                pid = rx_pids.recv() => {
                    if let Some(pid) = pid {
                        if proc_maps_by_pid.contains_key(&pid) {
                            continue;
                        }

                        let maps = match proc_maps::get_process_maps(pid as proc_maps::Pid) {
                            Ok(maps) => maps,
                            Err(_) => continue,
                        };
                        proc_maps_by_pid.insert(pid, maps);
                    }
                }
            }
        }
        proc_maps_by_pid
    });

    let mut join_handles = Vec::new();

    for cpu_id in online_cpus()? {
        // TODO: would more than 2 pages in the perf array buffer be better?
        let mut buf = perf_array.open(cpu_id, Some(2))?;
        let mut rx = rx.clone();
        let tx_pids = tx_pids.clone();
        let task: JoinHandle<Result<_, anyhow::Error>> = task::spawn(async move {
            const SAMPLE_SIZE: usize = 60;
            const BUFFER_COUNT: usize = 10;
            let mut buffers = Vec::with_capacity(BUFFER_COUNT);
            let mut current_buffer = BytesMut::with_capacity(SAMPLE_SIZE * BUFFER_COUNT);
            for _ in 0..BUFFER_COUNT {
                let rest = current_buffer.split_off(SAMPLE_SIZE);
                buffers.push(current_buffer);
                current_buffer = rest;
            }

            let mut seen_pids = HashSet::new();

            let mut thread_samples = std::collections::HashMap::new();

            loop {
                select! {
                    _termination_message = rx.changed() => {
                        // Terminated.
                        break;
                    }
                    events = buf.read_events(&mut buffers) => {
                        let events = events?;
                        for buf in buffers.iter_mut().take(events.read) {
                            let data = unsafe { (buf.as_ptr() as *const Sample).read_unaligned() };
                            let mut thread_entry = thread_samples.entry(data.tid).or_insert_with(|| {
                                Thread {
                                    tid: data.tid,
                                    pid: None,
                                    name: None,
                                    samples: Vec::new(),
                                }
                            });

                            if thread_entry.pid.is_none() && data.pid != 0 {
                                thread_entry.pid = Some(data.pid);

                                if !seen_pids.contains(&data.pid) {
                                    tx_pids.send(data.pid).await?;
                                    seen_pids.insert(data.pid);
                                }
                            }

                            if thread_entry.name.is_none() {
                                let name: Vec<u8> = data.thread_name.iter().map(|s| *s as u8).collect();
                                if let Ok(name) = CStr::from_bytes_with_nul(&name) {
                                    if let Ok(name) = name.to_str() {
                                        thread_entry.name = Some(name.to_string());
                                    }
                                }
                            }

                            if data.is_on_cpu != 0 {
                                thread_entry.samples.push(Sample2{
                                    timestamp: data.timestamp,
                                    cpu_delta: data.cpu_delta,
                                    stack_id: data.stack_id,
                                    on_cpu: true,
                                });
                                // println!(
                                //     "{} | SAMPLE {:?} [{}]: ACTIVE with {}us CPU delta, stack {}",
                                //     data.timestamp,
                                //     thread_entry.name,
                                //     data.tid,
                                //     data.cpu_delta / 1000,
                                //     data.stack_id,
                                // );
                            } else {
                                let count = data.off_cpu_sample_count as u64;
                                let first_timestamp = data.timestamp - (count - 1) * SAMPLE_PERIOD;
                                thread_entry.samples.push(Sample2{
                                    timestamp: first_timestamp,
                                    cpu_delta: data.cpu_delta,
                                    stack_id: data.stack_id,
                                    on_cpu: false,
                                });
                                for i in 1..count {
                                    thread_entry.samples.push(Sample2{
                                        timestamp: first_timestamp + i * SAMPLE_PERIOD,
                                        cpu_delta: 0,
                                        stack_id: data.stack_id,
                                        on_cpu: false,
                                    });
                                }
                                // println!(
                                //     "{} | SAMPLE {:?} [{}]: INACTIVE with {}us CPU delta, stack {}",
                                //     data.timestamp,
                                //     thread_entry.name,
                                //     data.tid,
                                //     data.cpu_delta / 1000,
                                //     data.stack_id,
                                // );
                            }
                        }
                    }
                }
            }
            Ok(thread_samples)
        });
        join_handles.push(task);
    }

    for cpu_id in online_cpus()? {
        let mut buf = log_perf_array.open(cpu_id, Some(2))?;
        let mut rx = rx.clone();
        let _: JoinHandle<Result<_, PerfBufferError>> = task::spawn(async move {
            const SAMPLE_SIZE: usize = 20;
            const BUFFER_COUNT: usize = 10;
            let mut buffers = Vec::with_capacity(BUFFER_COUNT);
            let mut current_buffer = BytesMut::with_capacity(SAMPLE_SIZE * BUFFER_COUNT);
            for _ in 0..BUFFER_COUNT {
                let rest = current_buffer.split_off(SAMPLE_SIZE);
                buffers.push(current_buffer);
                current_buffer = rest;
            }

            loop {
                select! {
                    _termination_message = rx.changed() => {
                        // Terminated.
                        break;
                    }
                    events = buf.read_events(&mut buffers) => {
                        let events = events?;
                        for buf in buffers.iter_mut().take(events.read) {
                            let ptr = buf.as_ptr() as *const LogEvent;
                            let data = unsafe { ptr.read_unaligned() };
                            eprintln!("Log: 0x{:x} 0x{:x}", data.tag, data.field);
                        }
                    }
                }
            }
            Ok(())
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");
    eprintln!("ctrl c has arrived");
    drop(bpf);
    eprintln!("bpf is dropped");
    termination_signal_sender.send(true)?;
    eprintln!("termination signal has been sent");
    let proc_maps_by_pid = get_proc_maps.await?;
    let results = futures::future::join_all(join_handles).await;
    let thread_vecs: Vec<Vec<_>> = results
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(Result::ok)
        .map(|map| map.into_values().collect())
        .collect();
    let threads = merge_threads(thread_vecs);
    save_to_profile(
        start_time,
        start_timestamp_ns,
        threads,
        &stacks,
        proc_maps_by_pid,
    );
    // eprintln!("results: {:?}", results);
    Ok::<_, anyhow::Error>(())
}

fn merge_threads(thread_vecs: Vec<Vec<Thread>>) -> Vec<Thread> {
    let mut thread_map = HashMap::new();
    for thread_vec in thread_vecs {
        for thread in thread_vec {
            match thread_map.get_mut(&thread.tid) {
                Some(merged_thread) => merge_thread_into(thread, merged_thread),
                None => {
                    thread_map.insert(thread.tid, thread);
                }
            }
        }
    }
    thread_map
        .into_values()
        .map(|mut thread| {
            thread.samples.sort_by_key(|s| s.timestamp);
            thread
        })
        .collect()
}

fn merge_thread_into(mut thread: Thread, merged_thread: &mut Thread) {
    match (thread.pid, merged_thread.pid) {
        (Some(pid), None) => {
            merged_thread.pid = Some(pid);
        }
        (Some(pid1), Some(pid2)) if pid1 != pid2 => {
            eprintln!(
                "conflicting pids for tid {}: {} != {}",
                thread.tid, pid1, pid2
            );
        }
        _ => {}
    }
    match (thread.name, &merged_thread.name) {
        (Some(name), None) => {
            merged_thread.name = Some(name);
        }
        (Some(name1), Some(name2)) if &name1 != name2 => {
            eprintln!(
                "conflicting names for tid {}: {} != {}",
                thread.tid, name1, name2
            );
        }
        _ => {}
    }
    merged_thread.samples.append(&mut thread.samples);
}

fn save_to_profile(
    start_time: Instant,
    start_timestamp_ns: u64,
    threads: Vec<Thread>,
    stacks: &StackTraceMap<MapRefMut>,
    proc_maps_by_pid: HashMap<i32, Vec<MapRange>>,
) {
    let mut root_profile_builder =
        ProfileBuilder::new(start_time, "System", 0, Duration::from_millis(1));
    let (threads_without_pid, threads_with_pid): (Vec<_>, Vec<_>) =
        threads.into_iter().partition(|t| t.pid.is_none());
    let threads_by_pid = threads_with_pid
        .into_iter()
        .into_group_map_by(|t| t.pid.unwrap());

    add_threads_to_profile(
        &mut root_profile_builder,
        &start_time,
        start_timestamp_ns,
        threads_without_pid,
        stacks,
    );

    for (pid, threads) in threads_by_pid {
        let mut process_profile_builder = ProfileBuilder::new(
            start_time,
            "Other process",
            pid as u32,
            Duration::from_millis(1),
        );
        if let Some(map_ranges) = proc_maps_by_pid.get(&pid) {
            add_shared_libraries_to_profile(&mut process_profile_builder, map_ranges);
        }
        add_threads_to_profile(
            &mut process_profile_builder,
            &start_time,
            start_timestamp_ns,
            threads,
            stacks,
        );
        root_profile_builder.add_subprocess(process_profile_builder);
    }

    let file = File::create("profile.json").unwrap();
    let writer = BufWriter::new(file);
    to_writer(writer, &root_profile_builder.to_json()).expect("Couldn't write JSON");
}

fn add_threads_to_profile(
    profile_builder: &mut ProfileBuilder,
    _process_start_time: &Instant,
    process_start_timestamp_ns: u64,
    threads: Vec<Thread>,
    stacks: &StackTraceMap<MapRefMut>,
) {
    for thread in threads {
        profile_builder.add_thread(make_profile_thread(
            thread,
            stacks,
            process_start_timestamp_ns,
        ));
    }
}

fn get_timestamp_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut time) };
    (time.tv_sec * 1_000_000_000 + time.tv_nsec) as u64
}

fn make_profile_thread(
    thread: Thread,
    stacks: &StackTraceMap<MapRefMut>,
    start_timestamp_ns: u64,
) -> ThreadBuilder {
    let mut thread_builder = ThreadBuilder::new(
        thread.pid.unwrap_or(0) as u32,
        thread.tid as u32,
        0.0,
        thread.pid == Some(thread.tid),
        false,
    );

    if let Some(name) = thread.name {
        thread_builder.set_name(&name);
    }

    let mut stack_map = HashMap::new();

    for sample in thread.samples {
        let timestamp_rel_ms = (sample.timestamp - start_timestamp_ns) as f64 / 1_000_000.0;
        let cpu_delta_us = (sample.cpu_delta + 500) / 1_000;
        match stack_map.get(&sample.stack_id) {
            Some(stack_index) => {
                thread_builder.add_sample_same_stack(timestamp_rel_ms, *stack_index, cpu_delta_us);
            }
            None => {
                let trace = stacks.get(&(sample.stack_id as u32), 0);
                let frames: Vec<u64> = match trace {
                    Ok(trace) => trace.frames().iter().rev().map(|frame| frame.ip).collect(),
                    Err(_) => [].into(),
                };
                let stack_index =
                    thread_builder.add_sample(timestamp_rel_ms, &frames, cpu_delta_us);
                stack_map.insert(sample.stack_id, stack_index);
            }
        }
    }

    thread_builder
}

fn add_shared_libraries_to_profile(profile_builder: &mut ProfileBuilder, map_ranges: &[MapRange]) {
    let mut exec_ranges_by_path: HashMap<String, Range<u64>> = HashMap::new();
    for range in map_ranges {
        if !range.is_exec() {
            continue;
        }
        let path = match range.filename() {
            Some(path) => path,
            _ => continue,
        };
        let address_range = (range.start()) as u64..(range.start() + range.size()) as u64;
        // if path.contains("libxul") {
        //     eprintln!("adding range {:x}-{:x} with {:?}", address_range.start, address_range.end, range.is_exec());
        // }
        match exec_ranges_by_path.get_mut(path) {
            Some(rg) => {
                rg.start = rg.start.min(address_range.start);
                rg.end = rg.end.min(address_range.end);
            }
            None => {
                exec_ranges_by_path.insert(path.to_string(), address_range);
            }
        }
    }
    for range in map_ranges {
        let path = match range.filename() {
            Some(path) => path,
            _ => continue,
        };
        // if path.contains("libxul") {
        //     eprintln!("adding range {:x}-{:x} with {:?}", address_range.start, address_range.end, range.is_exec());
        // }
        if let Some(rg) = exec_ranges_by_path.get_mut(path) {
            rg.start = rg.start.min(range.start() as u64);
        }
    }

    // eprintln!("ranges_by_path: {:#?}", ranges_by_path);

    for (path, address_range) in exec_ranges_by_path {
        if path.contains("libxul") {
            eprintln!(
                "{:x}-{:x} exec? {:?}",
                address_range.start, address_range.end, path
            );
        }
        let p = Path::new(&path);
        if let Ok(file) = File::open(p) {
            if let Ok(mmap) = unsafe { memmap2::MmapOptions::new().map(&file) } {
                if let Ok(f) = object::File::parse(&mmap[..]) {
                    if let Some(uuid) = get_elf_id(&f) {
                        let name = p.file_name().unwrap().to_str().unwrap();
                        if path.contains("libxul") {
                            eprintln!("got to adding");
                        }
                        profile_builder.add_lib(name, &path, &uuid, "", &address_range);
                    }
                }
            }
        }
    }
}

const UUID_SIZE: usize = 16;
const PAGE_SIZE: usize = 4096;

fn create_elf_id(identifier: &[u8], little_endian: bool) -> Uuid {
    // Make sure that we have exactly UUID_SIZE bytes available
    let mut data = [0u8; UUID_SIZE];
    let len = cmp::min(identifier.len(), UUID_SIZE);
    data[0..len].copy_from_slice(&identifier[0..len]);

    if little_endian {
        // The file ELF file targets a little endian architecture. Convert to
        // network byte order (big endian) to match the Breakpad processor's
        // expectations. For big endian object files, this is not needed.
        data[0..4].reverse(); // uuid field 1
        data[4..6].reverse(); // uuid field 2
        data[6..8].reverse(); // uuid field 3
    }

    Uuid::from_bytes(data)
}
/// Tries to obtain the object identifier of an ELF object.
///
/// As opposed to Mach-O, ELF does not specify a unique ID for object files in
/// its header. Compilers and linkers usually add either `SHT_NOTE` sections or
/// `PT_NOTE` program header elements for this purpose. If one of these notes
/// is present, ElfFile's build_id() method will find it.
///
/// If neither of the above are present, this function will hash the first page
/// of the `.text` section (program code). This matches what the Breakpad
/// processor does.
///
/// If all of the above fails, this function will return `None`.
pub fn get_elf_id<'data: 'file, 'file>(elf_file: &'file impl Object<'data, 'file>) -> Option<Uuid> {
    if let Some(identifier) = elf_file.build_id().ok()? {
        return Some(create_elf_id(identifier, elf_file.is_little_endian()));
    }

    // We were not able to locate the build ID, so fall back to hashing the
    // first page of the ".text" (program code) section. This algorithm XORs
    // 16-byte chunks directly into a UUID buffer.
    if let Some(section_data) = find_text_section(elf_file) {
        let mut hash = [0; UUID_SIZE];
        for i in 0..cmp::min(section_data.len(), PAGE_SIZE) {
            hash[i % UUID_SIZE] ^= section_data[i];
        }

        return Some(create_elf_id(&hash, elf_file.is_little_endian()));
    }

    None
}

/// Returns a reference to the data of the the .text section in an ELF binary.
fn find_text_section<'data: 'file, 'file>(
    file: &'file impl Object<'data, 'file>,
) -> Option<&'data [u8]> {
    file.sections()
        .find(|header| header.kind() == SectionKind::Text)
        .and_then(|header| header.data().ok())
}
