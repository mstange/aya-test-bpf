use aya::{maps::perf::AsyncPerfEventArray, programs::TracePoint, util::online_cpus, Bpf};
use bytes::BytesMut;
use std::{
    convert::{TryFrom, TryInto},
    env, fs,
};
use tokio::{signal, task};

use aya_test_bpf_common::SwitchLog;

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

    let probe: &mut TracePoint = bpf.program_mut("sched_switch")?.try_into()?;
    probe.load()?;
    probe.attach("sched", "sched_switch")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(12))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SwitchLog;
                    let data = unsafe { ptr.read_unaligned() };
                    println!("SWITCH {} -> {}", data.prev_pid, data.next_pid);
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
