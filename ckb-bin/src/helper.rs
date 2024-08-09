use ckb_logger::debug;

use std::io::{stdin, stdout, Write};


use chrono::prelude::Local;
use pprof::ProfilerGuardBuilder;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

#[cfg(not(feature = "deadlock_detection"))]
pub fn deadlock_detection() {}

#[cfg(feature = "deadlock_detection")]
pub fn deadlock_detection() {
    use ckb_channel::select;
    use ckb_logger::{info, warn};
    use ckb_stop_handler::{new_crossbeam_exit_rx, register_thread};
    use ckb_util::parking_lot::deadlock;
    use std::{thread, time::Duration};

    info!("deadlock_detection enabled");
    let dead_lock_jh = thread::spawn({
        let ticker = ckb_channel::tick(Duration::from_secs(10));
        let stop_rx = new_crossbeam_exit_rx();
        move || loop {
            select! {
                recv(ticker) -> _ => {
                    let deadlocks = deadlock::check_deadlock();
                    if deadlocks.is_empty() {
                        continue;
                    }

                    warn!("{} deadlocks detected", deadlocks.len());
                    for (i, threads) in deadlocks.iter().enumerate() {
                        warn!("Deadlock #{}", i);
                        for t in threads {
                            warn!("Thread Id {:#?}", t.thread_id());
                            warn!("{:#?}", t.backtrace());
                        }
                    }

                },
                recv(stop_rx) -> _ =>{
                    info!("deadlock_detection received exit signal, stopped");
                    return;
                }
            }
        }
    });
    register_thread("dead_lock_detect", dead_lock_jh);
}

pub fn prompt(msg: &str) -> String {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();

    write!(stdout, "{msg}").unwrap();
    stdout.flush().unwrap();

    let mut input = String::new();
    let _ = stdin.read_line(&mut input);

    input
}

/// Raise the soft open file descriptor resource limit to the hard resource
/// limit.
///
/// # Panics
///
/// Panics if [`libc::getrlimit`], [`libc::setrlimit`], [`libc::sysctl`], [`libc::getrlimit`] or [`libc::setrlimit`]
/// fail.
///
/// darwin_fd_limit exists to work around an issue where launchctl on Mac OS X
/// defaults the rlimit maxfiles to 256/unlimited. The default soft limit of 256
/// ends up being far too low for our multithreaded scheduler testing, depending
/// on the number of cores available.
pub fn raise_fd_limit() {
    if let Some(limit) = fdlimit::raise_fd_limit() {
        debug!("raise_fd_limit newly-increased limit: {}", limit);
    }
}

pub fn generate_perf_data() {
    loop {
        let file = NamedTempFile::new().expect("Failed to create tempfile");

        {
            let guard = ProfilerGuardBuilder::default().frequency(1000).blocklist(&["libc", "libgcc", "pthread", "vdso"]).build().unwrap();

            thread::sleep(Duration::from_secs(5));

            if let Ok(report) = guard.report().build() {
                let mut _file = file.reopen().expect("Failed to reopen tempfile");
                report.flamegraph(_file).unwrap();

            }

        }

        let now = Local::now();
        let timestamp = now.format("%Y-%m-%d_%H-%M-%S").to_string();

        let output_file_name = format!("perf_{}.svg", timestamp);

        std::fs::rename(file.path(), &output_file_name).expect("Failed to rename tempfile");

    }
}