// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Independent checks run at the same time. Every guest boots on one
//! core of the host and the host has many, so a run of `test`, `ci` or
//! `os-test` gives its boots to a pool of threads. A job's output is kept
//! (out.rs) and printed whole when the jobs before it have printed theirs,
//! so the log reads in the same order whatever the pace. A failed job is
//! named in the summary; the jobs not yet started are dropped after the
//! first failure (the jobs started form a prefix of the list, so every
//! output has its turn).

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

/// A check that stands alone: it shares with the others only what the
/// builds of xtask guard (`once`, BUILD_LOCK).
pub struct Job {
    name: String,
    run: Box<dyn FnOnce() -> Result<(), String> + Send>,
}

impl Job {
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub fn job(name: &str, run: impl FnOnce() -> Result<(), String> + Send + 'static) -> Job {
    Job {
        name: name.to_owned(),
        run: Box::new(run),
    }
}

/// The default number of jobs at a time: half the cores of the host.
pub fn default_jobs() -> usize {
    std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1))
}

/// The number after `--jobs` in `args`, or the default; an error for any
/// other argument.
pub fn parse_jobs(command: &str, args: &[String]) -> Result<usize, String> {
    match args {
        [] => Ok(default_jobs()),
        [flag, n] if flag == "--jobs" => n
            .parse::<usize>()
            .ok()
            .filter(|&n| n >= 1)
            .ok_or_else(|| format!("{command} --jobs expects a number from 1")),
        _ => Err(format!("usage: cargo xtask {command} [--jobs N]")),
    }
}

struct Done {
    result: Result<(), String>,
    output: String,
    took: Duration,
}

/// Runs `jobs` with at most `limit` at a time. With one, they run in
/// their order on this thread with live output, and the first failure
/// stops the run. With more, each job's output comes whole in the order
/// of `jobs`, then a line of its end, and the error names the failed
/// jobs.
pub fn run_all(jobs: Vec<Job>, limit: usize) -> Result<(), String> {
    if limit <= 1 {
        for job in jobs {
            (job.run)().map_err(|e| format!("{}: {e}", job.name))?;
        }
        return Ok(());
    }
    let start = Instant::now();
    let names: Vec<String> = jobs.iter().map(|j| j.name.clone()).collect();
    let total = jobs.len();
    let queue: Mutex<VecDeque<(usize, Job)>> = Mutex::new(jobs.into_iter().enumerate().collect());
    let failed = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel::<(usize, Done)>();
    let mut results: Vec<Option<Done>> = (0..total).map(|_| None).collect();
    std::thread::scope(|scope| {
        for _ in 0..limit.min(total) {
            let tx = tx.clone();
            let (queue, failed) = (&queue, &failed);
            scope.spawn(move || {
                loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let next = queue
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pop_front();
                    let Some((index, job)) = next else { break };
                    let began = Instant::now();
                    // Order 0 is outside the jobs: the jobs count from 1.
                    let (result, output) = crate::out::capture(index + 1, || {
                        catch_unwind(AssertUnwindSafe(job.run))
                            .unwrap_or_else(|_| Err("panicked".to_owned()))
                    });
                    if result.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    let done = Done {
                        result,
                        output,
                        took: began.elapsed(),
                    };
                    if tx.send((index, done)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut next = 0;
        while let Ok((index, done)) = rx.recv() {
            results[index] = Some(done);
            while let Some(done) = results.get(next).and_then(Option::as_ref) {
                print!("{}", done.output);
                match &done.result {
                    Ok(()) => println!(
                        "== ok: {} ({:.1} s) [{}/{total}]",
                        names[next],
                        done.took.as_secs_f64(),
                        next + 1
                    ),
                    Err(e) => println!(
                        "== FAILED: {} ({:.1} s): {e}",
                        names[next],
                        done.took.as_secs_f64()
                    ),
                }
                next += 1;
            }
        }
    });
    let failures: Vec<String> = results
        .iter()
        .enumerate()
        .filter_map(|(i, done)| match done.as_ref()?.result.as_ref() {
            Err(why) => Some(format!(
                "{} ({})",
                names[i],
                why.lines().next().unwrap_or_default()
            )),
            Ok(()) => None,
        })
        .collect();
    let skipped = results.iter().filter(|done| done.is_none()).count();
    println!(
        "{} jobs, {limit} at a time, {:.0} s",
        total - skipped,
        start.elapsed().as_secs_f64()
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}{}",
            failures.len(),
            failures.join(", "),
            if skipped > 0 {
                format!("; {skipped} not run")
            } else {
                String::new()
            }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(name: &str) -> Job {
        job(name, || Ok(()))
    }

    #[test]
    fn jobs_in_a_pool_all_run() {
        let jobs = (0..9).map(|i| ok(&format!("j{i}"))).collect();
        assert_eq!(run_all(jobs, 4), Ok(()));
    }

    #[test]
    fn a_failure_is_named() {
        let jobs = vec![ok("a"), job("b", || Err("broken".to_owned()))];
        let e = run_all(jobs, 3).unwrap_err();
        assert!(e.contains("b"), "{e}");
    }

    /// A job that panics ends as `panicked` in the summary.
    #[test]
    fn a_panic_is_caught_and_named() {
        let jobs = vec![job("boom", || panic!("boom"))];
        let e = run_all(jobs, 2).unwrap_err();
        assert_eq!(e, "1 failed: boom (panicked)");
    }

    #[test]
    fn one_job_at_a_time_stops_at_the_first_failure() {
        let jobs = vec![job("a", || Err("x".to_owned())), job("b", || Ok(()))];
        assert_eq!(run_all(jobs, 1), Err("a: x".to_owned()));
    }

    #[test]
    fn jobs_flag() {
        assert_eq!(parse_jobs("ci", &["--jobs".into(), "3".into()]), Ok(3));
        assert!(parse_jobs("ci", &["--jobs".into(), "0".into()]).is_err());
        assert!(parse_jobs("ci", &["--bogus".into()]).is_err());
        assert!(parse_jobs("ci", &[]).unwrap() >= 1);
    }
}
