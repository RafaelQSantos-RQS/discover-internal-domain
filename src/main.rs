mod checkpoint;
mod cli;
mod dnsengine;
mod generator;
mod negcache;
mod resolver;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;

use dnsengine::{DnsEngine, ResolverPool};
use generator::{Generator, JobSource, WordlistGenerator};

/// Number of lookup attempts per query before giving up.
const ATTEMPTS: usize = 2;

/// EMA smoothing factor for the adaptive worker latency.
const EMA_ALPHA: f64 = 0.2;

/// Latency thresholds (microseconds) for the adaptive worker controller.
const LATENCY_FAST_US: u64 = 50_000;
const LATENCY_SLOW_US: u64 = 200_000;

#[tokio::main]
async fn main() {
    let mut args = cli::Args::parse();
    if let Err(e) = args.validate() {
        eprintln!("Error: {e}");
        eprintln!("Use --help for usage information");
        std::process::exit(1);
    }

    // Load checkpoint (resume position + wildcard IPs). Wordlist mode uses
    // max_len 0 in the checkpoint (no length dimension).
    let expected_max_len = if args.wordlist.is_some() {
        0
    } else {
        args.maxlen
    };
    let checkpoint_data = match &args.checkpoint {
        Some(path) => match checkpoint::load(Path::new(path), &args.domain, expected_max_len) {
            Ok(cp) => {
                eprintln!(
                    "Resuming from checkpoint: {} combinations completed",
                    cp.completed
                );
                Some(cp)
            }
            Err(e) => {
                eprintln!("Warning: failed to load checkpoint: {e}");
                None
            }
        },
        None => None,
    };

    // Build the raw UDP DNS engine with the resolver pool.
    let pool = match &args.resolvers {
        Some(path) => match dnsengine::load_resolvers_file(path) {
            Ok(r) => ResolverPool::new(r),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
        None => ResolverPool::new(dnsengine::load_system_resolvers()),
    };
    if pool.is_empty() {
        eprintln!("Error: no DNS resolvers available (use -r to provide a list)");
        std::process::exit(1);
    }
    let engine = DnsEngine::new(pool, args.timeout, ATTEMPTS);

    // Wildcard detection: restore from checkpoint or probe N random subdomains.
    let mut wildcard_ips: Vec<String> = Vec::new();
    if args.wildcard {
        if let Some(cp) = &checkpoint_data {
            if !cp.wildcard_ips.is_empty() {
                wildcard_ips = cp.wildcard_ips.clone();
                eprintln!("Restored wildcard IPs: {}", wildcard_ips.join(", "));
            }
        }
        if wildcard_ips.is_empty() {
            wildcard_ips = resolver::detect_wildcards(&engine, &args.domain).await;
            if wildcard_ips.is_empty() {
                eprintln!("No wildcard detected");
            } else {
                eprintln!("Wildcard detected: {}", wildcard_ips.join(", "));
            }
        }
    }
    let wildcard = Arc::new(resolver::WildcardDetector::new(wildcard_ips.clone()));
    if args.wildcard && wildcard.has_wildcard() {
        eprintln!("Wildcard filtering enabled");
    }

    // Job source: exhaustive brute-force or wordlist, resuming from the
    // checkpoint position.
    let job_source = match &checkpoint_data {
        Some(cp) => match &args.wordlist {
            Some(path) => WordlistGenerator::resume(
                path,
                args.max_combinations,
                cp.last_index.first().copied().unwrap_or(0),
                cp.completed,
            )
            .map(JobSource::Wordlist),
            None => Ok(JobSource::Brute(Generator::resume(
                args.maxlen,
                args.max_combinations,
                cp.last_index.clone(),
                cp.length,
                cp.completed,
            ))),
        },
        None => match &args.wordlist {
            Some(path) => {
                WordlistGenerator::new(path, args.max_combinations).map(JobSource::Wordlist)
            }
            None => Ok(JobSource::Brute(Generator::new(
                args.maxlen,
                args.min_len,
                args.max_combinations,
            ))),
        },
    };
    let gen = Arc::new(Mutex::new(match job_source {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }));

    // Output writer: file if --out, otherwise stdout. Owned by the writer task.
    let writer: Box<dyn Write + Send> = match &args.out {
        Some(path) => match std::fs::File::create(path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("Error: cannot open output file {path}: {e}");
                std::process::exit(1);
            }
        },
        None => Box::new(std::io::stdout()),
    };

    // Bounded job channel (producer -> workers) and unbounded result channel
    // (workers -> writer task).
    let (tx, rx) = async_channel::bounded(args.buffer);
    let rx = Arc::new(rx);
    let (result_tx, result_rx) = async_channel::unbounded::<String>();

    // Writer task: owns the output, drains result lines from the channel.
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Ok(line) = result_rx.recv().await {
            let _ = writer.write_all(line.as_bytes());
        }
        let _ = writer.flush();
    });

    // Shared counters and negative cache.
    let initial_completed = checkpoint_data.as_ref().map(|cp| cp.completed).unwrap_or(0);
    let completed_counter = Arc::new(AtomicU64::new(initial_completed));
    let found_counter = Arc::new(AtomicU64::new(0));
    let neg_cache = Arc::new(negcache::NegCache::new(args.cache_ttl));

    // --include-root: resolve and report the root domain itself (not subject
    // to wildcard filtering; it is the explicit target).
    if args.include_root {
        if let Some(res) = resolver::lookup(&engine, &args.domain).await {
            found_counter.fetch_add(1, Ordering::Relaxed);
            let line = match &res.cname {
                Some(cname) => {
                    format!("{} -> {cname} -> {}\n", args.domain, res.ips.join(", "))
                }
                None => format!("{} -> {}\n", args.domain, res.ips.join(", ")),
            };
            let _ = result_tx.send(line).await;
        }
    }

    // Adaptive worker state.
    let target_workers = Arc::new(AtomicUsize::new(args.workers));
    let active_workers = Arc::new(AtomicUsize::new(0));
    let latency_ema = Arc::new(AtomicU64::new(0));

    // Cancellation signal (Ctrl+C / SIGTERM / normal completion).
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Signal handler.
    let sig_tx = cancel_tx.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
        }
        let _ = sig_tx.send(true);
    });

    // Checkpoint saver: periodic (10s) + final save on cancel.
    let checkpoint_task = match &args.checkpoint {
        Some(path) => {
            let path = path.clone();
            let gen = gen.clone();
            let domain = args.domain.clone();
            let max_len = if args.wordlist.is_some() {
                0
            } else {
                args.maxlen
            };
            let wips = wildcard_ips.clone();
            let mut cancel_rx = cancel_rx.clone();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            save_checkpoint(&path, &gen, &domain, max_len, &wips);
                        }
                        _ = cancel_rx.changed() => {
                            save_checkpoint(&path, &gen, &domain, max_len, &wips);
                            break;
                        }
                    }
                }
            }))
        }
        None => None,
    };

    // Negative cache cleanup task (periodic).
    let cleanup_task = {
        let neg_cache = neg_cache.clone();
        let mut cancel_rx = cancel_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => neg_cache.cleanup(),
                    _ = cancel_rx.changed() => break,
                }
            }
        })
    };

    // Adaptive worker controller: adjusts the target worker count from the
    // EMA of query latency (fast -> ramp up, slow -> ramp down).
    let controller = {
        let target_workers = target_workers.clone();
        let latency_ema = latency_ema.clone();
        let max_workers = args.workers;
        let mut cancel_rx = cancel_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let ema_us = latency_ema.load(Ordering::Relaxed);
                        let target = if ema_us == 0 || ema_us < LATENCY_FAST_US {
                            max_workers
                        } else if ema_us > LATENCY_SLOW_US {
                            let cur = target_workers.load(Ordering::Relaxed);
                            (cur * 3 / 4).max(1)
                        } else {
                            target_workers.load(Ordering::Relaxed)
                        };
                        target_workers.store(target, Ordering::Relaxed);
                    }
                    _ = cancel_rx.changed() => break,
                }
            }
        })
    };

    // Producer task: generate combinations into the channel.
    let producer = {
        let gen = gen.clone();
        let cancel_rx = cancel_rx.clone();
        let completed_counter = completed_counter.clone();
        tokio::spawn(async move {
            loop {
                if *cancel_rx.borrow() {
                    break;
                }
                let comb = {
                    let mut gen = gen.lock().unwrap();
                    match gen.next() {
                        Some(c) => c,
                        None => break,
                    }
                };
                if tx.send(comb).await.is_err() {
                    break;
                }
                completed_counter.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // Worker tasks: consume jobs, perform raw UDP lookups, respect the
    // adaptive worker target, and stream results to the writer task.
    let start = Instant::now();

    // Live progress: rewrite a single stderr line every second.
    let total_jobs = gen.lock().unwrap().total();
    let progress = {
        let completed_counter = completed_counter.clone();
        let found_counter = found_counter.clone();
        let mut cancel_rx = cancel_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let elapsed = start.elapsed();
                        let checked = completed_counter.load(Ordering::Relaxed);
                        let found = found_counter.load(Ordering::Relaxed);
                        let qps = if elapsed.as_secs_f64() > 0.0 {
                            checked as f64 / elapsed.as_secs_f64()
                        } else {
                            0.0
                        };
                        let pct = if total_jobs > 0 {
                            checked as f64 / total_jobs as f64 * 100.0
                        } else {
                            0.0
                        };
                        eprint!(
                            "\r[{:?}] {checked}/{total_jobs} ({pct:.0}%) {qps:.0} qps | found: {found}",
                            elapsed
                        );
                    }
                    _ = cancel_rx.changed() => break,
                }
            }
        })
    };
    let mut workers = Vec::new();
    for _ in 0..args.workers {
        let rx = rx.clone();
        let engine = engine.clone();
        let wildcard = wildcard.clone();
        let neg_cache = neg_cache.clone();
        let result_tx = result_tx.clone();
        let domain = args.domain.clone();
        let found_counter = found_counter.clone();
        let target_workers = target_workers.clone();
        let active_workers = active_workers.clone();
        let latency_ema = latency_ema.clone();
        workers.push(tokio::spawn(async move {
            loop {
                // Adaptive gate: wait while at/over the target worker count.
                while active_workers.load(Ordering::Relaxed)
                    >= target_workers.load(Ordering::Relaxed)
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let comb = match rx.recv().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                active_workers.fetch_add(1, Ordering::Relaxed);
                let query_start = Instant::now();
                let fqdn = format!("{comb}.{domain}");
                if !neg_cache.is_cached(&fqdn) {
                    if let Some(res) = resolver::lookup(&engine, &fqdn).await {
                        if !wildcard.is_wildcard_response(&res.ips) {
                            found_counter.fetch_add(1, Ordering::Relaxed);
                            let line = match &res.cname {
                                Some(cname) => {
                                    format!("{fqdn} -> {cname} -> {}\n", res.ips.join(", "))
                                }
                                None => format!("{fqdn} -> {}\n", res.ips.join(", ")),
                            };
                            let _ = result_tx.send(line).await;
                        }
                    } else {
                        neg_cache.add(fqdn);
                    }
                }
                update_ema(&latency_ema, query_start.elapsed().as_micros() as u64);
                active_workers.fetch_sub(1, Ordering::Relaxed);
            }
        }));
    }

    // Wait for the producer, then signal the final checkpoint save.
    let _ = producer.await;
    let _ = cancel_tx.send(true);

    // Wait for workers to drain, the writer to flush, and background tasks.
    for w in workers {
        let _ = w.await;
    }
    drop(result_tx);
    let _ = writer_task.await;
    if let Some(task) = checkpoint_task {
        let _ = task.await;
    }
    let _ = progress.await;
    let _ = controller.await;
    let _ = cleanup_task.await;
    eprintln!(); // break the live progress line

    // Summary.
    let elapsed = start.elapsed();
    let checked = completed_counter.load(Ordering::Relaxed);
    let qps = if elapsed.as_secs_f64() > 0.0 {
        checked as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    eprintln!("\n========================================");
    eprintln!("  DNS Enumeration Complete");
    eprintln!("========================================");
    eprintln!("  Total checked:  {}", checked);
    eprintln!(
        "  Found:          {}",
        found_counter.load(Ordering::Relaxed)
    );
    eprintln!("  Time:           {:?}", elapsed);
    eprintln!("  Rate:           {:.0} qps", qps);
    eprintln!("========================================");
}

/// Updates the exponential moving average of query latency (in microseconds).
fn update_ema(ema: &AtomicU64, sample_us: u64) {
    let current = ema.load(Ordering::Relaxed) as f64;
    let new = if current == 0.0 {
        sample_us as f64
    } else {
        EMA_ALPHA * sample_us as f64 + (1.0 - EMA_ALPHA) * current
    };
    ema.store(new as u64, Ordering::Relaxed);
}

/// Saves a checkpoint snapshot from the current generator state.
fn save_checkpoint(
    path: &str,
    gen: &Mutex<JobSource>,
    domain: &str,
    max_len: usize,
    wildcard_ips: &[String],
) {
    let (last_index, length, completed) = gen.lock().unwrap().state();
    let data = checkpoint::CheckpointData {
        completed,
        last_index,
        length,
        timestamp: chrono::Utc::now().to_rfc3339(),
        max_len,
        domain: domain.to_string(),
        wildcard_ips: wildcard_ips.to_vec(),
    };
    if let Err(e) = checkpoint::save(Path::new(path), &data) {
        eprintln!("Warning: failed to save checkpoint: {e}");
    }
}
