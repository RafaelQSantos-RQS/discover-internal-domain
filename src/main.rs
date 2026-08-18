mod checkpoint;
mod cli;
mod generator;
mod negcache;
mod resolver;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;

#[tokio::main]
async fn main() {
    let mut args = cli::Args::parse();
    if let Err(e) = args.validate() {
        eprintln!("Error: {e}");
        eprintln!("Use --help for usage information");
        std::process::exit(1);
    }

    // Load checkpoint (resume position + wildcard IPs).
    let checkpoint_data = match &args.checkpoint {
        Some(path) => match checkpoint::load(Path::new(path), &args.domain, args.maxlen) {
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

    // Build the DNS resolver.
    let resolver = match resolver::build_resolver(args.timeout) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    // Wildcard detection: restore from checkpoint or probe a random subdomain.
    let mut wildcard_ips: Vec<String> = Vec::new();
    if args.wildcard {
        if let Some(cp) = &checkpoint_data {
            if !cp.wildcard_ips.is_empty() {
                wildcard_ips = cp.wildcard_ips.clone();
                eprintln!("Restored wildcard IPs: {}", wildcard_ips.join(", "));
            }
        }
        if wildcard_ips.is_empty() {
            wildcard_ips = resolver::detect_wildcards(&resolver, &args.domain, args.timeout).await;
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

    // Generator, resuming from the checkpoint position.
    let gen = Arc::new(Mutex::new(match &checkpoint_data {
        Some(cp) => generator::Generator::resume(
            args.maxlen,
            args.max_combinations,
            cp.last_index.clone(),
            cp.length,
            cp.completed,
        ),
        None => generator::Generator::new(args.maxlen, args.max_combinations),
    }));

    // Output writer: file if --out, otherwise stdout.
    let writer: Arc<Mutex<Box<dyn Write + Send>>> = match &args.out {
        Some(path) => match std::fs::File::create(path) {
            Ok(f) => Arc::new(Mutex::new(Box::new(f))),
            Err(e) => {
                eprintln!("Error: cannot open output file {path}: {e}");
                std::process::exit(1);
            }
        },
        None => Arc::new(Mutex::new(Box::new(std::io::stdout()))),
    };

    // Bounded job channel (producer -> workers).
    let (tx, rx) = async_channel::bounded(args.buffer);
    let rx = Arc::new(rx);

    // Shared counters and negative cache.
    let initial_completed = checkpoint_data.as_ref().map(|cp| cp.completed).unwrap_or(0);
    let completed_counter = Arc::new(AtomicU64::new(initial_completed));
    let found_counter = Arc::new(AtomicU64::new(0));
    let neg_cache = Arc::new(negcache::NegCache::new(args.cache_ttl));

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
            let max_len = args.maxlen;
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

    // Worker tasks: consume jobs and perform DNS lookups.
    let start = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..args.workers {
        let rx = rx.clone();
        let resolver = resolver.clone();
        let wildcard = wildcard.clone();
        let neg_cache = neg_cache.clone();
        let writer = writer.clone();
        let domain = args.domain.clone();
        let timeout = args.timeout;
        let found_counter = found_counter.clone();
        workers.push(tokio::spawn(async move {
            while let Ok(comb) = rx.recv().await {
                let fqdn = format!("{comb}.{domain}");
                if neg_cache.is_cached(&fqdn) {
                    continue;
                }
                match resolver::lookup(&resolver, &fqdn, timeout).await {
                    Some(ips) => {
                        if wildcard.is_wildcard_response(&ips) {
                            continue;
                        }
                        found_counter.fetch_add(1, Ordering::Relaxed);
                        let line = format!("{fqdn} -> {}\n", ips.join(", "));
                        let mut w = writer.lock().unwrap();
                        let _ = w.write_all(line.as_bytes());
                    }
                    None => {
                        neg_cache.add(fqdn);
                    }
                }
            }
        }));
    }

    // Wait for the producer, then signal the final checkpoint save.
    let _ = producer.await;
    let _ = cancel_tx.send(true);

    // Wait for workers to drain and the checkpoint saver to finish.
    for w in workers {
        let _ = w.await;
    }
    if let Some(task) = checkpoint_task {
        let _ = task.await;
    }
    let _ = cleanup_task.await;

    // Summary.
    let elapsed = start.elapsed();
    eprintln!("\n========================================");
    eprintln!("  DNS Enumeration Complete");
    eprintln!("========================================");
    eprintln!(
        "  Total checked:  {}",
        completed_counter.load(Ordering::Relaxed)
    );
    eprintln!(
        "  Found:          {}",
        found_counter.load(Ordering::Relaxed)
    );
    eprintln!("  Time:           {:?}", elapsed);
    eprintln!("========================================");
}

/// Saves a checkpoint snapshot from the current generator state.
fn save_checkpoint(
    path: &str,
    gen: &Mutex<generator::Generator>,
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
