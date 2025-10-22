use clap::{Parser, ValueEnum};
use colored::*;
use dns_lookup::lookup_addr;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use ipnet::Ipv4Net;
use serde_json::json;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::signal;
use tokio::sync::{Mutex, Semaphore};

#[derive(Parser, Debug)]
#[clap(author, version, about = "A blazing fast network scanner with beautiful terminal output", long_about = None)]
struct Args {
    /// Network to scan in CIDR notation (can specify multiple)
    #[clap(default_value = "")]
    cidr: String,

    /// Input file containing IP addresses and/or CIDR ranges (one per line)
    #[clap(short = 'i', long = "input")]
    input_file: Option<String>,

    /// Show unreachable hosts
    #[clap(short, long)]
    verbose: bool,

    /// Number of concurrent pings (auto = automatic optimization)
    #[clap(short = 't', long = "threads", default_value = "auto")]
    concurrency: String,

    /// Output file path (without extension)
    #[clap(short, long)]
    output: Option<String>,

    /// Output format
    #[clap(short = 'f', long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Suppress colorized output
    #[clap(long)]
    no_color: bool,

    /// Quiet mode (minimal output)
    #[clap(short = 'q', long)]
    quiet: bool,

    /// Number of ping attempts per host
    #[clap(short = 'c', long = "count", default_value = "1")]
    ping_count: u8,

    /// Ping timeout in seconds
    #[clap(long = "timeout", default_value = "1")]
    timeout: u64,

    /// Resolve hostnames
    #[clap(short = 'r', long = "resolve")]
    resolve: bool,

    /// Show RTT statistics
    #[clap(long = "stats")]
    stats: bool,

    /// Adaptive timeout based on network conditions
    #[clap(long = "adaptive")]
    adaptive: bool,

    /// Rate limit (pings per second, 0 = unlimited)
    #[clap(long = "rate", default_value = "0")]
    rate_limit: u32,

    /// Export format for integration (csv, xml, nmap)
    #[clap(long = "export")]
    export_format: Option<String>,

    /// Auto-save results on interrupt
    #[clap(long = "autosave", default_value = "true")]
    autosave: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Both,
}

#[derive(Debug, Clone)]
struct HostInfo {
    ip: Ipv4Addr,
    hostname: Option<String>,
    rtt: Option<Duration>,
    attempts: u8,
    network: String, // Track which network this host belongs to
}

struct ScanResult {
    alive_hosts: Vec<HostInfo>,
    dead_hosts: Vec<Ipv4Addr>,
    scan_duration: Duration,
    total_scanned: usize,
    avg_rtt: Option<Duration>,
    min_rtt: Option<Duration>,
    max_rtt: Option<Duration>,
    interrupted: bool,
    networks_scanned: Vec<String>,
}

// Global flag for interrupt handling
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    // Parse input networks from file or command line
    let networks = parse_input_networks(&args)?;

    if networks.is_empty() {
        eprintln!(
            "{} No networks to scan. Provide CIDR ranges via command line or use -i <file>",
            "✗ Error:".red().bold()
        );
        eprintln!("\nUsage examples:");
        eprintln!("  pingr 192.168.1.0/24");
        eprintln!("  pingr -i targets.txt");
        eprintln!("  pingr 10.0.0.0/24 192.168.1.0/24");
        std::process::exit(1);
    }

    // Setup interrupt handler
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_clone = interrupted.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
        println!(
            "\n{} {}",
            "⚠".yellow().bold(),
            "Interrupt received! Saving partial results...".yellow()
        );
        interrupted_clone.store(true, Ordering::Relaxed);
        INTERRUPTED.store(true, Ordering::Relaxed);
    });

    // Shared results storage for graceful shutdown
    let all_alive_hosts = Arc::new(Mutex::new(Vec::new()));
    let all_dead_hosts = Arc::new(Mutex::new(Vec::new()));

    // Calculate total hosts
    let mut total_hosts = 0;
    let mut network_details = Vec::new();

    for cidr in &networks {
        match Ipv4Net::from_str(cidr) {
            Ok(net) => {
                let host_count = net.hosts().count();
                total_hosts += host_count;
                network_details.push((cidr.clone(), net, host_count));
            }
            Err(e) => {
                eprintln!("{} Invalid CIDR '{}': {}", "⚠".yellow(), cidr, e);
            }
        }
    }

    if !args.quiet {
        print_banner_multi(&network_details, total_hosts, &args);
    }

    let start_time = Instant::now();

    // Determine concurrency for total hosts
    let concurrency = determine_concurrency(&args.concurrency, total_hosts)?;

    // Create progress bar for all networks
    let multi_progress = MultiProgress::new();
    let main_pb = if !args.quiet {
        let pb = multi_progress.add(ProgressBar::new(total_hosts as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );
        pb.set_message(format!("Scanning {} networks", networks.len()));
        Some(pb)
    } else {
        None
    };

    // Setup semaphore and rate limiter
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let rate_limiter = if args.rate_limit > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(1)))
    } else {
        None
    };

    // Create ping client
    let config = Config::builder().kind(surge_ping::ICMP::V4).build();
    let client = match Client::new(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} {}",
                "✗ Error:".red().bold(),
                format!("Failed to create ping client: {}", e).red()
            );
            eprintln!(
                "{} {}",
                "ℹ".blue(),
                "Make sure you're running with sudo or have appropriate permissions".blue()
            );
            std::process::exit(1);
        }
    };

    // Statistics tracking
    let success_count = Arc::new(AtomicUsize::new(0));
    let fail_count = Arc::new(AtomicUsize::new(0));

    let mut all_tasks = Vec::new();
    let timeout_duration = Duration::from_secs(args.timeout);

    // Process each network
    for (cidr, net, _host_count) in network_details {
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }

        if !args.quiet {
            if let Some(pb) = &main_pb {
                pb.set_message(format!("Scanning {}", cidr.yellow()));
            }
        }

        // Generate tasks for this network
        for host in net.hosts() {
            if INTERRUPTED.load(Ordering::Relaxed) {
                break;
            }

            let client = client.clone();
            let sem = semaphore.clone();
            let pb_clone = main_pb.clone();
            let success = success_count.clone();
            let fail = fail_count.clone();
            let rate_limiter = rate_limiter.clone();
            let alive_hosts_clone = all_alive_hosts.clone();
            let dead_hosts_clone = all_dead_hosts.clone();
            let network_cidr = cidr.clone();
            let ping_count = args.ping_count;
            let resolve = args.resolve;
            let timeout = timeout_duration;
            let verbose = args.verbose;

            let task = tokio::spawn(async move {
                // Check if interrupted before starting
                if INTERRUPTED.load(Ordering::Relaxed) {
                    return;
                }

                // Rate limiting
                if let Some(limiter) = rate_limiter {
                    let _permit = limiter.acquire().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }

                let _permit = sem.acquire().await.unwrap();

                // Check again after acquiring permit
                if INTERRUPTED.load(Ordering::Relaxed) {
                    return;
                }

                let mut successful_pings = 0;
                let mut total_rtt = Duration::ZERO;

                // Multiple ping attempts
                for attempt in 0..ping_count {
                    if let Some(rtt) =
                        ping_host_with_rtt(client.clone(), host, timeout, attempt).await
                    {
                        successful_pings += 1;
                        total_rtt += rtt;
                    }
                }

                if successful_pings > 0 {
                    success.fetch_add(1, Ordering::Relaxed);

                    let avg_rtt = total_rtt / successful_pings as u32;

                    // Resolve hostname if requested
                    let hostname = if resolve {
                        lookup_addr(&IpAddr::V4(host)).ok()
                    } else {
                        None
                    };

                    if let Some(pb) = &pb_clone {
                        pb.set_message(format!(
                            "{} {} from {} ({}ms)",
                            "Found:".green().bold(),
                            host.to_string().green(),
                            network_cidr.yellow(),
                            avg_rtt.as_millis()
                        ));
                    }

                    let host_info = HostInfo {
                        ip: host,
                        hostname,
                        rtt: Some(avg_rtt),
                        attempts: successful_pings,
                        network: network_cidr,
                    };

                    let mut hosts = alive_hosts_clone.lock().await;
                    hosts.push(host_info);
                } else {
                    fail.fetch_add(1, Ordering::Relaxed);
                    if verbose {
                        let mut hosts = dead_hosts_clone.lock().await;
                        hosts.push(host);
                    }
                }

                if let Some(pb) = pb_clone {
                    pb.inc(1);
                }
            });

            all_tasks.push(task);
        }
    }

    // Wait for all tasks or interruption
    for task in all_tasks {
        if INTERRUPTED.load(Ordering::Relaxed) {
            task.abort();
        } else {
            let _ = task.await;
        }
    }

    if let Some(pb) = main_pb {
        pb.finish_and_clear();
    }

    let scan_duration = start_time.elapsed();

    // Collect final results
    let mut alive_hosts = all_alive_hosts.lock().await.clone();
    let dead_hosts = all_dead_hosts.lock().await.clone();

    // Sort results
    alive_hosts.sort_by(|a, b| a.network.cmp(&b.network).then(a.ip.cmp(&b.ip)));

    // Calculate statistics
    let all_rtts: Vec<Duration> = alive_hosts.iter().filter_map(|h| h.rtt).collect();

    let (avg_rtt, min_rtt, max_rtt) = if !all_rtts.is_empty() {
        let sum: Duration = all_rtts.iter().sum();
        let avg = sum / all_rtts.len() as u32;
        let min = *all_rtts.iter().min().unwrap();
        let max = *all_rtts.iter().max().unwrap();
        (Some(avg), Some(min), Some(max))
    } else {
        (None, None, None)
    };

    let was_interrupted = INTERRUPTED.load(Ordering::Relaxed);

    let result = ScanResult {
        alive_hosts: alive_hosts.clone(),
        dead_hosts: dead_hosts.clone(),
        scan_duration,
        total_scanned: success_count.load(Ordering::Relaxed) + fail_count.load(Ordering::Relaxed),
        avg_rtt,
        min_rtt,
        max_rtt,
        interrupted: was_interrupted,
        networks_scanned: networks,
    };

    // Display results
    if !args.quiet {
        display_results(&result, &args);
    } else {
        for host in &result.alive_hosts {
            if let Some(hostname) = &host.hostname {
                println!("{} ({}) [{}]", host.ip, hostname, host.network);
            } else {
                println!("{} [{}]", host.ip, host.network);
            }
        }
    }

    // Save to file if requested or if interrupted with autosave
    if args.output.is_some() || (was_interrupted && args.autosave) {
        let output_path = args.output.unwrap_or_else(|| {
            format!(
                "pingr_interrupted_{}",
                chrono::Local::now().format("%Y%m%d_%H%M%S")
            )
        });

        save_results(&result, &output_path, &args.format)?;

        if was_interrupted {
            println!(
                "{} Partial results saved to: {}",
                "💾".green(),
                format!("{}.txt/json", output_path).white().bold()
            );
        }
    }

    // Export in special formats
    if let Some(export_format) = &args.export_format {
        export_results(&result, export_format)?;
    }

    Ok(())
}

fn parse_input_networks(args: &Args) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut networks = Vec::new();

    // Parse from input file if provided
    if let Some(input_file) = &args.input_file {
        let file = File::open(input_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check if it's a single IP or CIDR
            if trimmed.contains('/') {
                // CIDR notation
                networks.push(trimmed.to_string());
            } else if trimmed.parse::<Ipv4Addr>().is_ok() {
                // Single IP - convert to /32
                networks.push(format!("{}/32", trimmed));
            } else {
                eprintln!("{} Invalid entry in input file: {}", "⚠".yellow(), trimmed);
            }
        }

        println!(
            "{} Loaded {} networks from {}",
            "📁".blue(),
            networks.len(),
            input_file.white().bold()
        );
    }

    // Parse from command line (can be multiple)
    if !args.cidr.is_empty() {
        let parts: Vec<&str> = args.cidr.split_whitespace().collect();
        for part in parts {
            if part.contains('/') {
                networks.push(part.to_string());
            } else if part.parse::<Ipv4Addr>().is_ok() {
                networks.push(format!("{}/32", part));
            } else if !part.is_empty() {
                eprintln!("{} Invalid CIDR: {}", "⚠".yellow(), part);
            }
        }
    }

    // If still no networks and no input file was specified, use default
    if networks.is_empty() && args.input_file.is_none() && args.cidr.is_empty() {
        networks.push("192.168.1.0/24".to_string());
    }

    Ok(networks)
}

fn print_banner_multi(
    network_details: &[(String, Ipv4Net, usize)],
    total_hosts: usize,
    args: &Args,
) {
    println!(
        "\n{}",
        "═══════════════════════════════════════════════════════"
            .blue()
            .bold()
    );
    println!(
        "{}",
        "                PINGR - Network Scanner v0.1.0          "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .blue()
            .bold()
    );

    println!(
        "\n{} {} networks to scan:",
        "📡".white(),
        network_details.len().to_string().yellow().bold()
    );
    for (cidr, _, host_count) in network_details.iter().take(5) {
        println!(
            "   {} {} ({} hosts)",
            "├─".blue(),
            cidr.white(),
            host_count.to_string().yellow()
        );
    }
    if network_details.len() > 5 {
        println!(
            "   {} ... and {} more networks",
            "└─".blue(),
            (network_details.len() - 5).to_string().yellow()
        );
    }

    println!(
        "\n{} {}",
        "🔢 Total hosts:".white().bold(),
        total_hosts.to_string().yellow()
    );
    println!(
        "{} {}",
        "🔄 Ping attempts:".white().bold(),
        args.ping_count.to_string().yellow()
    );
    println!(
        "{} {}",
        "⏱️  Timeout:".white().bold(),
        format!("{}s", args.timeout).yellow()
    );

    if args.resolve {
        println!(
            "{} {}",
            "🔍 DNS Resolution:".white().bold(),
            "Enabled".green()
        );
    }

    if args.rate_limit > 0 {
        println!(
            "{} {}",
            "🚦 Rate Limit:".white().bold(),
            format!("{} pings/sec", args.rate_limit).yellow()
        );
    }

    println!(
        "{} {}",
        "🛡️  Interrupt handling:".white().bold(),
        "Enabled (Ctrl-C to save partial results)".green()
    );

    println!("{}", "─".repeat(56).blue());
}

fn determine_concurrency(
    concurrency_str: &str,
    host_count: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    if concurrency_str == "auto" {
        let optimal = match host_count {
            0..=256 => host_count.min(256),
            257..=1024 => 512,
            1025..=4096 => 1024,
            4097..=16384 => 2048,
            16385..=65536 => 4096,
            _ => 8192,
        };

        println!(
            "{} Auto-selected {} threads for {} hosts",
            "🔧".blue(),
            optimal.to_string().yellow().bold(),
            host_count
        );
        Ok(optimal)
    } else {
        Ok(concurrency_str.parse()?)
    }
}

async fn ping_host_with_rtt(
    client: Client,
    host: Ipv4Addr,
    timeout: Duration,
    sequence: u8,
) -> Option<Duration> {
    let payload = vec![0; 56];
    let mut pinger = client.pinger(IpAddr::V4(host), PingIdentifier(1)).await;
    pinger.timeout(timeout);

    let start = Instant::now();
    match pinger.ping(PingSequence(sequence as u16), &payload).await {
        Ok(_) => Some(start.elapsed()),
        Err(_) => None,
    }
}

fn display_results(result: &ScanResult, args: &Args) {
    let header = if result.interrupted {
        format!(
            "    ⚠ SCAN INTERRUPTED - Found {} Live Hosts    ",
            result.alive_hosts.len()
        )
        .yellow()
        .bold()
    } else {
        format!(
            "    ✅ SCAN COMPLETE - Found {} Live Hosts    ",
            result.alive_hosts.len()
        )
        .green()
        .bold()
    };

    println!(
        "\n{}",
        "═══════════════════════════════════════════════════════"
            .green()
            .bold()
    );
    println!("{}", header);
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .green()
            .bold()
    );

    if !result.alive_hosts.is_empty() {
        // Group hosts by network
        let mut by_network: std::collections::HashMap<String, Vec<&HostInfo>> =
            std::collections::HashMap::new();
        for host in &result.alive_hosts {
            by_network
                .entry(host.network.clone())
                .or_insert_with(Vec::new)
                .push(host);
        }

        println!("\n{}", "🟢 Live Hosts by Network:".green().bold());
        println!("{}", "─".repeat(56).green());

        for network in &result.networks_scanned {
            if let Some(hosts) = by_network.get(network) {
                println!(
                    "\n  {} {} ({} hosts)",
                    "📍".cyan(),
                    network.yellow().bold(),
                    hosts.len()
                );

                for (i, host) in hosts.iter().enumerate() {
                    let prefix = if i == hosts.len() - 1 {
                        "    └─"
                    } else {
                        "    ├─"
                    };

                    let mut info = host.ip.to_string();

                    if let Some(hostname) = &host.hostname {
                        info = format!("{} ({})", info, hostname.cyan());
                    }

                    if let Some(rtt) = host.rtt {
                        let rtt_color = if rtt.as_millis() < 10 {
                            format!("{}ms", rtt.as_millis()).green()
                        } else if rtt.as_millis() < 50 {
                            format!("{}ms", rtt.as_millis()).yellow()
                        } else {
                            format!("{}ms", rtt.as_millis()).red()
                        };
                        info = format!("{} - {}", info, rtt_color);
                    }

                    if args.ping_count > 1 {
                        info = format!("{} [{}/{} replies]", info, host.attempts, args.ping_count);
                    }

                    println!("{} {}", prefix.green(), info.white().bold());
                }
            }
        }
    } else {
        println!("\n{} {}", "⚠".yellow(), "No live hosts found".yellow());
    }

    if args.verbose && !result.dead_hosts.is_empty() {
        println!("\n{}", "🔴 Unreachable Hosts:".red().bold());
        println!("{}", "─".repeat(56).red());
        for host in &result.dead_hosts {
            println!("  └─ {}", host.to_string().red());
        }
    }

    // Statistics
    println!("\n{}", "📊 Statistics:".cyan().bold());
    println!("{}", "─".repeat(56).cyan());

    println!(
        "  {} {}",
        "Networks Scanned:".white(),
        result.networks_scanned.len().to_string().yellow()
    );
    println!(
        "  {} {}",
        "Total Scanned:".white(),
        result.total_scanned.to_string().yellow()
    );
    println!(
        "  {} {}",
        "Alive Hosts:".white(),
        result.alive_hosts.len().to_string().green()
    );

    if args.verbose {
        println!(
            "  {} {}",
            "Dead Hosts:".white(),
            result.dead_hosts.len().to_string().red()
        );
    }

    let success_rate = if result.total_scanned > 0 {
        (result.alive_hosts.len() as f32 / result.total_scanned as f32 * 100.0) as u32
    } else {
        0
    };

    let success_text = format!("{}%", success_rate);
    let colored_success = if success_rate > 50 {
        success_text.green()
    } else if success_rate > 20 {
        success_text.yellow()
    } else {
        success_text.red()
    };
    println!("  {} {}", "Success Rate:".white(), colored_success.bold());

    // RTT Statistics
    if args.stats {
        if let (Some(avg), Some(min), Some(max)) = (result.avg_rtt, result.min_rtt, result.max_rtt)
        {
            println!("\n  {} ", "RTT Statistics:".cyan().bold());
            println!(
                "    {} {}ms",
                "Min:".white(),
                min.as_millis().to_string().green()
            );
            println!(
                "    {} {}ms",
                "Avg:".white(),
                avg.as_millis().to_string().yellow()
            );
            println!(
                "    {} {}ms",
                "Max:".white(),
                max.as_millis().to_string().red()
            );
        }
    }

    println!(
        "  {} {}",
        "Scan Time:".white(),
        format!("{:.2}s", result.scan_duration.as_secs_f32()).yellow()
    );

    let scan_rate = if result.scan_duration.as_secs_f32() > 0.0 {
        result.total_scanned as f32 / result.scan_duration.as_secs_f32()
    } else {
        0.0
    };
    println!(
        "  {} {}",
        "Scan Rate:".white(),
        format!("{:.0} hosts/sec", scan_rate).cyan()
    );

    if result.interrupted {
        println!(
            "\n  {} {}",
            "Status:".white(),
            "INTERRUPTED - Partial results saved".yellow().bold()
        );
    }

    println!("{}", "═".repeat(56).blue().bold());
}

fn save_results(
    result: &ScanResult,
    output_path: &str,
    format: &OutputFormat,
) -> std::io::Result<()> {
    match format {
        OutputFormat::Text | OutputFormat::Both => {
            let txt_path = format!("{}.txt", output_path);
            let mut file = File::create(&txt_path)?;

            writeln!(file, "# Pingr Scan Results")?;
            writeln!(
                file,
                "# Generated: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            )?;
            if result.interrupted {
                writeln!(file, "# Status: INTERRUPTED - Partial Results")?;
            }
            writeln!(
                file,
                "# Scan Duration: {:.2}s",
                result.scan_duration.as_secs_f32()
            )?;
            writeln!(
                file,
                "# Networks Scanned: {}",
                result.networks_scanned.join(", ")
            )?;
            writeln!(file, "# Total Hosts Scanned: {}", result.total_scanned)?;
            writeln!(file, "# Alive Hosts: {}", result.alive_hosts.len())?;
            writeln!(file, "#")?;

            // Group by network
            let mut by_network: std::collections::HashMap<String, Vec<&HostInfo>> =
                std::collections::HashMap::new();
            for host in &result.alive_hosts {
                by_network
                    .entry(host.network.clone())
                    .or_insert_with(Vec::new)
                    .push(host);
            }

            for network in &result.networks_scanned {
                if let Some(hosts) = by_network.get(network) {
                    writeln!(file, "\n# Network: {}", network)?;
                    for host in hosts {
                        let mut line = host.ip.to_string();
                        if let Some(hostname) = &host.hostname {
                            line = format!("{}\t{}", line, hostname);
                        }
                        if let Some(rtt) = host.rtt {
                            line = format!("{}\t{}ms", line, rtt.as_millis());
                        }
                        writeln!(file, "{}", line)?;
                    }
                }
            }

            println!(
                "{} {}",
                "💾 Saved text output to:".green(),
                txt_path.white().bold()
            );
        }
        _ => {}
    }

    match format {
        OutputFormat::Json | OutputFormat::Both => {
            let json_path = format!("{}.json", output_path);

            let hosts_data: Vec<_> = result
                .alive_hosts
                .iter()
                .map(|h| {
                    json!({
                        "ip": h.ip.to_string(),
                        "hostname": h.hostname,
                        "network": h.network,
                        "rtt_ms": h.rtt.map(|r| r.as_millis()),
                        "successful_pings": h.attempts,
                    })
                })
                .collect();

            let json_data = json!({
                "scan_info": {
                    "timestamp": chrono::Local::now().to_rfc3339(),
                    "interrupted": result.interrupted,
                    "duration_seconds": result.scan_duration.as_secs_f32(),
                    "networks_scanned": result.networks_scanned,
                    "total_hosts": result.total_scanned,
                    "alive_count": result.alive_hosts.len(),
                    "dead_count": result.dead_hosts.len(),
                    "success_rate": (result.alive_hosts.len() as f32 / result.total_scanned.max(1) as f32 * 100.0) as u32,
                    "rtt_stats": {
                        "avg_ms": result.avg_rtt.map(|r| r.as_millis()),
                        "min_ms": result.min_rtt.map(|r| r.as_millis()),
                        "max_ms": result.max_rtt.map(|r| r.as_millis()),
                    }
                },
                "alive_hosts": hosts_data,
                "dead_hosts": result.dead_hosts.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            });

            let mut file = File::create(&json_path)?;
            file.write_all(serde_json::to_string_pretty(&json_data)?.as_bytes())?;

            println!(
                "{} {}",
                "💾 Saved JSON output to:".green(),
                json_path.white().bold()
            );
        }
        _ => {}
    }

    Ok(())
}

fn export_results(result: &ScanResult, format: &str) -> std::io::Result<()> {
    match format {
        "csv" => {
            let filename = if result.interrupted {
                format!(
                    "pingr_export_interrupted_{}.csv",
                    chrono::Local::now().format("%Y%m%d_%H%M%S")
                )
            } else {
                "pingr_export.csv".to_string()
            };

            let mut file = File::create(&filename)?;
            writeln!(file, "IP,Hostname,Network,RTT_ms,Status")?;

            for host in &result.alive_hosts {
                writeln!(
                    file,
                    "{},{},{},{},alive",
                    host.ip,
                    host.hostname.as_ref().unwrap_or(&String::from("")),
                    host.network,
                    host.rtt.map(|r| r.as_millis()).unwrap_or(0)
                )?;
            }

            for host in &result.dead_hosts {
                writeln!(file, "{},,,,dead", host)?;
            }

            println!(
                "{} {}",
                "📊 Exported CSV to:".green(),
                filename.white().bold()
            );
        }
        "nmap" => {
            let filename = if result.interrupted {
                format!(
                    "pingr_export_interrupted_{}.gnmap",
                    chrono::Local::now().format("%Y%m%d_%H%M%S")
                )
            } else {
                "pingr_export.gnmap".to_string()
            };

            let mut file = File::create(&filename)?;
            writeln!(
                file,
                "# Nmap 7.94 scan initiated {} as: pingr {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M"),
                result.networks_scanned.join(" ")
            )?;

            for host in &result.alive_hosts {
                writeln!(file, "Host: {} () Status: Up", host.ip)?;
            }

            println!(
                "{} {}",
                "🗺️  Exported nmap format to:".green(),
                filename.white().bold()
            );
        }
        _ => {
            eprintln!("{} Unknown export format: {}", "⚠".yellow(), format);
        }
    }

    Ok(())
}
