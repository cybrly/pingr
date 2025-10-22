use clap::{Parser, ValueEnum};
use colored::*;
use dns_lookup::lookup_addr;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use ipnet::Ipv4Net;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Fast parallel ICMP ping scanner", long_about = None)]
struct Args {
    /// Network to scan in CIDR notation
    #[clap(default_value = "192.168.1.0/24")]
    cidr: String,

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
}

struct ScanResult {
    alive_hosts: Vec<HostInfo>,
    dead_hosts: Vec<Ipv4Addr>,
    scan_duration: Duration,
    total_scanned: usize,
    avg_rtt: Option<Duration>,
    min_rtt: Option<Duration>,
    max_rtt: Option<Duration>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    // Parse the CIDR
    let net: Ipv4Net = match Ipv4Net::from_str(&args.cidr) {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "{} {}",
                "✗ Error:".red().bold(),
                format!("Invalid CIDR '{}': {}", args.cidr, e).red()
            );
            std::process::exit(1);
        }
    };

    let hosts_iterator = net.hosts();
    let host_count = hosts_iterator.count();

    if host_count == 0 {
        eprintln!(
            "{} {}",
            "⚠".yellow(),
            format!("No hosts to scan in {}", args.cidr).yellow()
        );
        return Ok(());
    }

    // Determine concurrency
    let concurrency = determine_concurrency(&args.concurrency, host_count)?;

    if !args.quiet {
        print_banner(&args.cidr, host_count, concurrency, &args);
    }

    let start_time = Instant::now();

    // Set up rate limiting
    let rate_limiter = if args.rate_limit > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(1)))
    } else {
        None
    };

    let semaphore = Arc::new(Semaphore::new(concurrency));

    // Progress bars
    let multi_progress = MultiProgress::new();
    let pb = if !args.quiet {
        let pb = multi_progress.add(ProgressBar::new(host_count as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );
        Some(pb)
    } else {
        None
    };

    // Statistics tracking
    let success_count = Arc::new(AtomicUsize::new(0));
    let fail_count = Arc::new(AtomicUsize::new(0));

    // We need to re-create the iterator since .count() consumed it
    let hosts = net.hosts();

    // Create ping client with custom config
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

    let mut tasks = Vec::new();
    let timeout_duration = Duration::from_secs(args.timeout);

    // Generate and spawn tasks for all hosts
    for host in hosts {
        let client = client.clone();
        let sem = semaphore.clone();
        let pb_clone = pb.clone();
        let success = success_count.clone();
        let fail = fail_count.clone();
        let rate_limiter = rate_limiter.clone();
        let ping_count = args.ping_count;
        let resolve = args.resolve;
        let timeout = timeout_duration;

        let task = tokio::spawn(async move {
            // Rate limiting
            if let Some(limiter) = rate_limiter {
                let _permit = limiter.acquire().await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            let _permit = sem.acquire().await.unwrap();

            let mut successful_pings = 0;
            let mut total_rtt = Duration::ZERO;
            let mut min_rtt = Duration::MAX;
            let mut max_rtt = Duration::ZERO;

            // Multiple ping attempts
            for attempt in 0..ping_count {
                if let Some(rtt) = ping_host_with_rtt(client.clone(), host, timeout, attempt).await
                {
                    successful_pings += 1;
                    total_rtt += rtt;
                    min_rtt = min_rtt.min(rtt);
                    max_rtt = max_rtt.max(rtt);
                }
            }

            let result = if successful_pings > 0 {
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
                        "{} {} ({}ms)",
                        "Found:".green().bold(),
                        host.to_string().green(),
                        avg_rtt.as_millis()
                    ));
                }

                Some(HostInfo {
                    ip: host,
                    hostname,
                    rtt: Some(avg_rtt),
                    attempts: successful_pings,
                })
            } else {
                fail.fetch_add(1, Ordering::Relaxed);
                None
            };

            if let Some(pb) = pb_clone {
                pb.inc(1);
            }

            (host, result)
        });

        tasks.push(task);
    }

    // Collect results
    let mut alive_hosts = Vec::new();
    let mut dead_hosts = Vec::new();
    let mut all_rtts = Vec::new();

    for task in tasks {
        let (host, info) = task.await?;
        if let Some(host_info) = info {
            if let Some(rtt) = host_info.rtt {
                all_rtts.push(rtt);
            }
            alive_hosts.push(host_info);
        } else if args.verbose {
            dead_hosts.push(host);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    let scan_duration = start_time.elapsed();

    // Sort results
    alive_hosts.sort_by_key(|h| h.ip);
    dead_hosts.sort();

    // Calculate statistics
    let (avg_rtt, min_rtt, max_rtt) = if !all_rtts.is_empty() {
        let sum: Duration = all_rtts.iter().sum();
        let avg = sum / all_rtts.len() as u32;
        let min = *all_rtts.iter().min().unwrap();
        let max = *all_rtts.iter().max().unwrap();
        (Some(avg), Some(min), Some(max))
    } else {
        (None, None, None)
    };

    let result = ScanResult {
        alive_hosts: alive_hosts.clone(),
        dead_hosts: dead_hosts.clone(),
        scan_duration,
        total_scanned: host_count,
        avg_rtt,
        min_rtt,
        max_rtt,
    };

    // Display results
    if !args.quiet {
        display_results(&result, &args);
    } else {
        for host in &result.alive_hosts {
            if let Some(hostname) = &host.hostname {
                println!("{} ({})", host.ip, hostname);
            } else {
                println!("{}", host.ip);
            }
        }
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        save_results(&result, &output_path, &args.format)?;
    }

    // Export in special formats
    if let Some(export_format) = &args.export_format {
        export_results(&result, export_format)?;
    }

    Ok(())
}

fn determine_concurrency(
    concurrency_str: &str,
    host_count: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    if concurrency_str == "auto" {
        // Automatic optimization based on network size
        let optimal = match host_count {
            0..=256 => host_count.min(256), // /24 or smaller
            257..=1024 => 512,              // /22 to /20
            1025..=4096 => 1024,            // /20 to /18
            4097..=16384 => 2048,           // /18 to /16
            16385..=65536 => 4096,          // /16 to /14
            _ => 8192,                      // Larger networks
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
    let payload = vec![0; 56]; // Standard ping payload size
    let mut pinger = client.pinger(IpAddr::V4(host), PingIdentifier(1)).await;
    pinger.timeout(timeout);

    let start = Instant::now();
    match pinger.ping(PingSequence(sequence as u16), &payload).await {
        Ok(_) => Some(start.elapsed()),
        Err(_) => None,
    }
}

fn print_banner(cidr: &str, host_count: usize, concurrency: usize, args: &Args) {
    println!(
        "\n{}",
        "═══════════════════════════════════════════════════════"
            .blue()
            .bold()
    );
    println!(
        "{}",
        "           PINGSWEEP - Network Scanner v0.2.0           "
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
        "\n{} {}",
        "📡 Target Network:".white().bold(),
        cidr.yellow()
    );
    println!(
        "{} {}",
        "🔢 Hosts to scan:".white().bold(),
        host_count.to_string().yellow()
    );
    println!(
        "{} {}",
        "⚡ Concurrency:".white().bold(),
        format!("{} threads", concurrency).yellow()
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

    println!("{}", "─".repeat(56).blue());
}

fn display_results(result: &ScanResult, args: &Args) {
    println!(
        "\n{}",
        "═══════════════════════════════════════════════════════"
            .green()
            .bold()
    );
    println!(
        "{}",
        format!(
            "    ✅ SCAN COMPLETE - Found {} Live Hosts    ",
            result.alive_hosts.len()
        )
        .green()
        .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════"
            .green()
            .bold()
    );

    if !result.alive_hosts.is_empty() {
        println!("\n{}", "🟢 Live Hosts:".green().bold());
        println!("{}", "─".repeat(56).green());

        for (i, host) in result.alive_hosts.iter().enumerate() {
            let prefix = if i == result.alive_hosts.len() - 1 {
                "└─"
            } else {
                "├─"
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

            println!("  {} {}", prefix.green(), info.white().bold());
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

    let success_rate =
        (result.alive_hosts.len() as f32 / result.total_scanned as f32 * 100.0) as u32;

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

    let scan_rate = result.total_scanned as f32 / result.scan_duration.as_secs_f32();
    println!(
        "  {} {}",
        "Scan Rate:".white(),
        format!("{:.0} hosts/sec", scan_rate).cyan()
    );

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

            writeln!(file, "# Pingsweep Scan Results")?;
            writeln!(
                file,
                "# Generated: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            )?;
            writeln!(
                file,
                "# Scan Duration: {:.2}s",
                result.scan_duration.as_secs_f32()
            )?;
            writeln!(file, "# Total Hosts: {}", result.total_scanned)?;
            writeln!(file, "# Alive Hosts: {}", result.alive_hosts.len())?;
            writeln!(file, "#")?;

            for host in &result.alive_hosts {
                let mut line = host.ip.to_string();
                if let Some(hostname) = &host.hostname {
                    line = format!("{}\t{}", line, hostname);
                }
                if let Some(rtt) = host.rtt {
                    line = format!("{}\t{}ms", line, rtt.as_millis());
                }
                writeln!(file, "{}", line)?;
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
                        "rtt_ms": h.rtt.map(|r| r.as_millis()),
                        "successful_pings": h.attempts,
                    })
                })
                .collect();

            let json_data = json!({
                "scan_info": {
                    "timestamp": chrono::Local::now().to_rfc3339(),
                    "duration_seconds": result.scan_duration.as_secs_f32(),
                    "total_hosts": result.total_scanned,
                    "alive_count": result.alive_hosts.len(),
                    "dead_count": result.dead_hosts.len(),
                    "success_rate": (result.alive_hosts.len() as f32 / result.total_scanned as f32 * 100.0) as u32,
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
            let mut file = File::create("pingsweep_export.csv")?;
            writeln!(file, "IP,Hostname,RTT_ms,Status")?;

            for host in &result.alive_hosts {
                writeln!(
                    file,
                    "{},{},{},alive",
                    host.ip,
                    host.hostname.as_ref().unwrap_or(&String::from("")),
                    host.rtt.map(|r| r.as_millis()).unwrap_or(0)
                )?;
            }

            for host in &result.dead_hosts {
                writeln!(file, "{},,,dead", host)?;
            }

            println!(
                "{} {}",
                "📊 Exported CSV to:".green(),
                "pingsweep_export.csv".white().bold()
            );
        }
        "nmap" => {
            let mut file = File::create("pingsweep_export.gnmap")?;
            writeln!(
                file,
                "# Nmap 7.94 scan initiated {} as: pingsweep {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M"),
                result
                    .alive_hosts
                    .first()
                    .map(|h| h.ip.to_string())
                    .unwrap_or_default()
            )?;

            for host in &result.alive_hosts {
                writeln!(file, "Host: {} () Status: Up", host.ip)?;
            }

            println!(
                "{} {}",
                "🗺️  Exported nmap format to:".green(),
                "pingsweep_export.gnmap".white().bold()
            );
        }
        _ => {
            eprintln!("{} Unknown export format: {}", "⚠".yellow(), format);
        }
    }

    Ok(())
}
