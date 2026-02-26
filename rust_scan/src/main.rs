use clap::Parser;
use colored::*;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;
use tokio::task;

#[derive(Parser, Debug)]
#[command(name = "Network Scanner")]
#[command(about = "A fast network scanner similar to nmap, written in Rust", long_about = None)]
struct Args {
    /// Target host or IP address to scan
    #[arg(value_name = "HOST")]
    target: String,

    /// Port range to scan (e.g., 80,443,1000-2000)
    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    /// Number of parallel threads
    #[arg(short, long, default_value = "100")]
    threads: usize,

    /// Timeout in seconds for each port connection attempt
    #[arg(short, long, default_value = "1")]
    timeout: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("{}", "═".repeat(60).cyan());
    println!(
        "{}",
        format!("🔍 Network Scanner - Target: {}", args.target).bold().cyan()
    );
    println!("{}", "═".repeat(60).cyan());

    // Parse target
    let target_ip = match IpAddr::from_str(&args.target) {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!(
                "{}",
                format!("✗ Invalid IP address: {}", args.target).red().bold()
            );
            std::process::exit(1);
        }
    };

    // Parse ports
    let ports = parse_ports(&args.ports);
    if ports.is_empty() {
        eprintln!("{}", "✗ No valid ports specified".red().bold());
        std::process::exit(1);
    }

    if args.verbose {
        println!("{} Ports to scan: {}", "ℹ".cyan(), ports.len());
        println!("{} Threads: {}", "ℹ".cyan(), args.threads);
        println!("{} Timeout: {} seconds", "ℹ".cyan(), args.timeout);
    }

    println!();

    // Scan ports
    let timeout = Duration::from_secs(args.timeout);
    let open_ports = scan_ports(target_ip, ports, args.threads, timeout, args.verbose).await;

    // Print results
    println!();
    println!("{}", "─".repeat(60).cyan());
    if open_ports.is_empty() {
        println!(
            "{}",
            "No open ports found.".yellow()
        );
    } else {
        println!(
            "{}",
            format!("✓ Found {} open port(s):", open_ports.len())
                .green()
                .bold()
        );
        for port in open_ports {
            println!("  {}", format!("Port {}: OPEN", port).green().bold());
        }
    }
    println!("{}", "─".repeat(60).cyan());
}

fn parse_ports(port_spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in port_spec.split(',') {
        let part = part.trim();
        if let Some(dash_pos) = part.find('-') {
            // Range (e.g., "1000-2000")
            if let (Ok(start), Ok(end)) = (
                part[..dash_pos].parse::<u16>(),
                part[dash_pos + 1..].parse::<u16>(),
            ) {
                for port in start..=end {
                    ports.push(port);
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }

    ports.sort();
    ports.dedup();
    ports
}

async fn scan_ports(
    target: IpAddr,
    ports: Vec<u16>,
    num_threads: usize,
    timeout: Duration,
    verbose: bool,
) -> Vec<u16> {
    let mut handles = vec![];
    let open_ports = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let ports_per_thread = (ports.len() + num_threads - 1) / num_threads;

    for chunk in ports.chunks(ports_per_thread) {
        let chunk = chunk.to_vec();
        let open_ports = open_ports.clone();

        let handle = task::spawn_blocking(move || {
            for port in chunk {
                let socket_addr = SocketAddr::new(target, port);

                if verbose {
                    print!(".");
                }

                match TcpStream::connect_timeout(&socket_addr, timeout) {
                    Ok(_) => {
                        open_ports.lock().unwrap().push(port);
                        if verbose {
                            print!("{}", "✓".green());
                        }
                    }
                    Err(_) => {
                        if verbose {
                            print!("{}", "✗".red());
                        }
                    }
                }
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let mut result = open_ports.lock().unwrap().clone();
    result.sort();
    result
}
