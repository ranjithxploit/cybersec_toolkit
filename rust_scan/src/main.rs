use clap::Parser;
use colored::*;
use dns_lookup::lookup_addr;
use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::task;
use x509_parser::prelude::parse_x509_certificate;

#[derive(Parser, Debug)]
#[command(name = "Network Scanner")]
#[command(about = "A fast network scanner similar to nmap, written in Rust", long_about = None)]
struct Args {
    #[arg(value_name = "HOST")]
    target: String,
    #[arg(short, long, default_value = "1-1000")]
    ports: String,
    #[arg(short, long, default_value = "100")]
    threads: usize,
    #[arg(short, long, default_value = "1")]
    timeout: u64,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long)]
    details: bool,
}

#[derive(Clone, Debug)]
struct TlsInfo {
    subject: Option<String>,
    issuer: Option<String>,
}

#[derive(Clone, Debug)]
struct PortDetail {
    port: u16,
    service: Option<&'static str>,
    latency_ms: Option<u128>,
    banner: Option<String>,
    tls: Option<TlsInfo>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!(
        "{}",
        format!("Network Scanner - Target: {}", args.target).bold().cyan()
    );
    let target_ip = match IpAddr::from_str(&args.target) {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!(
                "{}",
                format!("Invalid IP address: {}", args.target).red().bold()
            );
            std::process::exit(1);
        }
    };
    let ports = parse_ports(&args.ports);
    if ports.is_empty() {
        eprintln!("{}", "No valid ports specified".red().bold());
        std::process::exit(1);
    }

    if args.verbose {
        println!("{} Ports to scan: {}", "ℹ".cyan(), ports.len());
        println!("{} Threads: {}", "ℹ".cyan(), args.threads);
        println!("{} Timeout: {} seconds", "ℹ".cyan(), args.timeout);
    }

    if args.details {
        if let Ok(name) = lookup_addr(&target_ip) {
            println!("{} Reverse DNS: {}", "ℹ".cyan(), name);
        }
    }

    println!();
    let timeout = Duration::from_secs(args.timeout);
    let open_ports =
        scan_ports(target_ip, ports, args.threads, timeout, args.verbose, args.details).await;
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
            format!("Found {} open port(s):", open_ports.len())
                .green()
                .bold()
        );
        for detail in open_ports {
            println!(
                "  {}",
                format!("Port {}: OPEN", detail.port).green().bold()
            );
            if args.details {
                if let Some(service) = detail.service {
                    println!("    Service: {}", service);
                }
                if let Some(latency) = detail.latency_ms {
                    println!("    Latency: {} ms", latency);
                }
                if let Some(banner) = detail.banner {
                    println!("    Banner: {}", banner);
                }
                if let Some(tls) = detail.tls {
                    let tls_line = format_tls_info(&tls);
                    println!("    TLS: {}", tls_line);
                }
            }
        }
    }
    println!("{}", "─".repeat(60).cyan());
}

fn parse_ports(port_spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in port_spec.split(',') {
        let part = part.trim();
        if let Some(dash_pos) = part.find('-') {
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
    details: bool,
) -> Vec<PortDetail> {
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

                let start = Instant::now();
                match TcpStream::connect_timeout(&socket_addr, timeout) {
                    Ok(mut stream) => {
                        let latency_ms = start.elapsed().as_millis();
                        let service = guess_service(port);
                        let mut banner = None;
                        let mut tls = None;

                        if details {
                            if is_tls_port(port) {
                                if let Some((tls_info, tls_banner)) =
                                    try_tls_info(socket_addr, port, timeout)
                                {
                                    tls = Some(tls_info);
                                    banner = tls_banner;
                                }
                            } else {
                                banner = grab_banner_tcp(&mut stream, port, timeout);
                            }
                        }

                        open_ports.lock().unwrap().push(PortDetail {
                            port,
                            service,
                            latency_ms: if details { Some(latency_ms) } else { None },
                            banner,
                            tls,
                        });
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
    result.sort_by_key(|detail| detail.port);
    result
}

fn guess_service(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 => Some("https"),
        465 => Some("smtps"),
        587 => Some("smtp-submission"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgres"),
        6379 => Some("redis"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        _ => None,
    }
}

fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 465 | 587 | 636 | 993 | 995 | 8443)
}

fn grab_banner_tcp(stream: &mut TcpStream, port: u16, timeout: Duration) -> Option<String> {
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    if let Some(probe) = banner_probe(port, false) {
        let _ = stream.write_all(probe);
    }

    read_banner(stream)
}

fn try_tls_info(
    addr: SocketAddr,
    port: u16,
    timeout: Duration,
) -> Option<(TlsInfo, Option<String>)> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;

    let tcp = TcpStream::connect_timeout(&addr, timeout).ok()?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();

    let domain = addr.ip().to_string();
    let mut tls_stream = connector.connect(&domain, tcp).ok()?;

    let tls_info = tls_stream
        .peer_certificate()
        .ok()
        .and_then(|cert| cert.and_then(|c| parse_tls_info(&c.to_der().ok()?)))
        .unwrap_or(TlsInfo {
            subject: None,
            issuer: None,
        });

    if let Some(probe) = banner_probe(port, true) {
        let _ = tls_stream.write_all(probe);
    }

    let banner = read_banner(&mut tls_stream);
    Some((tls_info, banner))
}

fn parse_tls_info(der: &[u8]) -> Option<TlsInfo> {
    let (_, cert) = parse_x509_certificate(der).ok()?;
    let subject = Some(cert.subject().to_string());
    let issuer = Some(cert.issuer().to_string());
    Some(TlsInfo { subject, issuer })
}

fn format_tls_info(info: &TlsInfo) -> String {
    match (&info.subject, &info.issuer) {
        (Some(subject), Some(issuer)) => format!("cert subject: {}; issuer: {}", subject, issuer),
        (Some(subject), None) => format!("cert subject: {}", subject),
        (None, Some(issuer)) => format!("cert issuer: {}", issuer),
        (None, None) => "supported".to_string(),
    }
}

fn banner_probe(port: u16, tls: bool) -> Option<&'static [u8]> {
    match (port, tls) {
        (80 | 8080 | 8000 | 8008 | 8888, false) => Some(b"HEAD / HTTP/1.0\r\n\r\n"),
        (443 | 8443, true) => Some(b"HEAD / HTTP/1.0\r\n\r\n"),
        _ => None,
    }
}

fn read_banner<R: Read>(reader: &mut R) -> Option<String> {
    let mut buf = vec![0u8; 256];
    let size = reader.read(&mut buf).ok()?;
    if size == 0 {
        return None;
    }

    buf.truncate(size);
    let raw = String::from_utf8_lossy(&buf);
    let sanitized: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
        .collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.replace("\r\n", " ").replace('\n', " "))
    }
}
