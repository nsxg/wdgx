use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio::process::Command;
use log::{debug, info};
use crate::common::utils;

pub async fn scan_alive(
    targets: &[IpAddr],
    skip_alive: bool,
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    // 如果跳过存活检测，直接返回所有目标
    if skip_alive {
        info!("Skipping host discovery, assuming all hosts are alive");
        return Ok(targets.to_vec());
    }
    
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting host discovery for {} targets...", targets.len());
    
    let pb = utils::create_progress_bar(targets.len() as u64, "Checking host alive");
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 分块处理
    let chunk_size = (targets.len() + threads - 1) / threads;
    let chunks: Vec<Vec<IpAddr>> = targets
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let timeout_duration = timeout_duration;
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for ip in chunk {
                if is_host_alive(ip, timeout_duration).await {
                    let _ = tx.send(ip).await;
                }
                pb.inc(1);
            }
        });
    }
    
    // 丢弃原始发送者，让接收通道能够正常结束
    drop(tx);
    
    // 收集结果
    let mut alive_hosts = Vec::new();
    while let Some(ip) = rx.recv().await {
        alive_hosts.push(ip);
    }
    
    pb.finish_with_message(format!("Found {} alive hosts", alive_hosts.len()));
    
    Ok(alive_hosts)
}

async fn is_host_alive(ip: IpAddr, timeout_duration: Duration) -> bool {
    // 尝试多种方法检测主机是否存活
    
    // 1. ICMP ping
    if ping_host(ip, timeout_duration).await {
        debug!("Host {} is alive (ICMP ping)", ip);
        return true;
    }
    
    // 2. TCP端口探测（测试常用端口）
    let common_ports = [80, 443, 22, 445, 3389];
    for port in common_ports {
        if check_tcp_port(ip, port, timeout_duration).await {
            debug!("Host {} is alive (TCP port {})", ip, port);
            return true;
        }
    }
    
    false
}

async fn ping_host(ip: IpAddr, timeout_duration: Duration) -> bool {
    let ping_result = match ip {
        IpAddr::V4(_) => {
            timeout(
                timeout_duration,
                Command::new("ping")
                    .arg("-c1")
                    .arg("-W1")
                    .arg(ip.to_string())
                    .output(),
            ).await
        },
        IpAddr::V6(_) => {
            timeout(
                timeout_duration,
                Command::new("ping6")
                    .arg("-c1")
                    .arg("-W1")
                    .arg(ip.to_string())
                    .output(),
            ).await
        }
    };
    
    match ping_result {
        Ok(Ok(output)) => output.status.success(),
        _ => false,
    }
}

async fn check_tcp_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
    let addr = format!("{}:{}", ip, port);
    match timeout(timeout_duration, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
