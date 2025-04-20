use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info};
use crate::common::utils;

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub ip: IpAddr,
    pub port: u16,
}

pub async fn scan_ports(
    targets: &[IpAddr],
    ports_str: &str,
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<PortScanResult>, Box<dyn std::error::Error>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    
    // 解析端口
    let ports = parse_ports(ports_str)?;
    if ports.is_empty() {
        return Err("No valid ports specified".into());
    }
    
    info!("Starting port scan for {} targets with {} ports...", targets.len(), ports.len());
    
    let total_scans = targets.len() * ports.len();
    let pb = utils::create_progress_bar(total_scans as u64, "Scanning ports");
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 创建目标端口组合
    let mut target_ports = Vec::new();
    for &ip in targets {
        for &port in &ports {
            target_ports.push((ip, port));
        }
    }
    
    // 分块处理
    let chunk_size = (target_ports.len() + threads - 1) / threads;
    let chunks: Vec<Vec<(IpAddr, u16)>> = target_ports
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let timeout_duration = timeout_duration;
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for (ip, port) in chunk {
                if check_port(ip, port, timeout_duration).await {
                    let _ = tx.send(PortScanResult { ip, port }).await;
                }
                pb.inc(1);
            }
        });
    }
    
    // 丢弃原始发送者
    drop(tx);
    
    // 收集结果
    let mut open_ports = Vec::new();
    while let Some(result) = rx.recv().await {
        open_ports.push(result);
    }
    
    pb.finish_with_message(format!("Found {} open ports", open_ports.len()));
    
    Ok(open_ports)
}

/// 从字符串解析端口列表
fn parse_ports(ports_str: &str) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let mut ports = Vec::new();
    
    for part in ports_str.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            // 端口范围 (e.g., 80-100)
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start = range[0].parse::<u16>()?;
                let end = range[1].parse::<u16>()?;
                
                if start <= end {
                    ports.extend(start..=end);
                }
            }
        } else {
            // 单个端口
            let port = part.parse::<u16>()?;
            ports.push(port);
        }
    }
    
    // 去重
    ports.sort();
    ports.dedup();
    
    Ok(ports)
}

async fn check_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
    let addr = format!("{}:{}", ip, port);
    let result = timeout(timeout_duration, TcpStream::connect(&addr)).await;
    
    match result {
        Ok(Ok(_)) => {
            debug!("Found open port {}:{}", ip, port);
            true
        },
        _ => false,
    }
}
