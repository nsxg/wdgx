// src/plugins/netbios.rs
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio::net::UdpSocket;
use log::{debug, info, error};
use crate::common::utils;

#[derive(Debug, Clone)]
pub struct NetBIOSInfo {
    pub ip: IpAddr,
    pub hostname: String,
    pub domain: Option<String>,
    pub mac_address: Option<String>,
    pub details: Option<String>,
}

pub async fn scan(
    targets: &[IpAddr],
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<NetBIOSInfo>, Box<dyn std::error::Error>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting NetBIOS scanning for {} targets...", targets.len());
    
    let pb = utils::create_progress_bar(targets.len() as u64, "NetBIOS scanning");
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
            for &ip in &chunk {
                if let Some(info) = query_netbios(ip, timeout_duration).await {
                    let _ = tx.send(info).await;
                }
                pb.inc(1);
            }
        });
    }
    
    // 丢弃原始发送者
    drop(tx);
    
    // 收集结果
    let mut results = Vec::new();
    while let Some(info) = rx.recv().await {
        results.push(info);
    }
    
    pb.finish_with_message(format!("Found {} NetBIOS information", results.len()));
    
    Ok(results)
}

async fn query_netbios(ip: IpAddr, timeout_duration: Duration) -> Option<NetBIOSInfo> {
    // 创建NetBIOS Name Service查询
    let query_packet = create_netbios_name_query();
    
    // 创建UDP socket
    let local_addr = if ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    
    let socket = match UdpSocket::bind(local_addr).await {
        Ok(socket) => socket,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return None;
        }
    };
    
    // 发送查询
    let target_addr = format!("{}:137", ip);
    if let Err(e) = socket.send_to(&query_packet, &target_addr).await {
        error!("Failed to send NetBIOS query to {}: {}", ip, e);
        return None;
    }
    
    // 读取响应
    let mut buf = [0u8; 1024];
    let recv_result = timeout(
        timeout_duration,
        socket.recv_from(&mut buf)
    ).await;
    
    match recv_result {
        Ok(Ok((size, _))) => {
            if size > 0 {
                match parse_netbios_response(&buf[..size], ip) {
                    Some(info) => Some(info),
                    None => None,
                }
            } else {
                None
            }
        },
        _ => None,
    }
}

fn create_netbios_name_query() -> Vec<u8> {
    // NetBIOS Name Service查询包
    // Transaction ID: 随机值
    let transaction_id = rand::random::<u16>();
    
    // 构建查询包
    let mut packet = Vec::new();
    
    // 事务ID (2 bytes)
    packet.push((transaction_id >> 8) as u8);
    packet.push(transaction_id as u8);
    
    // 标志 (2 bytes) - 标准查询
    packet.push(0x00);
    packet.push(0x00);
    
    // 问题数 (2 bytes) - 1个问题
    packet.push(0x00);
    packet.push(0x01);
    
    // 回答数, 权威回答数, 附加回答数 (每个2 bytes) - 全部为0
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);
    
    // 查询名称 - '*' (通配符) NETBIOS查询
    // 32个代码点，每个由2个字节组成
    // 首先是长度字节
    packet.push(32);
    
    // 编码 '*' (0x2A) 为 NETBIOS 格式
    for _ in 0..16 {
        packet.push(0x20); // 'A'
        packet.push(0x41); // 'A'
    }
    
    // 名称类型 (0x00)
    packet.push(0x00);
    
    // 查询类型 (2 bytes) - 0x0021 (NBSTAT)
    packet.push(0x00);
    packet.push(0x21);
    
    // 查询类 (2 bytes) - 0x0001 (IN)
    packet.push(0x00);
    packet.push(0x01);
    
    packet
}

fn parse_netbios_response(response: &[u8], ip: IpAddr) -> Option<NetBIOSInfo> {
    // 解析NetBIOS响应
    // 最小响应长度检查
    if response.len() < 12 {
        return None;
    }
    
    // 检查响应标志
    let flags = ((response[2] as u16) << 8) | (response[3] as u16);
    if (flags & 0x8000) == 0 {
        // 不是响应消息
        return None;
    }
    
    // 解析主机名和域名信息
    let mut hostname = String::new();
    let mut domain = None;
    let mut mac_address = None;
    
    // 查找主机名
    // NetBIOS名称开始于偏移量57
    if response.len() > 57 {
        let name_count = response[56] as usize;
        let mut offset = 57;
        
        for _ in 0..name_count {
            if offset + 18 > response.len() {
                break;
            }
            
            // 获取NetBIOS名称
            let mut name = String::new();
            for i in 0..15 {
                let c = response[offset + i];
                if c != 0x20 && c != 0x00 {
                    name.push(c as char);
                }
            }
            
            // 获取NetBIOS类型
            let name_type = response[offset + 15];
            
            // 主机名
            if name_type == 0x00 {
                hostname = name.trim().to_string();
            }
            // 域名
            else if name_type == 0x1C {
                domain = Some(name.trim().to_string());
            }
            
            offset += 18;
        }
        
        // 获取MAC地址
        if offset + 6 <= response.len() {
            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
                response[offset + 4],
                response[offset + 5]
            );
            mac_address = Some(mac);
        }
    }
    
    if !hostname.is_empty() || domain.is_some() || mac_address.is_some() {
        let mut details = String::new();
        
        if !hostname.is_empty() {
            details.push_str(&format!("Hostname: {}\n", hostname));
        }
        
        if let Some(dom) = &domain {
            details.push_str(&format!("Domain: {}\n", dom));
        }
        
        if let Some(mac) = &mac_address {
            details.push_str(&format!("MAC: {}", mac));
        }
        
        Some(NetBIOSInfo {
            ip,
            hostname,
            domain,
            mac_address,
            details: Some(details),
        })
    } else {
        None
    }
}
