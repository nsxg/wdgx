// src/plugins/snmp.rs
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio::net::UdpSocket;
use log::{debug, info, error};
use crate::common::utils;

#[derive(Debug, Clone)]
pub struct SnmpInfo {
    pub ip: IpAddr,
    pub version: String,
    pub community: String,
    pub system_description: Option<String>,
    pub system_name: Option<String>,
    pub details: Option<String>,
}

pub async fn scan(
    targets: &[IpAddr],
    communities: &[String],
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<SnmpInfo>, Box<dyn std::error::Error>> {
    if targets.is_empty() || communities.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting SNMP scanning for {} targets with {} communities...", targets.len(), communities.len());
    
    // 计算总尝试次数
    let total_attempts = targets.len() * communities.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "SNMP scanning");
    
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 创建所有组合的任务
    let mut tasks = Vec::new();
    for &ip in targets {
        for community in communities {
            tasks.push((ip, community.clone()));
        }
    }
    
    // 分块处理
    let chunk_size = (tasks.len() + threads - 1) / threads;
    let chunks: Vec<Vec<(IpAddr, String)>> = tasks
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let timeout_duration = timeout_duration;
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for (ip, community) in chunk {
                // 尝试SNMP v1
                if let Some(info) = query_snmp_v1(ip, &community, timeout_duration).await {
                    let _ = tx.send(info).await;
                }
                // 尝试SNMP v2c
                else if let Some(info) = query_snmp_v2c(ip, &community, timeout_duration).await {
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
    
    pb.finish_with_message(format!("Found {} SNMP information", results.len()));
    
    Ok(results)
}

async fn query_snmp_v1(
    ip: IpAddr,
    community: &str,
    timeout_duration: Duration,
) -> Option<SnmpInfo> {
    // 创建SNMP GetRequest PDU
    let request_packet = create_snmp_get_request(community, "1.3.6.1.2.1.1.1.0", 0); // sysDescr.0
    
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return None;
        }
    };
    
    // 发送请求
    let target_addr = format!("{}:161", ip); // 标准SNMP端口
    if let Err(e) = socket.send_to(&request_packet, &target_addr).await {
        error!("Failed to send SNMP request to {}: {}", ip, e);
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
                // 解析SNMP响应
                if let Some(sys_descr) = parse_snmp_response(&buf[..size]) {
                    // 如果获取到系统描述，再尝试获取系统名称
                    if let Some(sys_name) = query_snmp_oid(ip, community, "1.3.6.1.2.1.1.5.0", timeout_duration).await {
                        let details = format!(
                            "SNMP v1 community: {}\nSystem Description: {}\nSystem Name: {}",
                            community, sys_descr, sys_name
                        );
                        
                        return Some(SnmpInfo {
                            ip,
                            version: "v1".to_string(),
                            community: community.to_string(),
                            system_description: Some(sys_descr),
                            system_name: Some(sys_name),
                            details: Some(details),
                        });
                    } else {
                        let details = format!(
                            "SNMP v1 community: {}\nSystem Description: {}",
                            community, sys_descr
                        );
                        
                        return Some(SnmpInfo {
                            ip,
                            version: "v1".to_string(),
                            community: community.to_string(),
                            system_description: Some(sys_descr),
                            system_name: None,
                            details: Some(details),
                        });
                    }
                }
            }
        },
        _ => {}
    }
    
    None
}

async fn query_snmp_v2c(
    ip: IpAddr,
    community: &str,
    timeout_duration: Duration,
) -> Option<SnmpInfo> {
    // 创建SNMP GetRequest PDU (v2c)
    let request_packet = create_snmp_get_request_v2c(community, "1.3.6.1.2.1.1.1.0"); // sysDescr.0
    
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return None;
        }
    };
    
    // 发送请求
    let target_addr = format!("{}:161", ip); // 标准SNMP端口
    if let Err(e) = socket.send_to(&request_packet, &target_addr).await {
        error!("Failed to send SNMP request to {}: {}", ip, e);
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
                // 解析SNMP响应
                if let Some(sys_descr) = parse_snmp_response_v2c(&buf[..size]) {
                    // 如果获取到系统描述，再尝试获取系统名称
                    if let Some(sys_name) = query_snmp_oid_v2c(ip, community, "1.3.6.1.2.1.1.5.0", timeout_duration).await {
                        let details = format!(
                            "SNMP v2c community: {}\nSystem Description: {}\nSystem Name: {}",
                            community, sys_descr, sys_name
                        );
                        
                        return Some(SnmpInfo {
                            ip,
                            version: "v2c".to_string(),
                            community: community.to_string(),
                            system_description: Some(sys_descr),
                            system_name: Some(sys_name),
                            details: Some(details),
                        });
                    } else {
                        let details = format!(
                            "SNMP v2c community: {}\nSystem Description: {}",
                            community, sys_descr
                        );
                        
                        return Some(SnmpInfo {
                            ip,
                            version: "v2c".to_string(),
                            community: community.to_string(),
                            system_description: Some(sys_descr),
                            system_name: None,
                            details: Some(details),
                        });
                    }
                }
            }
        },
        _ => {}
    }
    
    None
}

async fn query_snmp_oid(
    ip: IpAddr,
    community: &str,
    oid: &str,
    timeout_duration: Duration,
) -> Option<String> {
    // 创建SNMP GetRequest PDU
    let request_packet = create_snmp_get_request(community, oid, 1); // 请求ID递增
    
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(_) => return None,
    };
    
    // 发送请求
    let target_addr = format!("{}:161", ip);
    if let Err(_) = socket.send_to(&request_packet, &target_addr).await {
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
                // 解析SNMP响应
                parse_snmp_response(&buf[..size])
            } else {
                None
            }
        },
        _ => None,
    }
}

async fn query_snmp_oid_v2c(
    ip: IpAddr,
    community: &str,
    oid: &str,
    timeout_duration: Duration,
) -> Option<String> {
    // 创建SNMP GetRequest PDU (v2c)
    let request_packet = create_snmp_get_request_v2c(community, oid);
    
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(_) => return None,
    };
    
    // 发送请求
    let target_addr = format!("{}:161", ip);
    if let Err(_) = socket.send_to(&request_packet, &target_addr).await {
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
                // 解析SNMP响应
                parse_snmp_response_v2c(&buf[..size])
            } else {
                None
            }
        },
        _ => None,
    }
}

fn create_snmp_get_request(community: &str, oid: &str, request_id: u32) -> Vec<u8> {
    // 构建SNMPv1 GetRequest数据包
    let mut packet = Vec::new();
    
    // SEQUENCE
    packet.push(0x30);
    packet.push(0x00); // 长度，稍后填充
    
    // SNMP Version (v1 = 0)
    packet.push(0x02); // INTEGER
    packet.push(0x01); // Length
    packet.push(0x00); // Value (0 = SNMPv1)
    
    // Community String
    packet.push(0x04); // OCTET STRING
    packet.push(community.len() as u8); // Length
    packet.extend_from_slice(community.as_bytes()); // Value
    
    // PDU Type (GetRequest = 0xA0)
    packet.push(0xA0);
    packet.push(0x00); // 长度，稍后填充
    
    // Request ID
    packet.push(0x02); // INTEGER
    packet.push(0x04); // Length
    packet.push(((request_id >> 24) & 0xFF) as u8);
    packet.push(((request_id >> 16) & 0xFF) as u8);
    packet.push(((request_id >> 8) & 0xFF) as u8);
    packet.push((request_id & 0xFF) as u8);
    
    // Error Status (0 = noError)
    packet.push(0x02); // INTEGER
    packet.push(0x01); // Length
    packet.push(0x00); // Value
    
    // Error Index (0)
    packet.push(0x02); // INTEGER
    packet.push(0x01); // Length
    packet.push(0x00); // Value
    
    // Variable Bindings
    packet.push(0x30);
    packet.push(0x00); // 长度，稍后填充
    
    // Variable Binding
    packet.push(0x30);
    packet.push(0x00); // 长度，稍后填充
    
    // OID
    packet.push(0x06); // OBJECT IDENTIFIER
    packet.push(0x00); // 长度，稍后填充
    // 将OID字符串转换为ASN.1编码
    let oid_parts: Vec<&str> = oid.split('.').collect();
    let mut oid_value = Vec::new();
    oid_value.push(40 * oid_parts[0].parse::<u8>().unwrap_or(1) + oid_parts[1].parse::<u8>().unwrap_or(3));
    for part in oid_parts.iter().skip(2) {
        let value = part.parse::<u32>().unwrap_or(0);
        if value < 128 {
            oid_value.push(value as u8);
        } else {
            let mut val = value;
            let mut bytes = Vec::new();
            while val > 0 {
                let mut byte = (val & 0x7F) as u8;
                val >>= 7;
                if !bytes.is_empty() {
                    byte |= 0x80;
                }
                bytes.push(byte);
            }
            for b in bytes.iter().rev() {
                oid_value.push(*b);
            }
        }
    }
    packet[packet.len() - 1] = oid_value.len() as u8; // OID长度
    packet.extend_from_slice(&oid_value);
    
    // NULL value
    packet.push(0x05); // NULL
    packet.push(0x00); // Length
    
    // 填充长度
    // Variable Binding长度
    let vb_len = (packet.len() - packet.len() + 2) as u8;
    packet[packet.len() - vb_len - 2] = vb_len;
    
    // Variable Bindings长度
    let vbs_len = (packet.len() - packet.len() + 2 + 2) as u8;
    packet[packet.len() - vbs_len - 2] = vbs_len;
    
    // PDU长度
    let pdu_len = (packet.len() - 7) as u8;
    packet[6] = pdu_len;
    
    // 整个数据包长度
    let total_len = (packet.len() - 2) as u8;
    packet[1] = total_len;
    
    packet
}

fn create_snmp_get_request_v2c(community: &str, oid: &str) -> Vec<u8> {
    // 构建SNMPv2c GetRequest数据包
    let mut packet = Vec::new();
    
    // SEQUENCE
    packet.push(0x30);
    packet.push(0x00); // 长度，稍后填充
    
    // SNMP Version (v2c = 1)
    packet.push(0x02); // INTEGER
    packet.push(0x01); // Length
    packet.push(0x01); // Value (1 = SNMPv2c)
    
    // Community String
    packet.push(0x04); // OCTET STRING
    packet.push(community.len() as u8); // Length
    packet.extend_from_slice(community.as_bytes()); // Value
    
    // PDU Type (GetRequest = 0xA0)
    packet.push(0xA0);
    packet.push(0x00); // 长度，稍后填充
    
    // Request ID (使用随机值)
    let request_id = rand::random::<u32>();
    packet.push(0x02); // INTEGER
    packet.push(0x04); // Length
    packet.push(((request_id >> 24) & 0xFF) as u8);
    packet.push(((request_id >> 16) & 0xFF) as u8);
    packet.push(((request_id >> 8) & 0xFF) as u8);
    packet.push((request_id & 0xFF) as u8);
    
    // Error Status (0 = noError)
    packet.push(0x02); // INTEGER
    packet.push(0x01); // Length
    packet.push(0x00); // Value
    
    // Error Index (0)
    packet.push(0x02); // INTEGER
    packet.push(0x01); // Length
    packet.push(0x00); // Value
    
    // Variable Bindings
    packet.push(0x30);
    packet.push(0x00); // 长度，稍后填充
    
    // Variable Binding
    packet.push(0x30);
    packet.push(0x00); // 长度，稍后填充
    
    // OID
    packet.push(0x06); // OBJECT IDENTIFIER
    packet.push(0x00); // 长度，稍后填充
    // 将OID字符串转换为ASN.1编码
    let oid_parts: Vec<&str> = oid.split('.').collect();
    let mut oid_value = Vec::new();
    oid_value.push(40 * oid_parts[0].parse::<u8>().unwrap_or(1) + oid_parts[1].parse::<u8>().unwrap_or(3));
    for part in oid_parts.iter().skip(2) {
        let value = part.parse::<u32>().unwrap_or(0);
        if value < 128 {
            oid_value.push(value as u8);
        } else {
            let mut val = value;
            let mut bytes = Vec::new();
            while val > 0 {
                let mut byte = (val & 0x7F) as u8;
                val >>= 7;
                if !bytes.is_empty() {
                    byte |= 0x80;
                }
                bytes.push(byte);
            }
            for b in bytes.iter().rev() {
                oid_value.push(*b);
            }
        }
    }
    packet[packet.len() - 1] = oid_value.len() as u8; // OID长度
    packet.extend_from_slice(&oid_value);
    
    // NULL value
    packet.push(0x05); // NULL
    packet.push(0x00); // Length
    
    // 填充长度
    // Variable Binding长度
    let vb_len = (packet.len() - (packet.len() - 4)) as u8;
    packet[packet.len() - vb_len - 2] = vb_len;
    
    // Variable Bindings长度
    let vbs_len = (packet.len() - (packet.len() - 6)) as u8;
    packet[packet.len() - vbs_len - 2] = vbs_len;
    
    // PDU长度
    let pdu_len = (packet.len() - 7) as u8;
    packet[6] = pdu_len;
    
    // 整个数据包长度
    let total_len = (packet.len() - 2) as u8;
    packet[1] = total_len;
    
    packet
}

fn parse_snmp_response(response: &[u8]) -> Option<String> {
    // 简化的SNMP响应解析
    // 实际实现需要完整的ASN.1 BER解析器
    
    // 检查是否是SEQUENCE
    if response[0] != 0x30 {
        return None;
    }
    
    // 寻找OCTET STRING类型（可能是响应值）
    for i in 0..response.len() {
        if i + 1 < response.len() && response[i] == 0x04 {
            let len = response[i + 1] as usize;
            if i + 2 + len <= response.len() {
                let value = &response[i + 2..i + 2 + len];
                // 尝试转换为UTF-8字符串
                if let Ok(str_value) = std::str::from_utf8(value) {
                    // 忽略空字符串和社区名字符串
                    if !str_value.is_empty() && str_value.len() > 2 {
                        return Some(str_value.to_string());
                    }
                }
            }
        }
    }
    
    None
}

fn parse_snmp_response_v2c(response: &[u8]) -> Option<String> {
    // SNMPv2c响应解析
    // 基本与v1相同，但可能有不同的类型编码
    
    // 检查是否是SEQUENCE
    if response[0] != 0x30 {
        return None;
    }
    
    // 寻找OCTET STRING类型（可能是响应值）
    for i in 0..response.len() {
        if i + 1 < response.len() && response[i] == 0x04 {
            let len = response[i + 1] as usize;
            if i + 2 + len <= response.len() {
                let value = &response[i + 2..i + 2 + len];
                // 尝试转换为UTF-8字符串
                if let Ok(str_value) = std::str::from_utf8(value) {
                    // 忽略空字符串和社区名字符串
                    if !str_value.is_empty() && str_value.len() > 2 {
                        return Some(str_value.to_string());
                    }
                }
            }
        }
    }
    
    None
}
