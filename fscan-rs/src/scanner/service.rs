use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{debug, info};
use lazy_static::lazy_static;
use regex::Regex;
use crate::common::utils;
use crate::scanner::{port::PortScanResult, ServiceInfo};

// 服务指纹定义 - 修改类型签名，将探针从&'static str改为&'static [u8]
lazy_static! {
    static ref SERVICE_FINGERPRINTS: HashMap<&'static str, Vec<(&'static [u8], &'static str)>> = {
        let mut map = HashMap::new();
        
        // 服务名称 => [(探针, 正则匹配模式)]
        map.insert("ssh", vec![
            (b"", "SSH-\\d+\\.\\d+"),
            (b"SSH-2.0-OpenSSH\r\n", "SSH-\\d+\\.\\d+-([^\\r\\n]+)"),
        ]);
        
        map.insert("http", vec![
            (b"GET / HTTP/1.0\r\n\r\n", "HTTP/\\d+\\.\\d+.+Server: ([^\\r\\n]+)"),
            (b"HEAD / HTTP/1.0\r\n\r\n", "HTTP/\\d+\\.\\d+.+Server: ([^\\r\\n]+)"),
        ]);
        
        map.insert("https", vec![
            // HTTPS需要特殊处理，这里只是占位
            (b"", ""),
        ]);
        
        map.insert("ftp", vec![
            (b"", "^220.*FTP"),
            (b"", "^220.*FileZilla"),
        ]);
        
        map.insert("smtp", vec![
            (b"", "^220.*SMTP"),
            (b"", "^220.*ESMTP"),
        ]);
        
        map.insert("pop3", vec![
            (b"", "^\\+OK"),
        ]);
        
        map.insert("imap", vec![
            (b"", "^\\* OK.*IMAP"),
        ]);
        
        map.insert("mysql", vec![
            (b"", "^\\x5B\\x00\\x00\\x00\\x0A"),
            (b"", "^[0-9]+.*mysql"),
        ]);
        
        map.insert("mssql", vec![
            (b"", "^\\x04\\x01\\x00"),
        ]);
        
        map.insert("redis", vec![
            (b"*1\r\n$4\r\nPING\r\n", "\\+PONG"),
            (b"", "-ERR.*redis"),
        ]);
        
        map.insert("mongodb", vec![
            (b"", "MongoDB"),
        ]);
        
        map.insert("rdp", vec![
            (b"", "^\\x03\\x00\\x00"),  // 修改这里：使用字节字符串
        ]);
        
        map.insert("smb", vec![
            // 修改这里：使用字节数组而不是字符串，避免转义问题
            (&[0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00], "\\x00\\x00\\x00"),
        ]);
        
        map
    };
}

pub async fn scan_services(
    ports: &[PortScanResult],
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<ServiceInfo>, Box<dyn std::error::Error>> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting service detection for {} open ports...", ports.len());
    
    let pb = utils::create_progress_bar(ports.len() as u64, "Detecting services");
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 分块处理
    let chunk_size = (ports.len() + threads - 1) / threads;
    let chunks: Vec<Vec<PortScanResult>> = ports
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let timeout_duration = timeout_duration;
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for port_result in chunk {
                if let Some(service_info) = detect_service(
                    port_result.ip,
                    port_result.port,
                    timeout_duration
                ).await {
                    let _ = tx.send(service_info).await;
                }
                pb.inc(1);
            }
        });
    }
    
    // 丢弃原始发送者
    drop(tx);
    
    // 收集结果
    let mut services = Vec::new();
    while let Some(service_info) = rx.recv().await {
        services.push(service_info);
    }
    
    pb.finish_with_message(format!("Identified {} services", services.len()));
    
    Ok(services)
}

async fn detect_service(
    ip: std::net::IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Option<ServiceInfo> {
    // 特殊端口的默认服务
    let default_service = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        6379 => "redis",
        8080 => "http",
        8443 => "https",
        27017 => "mongodb",
        _ => "unknown",
    };
    
    let addr = format!("{}:{}", ip, port);
    let connect_result = timeout(timeout_duration, TcpStream::connect(&addr)).await;
    
    match connect_result {
        Ok(Ok(mut stream)) => {
            // 设置读写超时
            let _ = stream.set_nodelay(true);
            
            // 尝试获取服务横幅
            let mut banner = String::new();
            
            // 有些服务会主动发送横幅
            if let Ok(Ok(n)) = timeout(
                timeout_duration,
                stream.read_buf(&mut banner.as_mut_vec())
            ).await {
                if n > 0 {
                    debug!("Received banner from {}:{} ({} bytes)", ip, port, n);
                }
            }
            
            // 尝试使用探针识别服务
            let mut identified_service = default_service;
            let mut version = None;
            
            // 遍历所有服务指纹
            for (service, probes) in SERVICE_FINGERPRINTS.iter() {
                for (probe, pattern) in probes {
                    if !probe.is_empty() {
                        // 发送探针 - 修改这里：直接使用探针字节数据，无需转换
                        let _ = stream.write_all(probe).await;
                        let _ = stream.flush().await;
                        
                        // 读取响应
                        let mut response = Vec::new();
                        let read_result = timeout(
                            timeout_duration,
                            stream.read_buf(&mut response)
                        ).await;
                        
                        if let Ok(Ok(n)) = read_result {
                            if n > 0 {
                                let resp_str = String::from_utf8_lossy(&response);
                                banner.push_str(&resp_str);
                            }
                        }
                    }
                    
                    // 检查是否匹配
                    if !pattern.is_empty() {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&banner) {
                                identified_service = service;
                                
                                // 提取版本（如果有）
                                if let Some(caps) = re.captures(&banner) {
                                    if caps.len() > 1 {
                                        version = Some(caps[1].to_string());
                                    }
                                }
                                
                                break;
                            }
                        }
                    }
                }
                
                if identified_service != default_service {
                    break;
                }
            }
            
            // 特殊处理某些服务（如HTTPS）
            if port == 443 || port == 8443 {
                identified_service = "https";
            }
            
            Some(ServiceInfo {
                ip,
                port,
                service: identified_service.to_string(),
                banner,
                version,
            })
        },
        _ => None,
    }
}
