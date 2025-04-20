// src/plugins/intranet.rs
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use crate::common::utils;

#[derive(Debug, Clone)]
pub struct IntranetInfo {
    pub subnet: String,
    pub gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub details: Option<String>,
}

pub async fn scan(
    timeout_secs: u64,
) -> Result<IntranetInfo, Box<dyn std::error::Error>> {
    info!("Starting intranet information gathering...");
    
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 获取本地网络信息
    let network_info = get_network_info(timeout_duration).await?;
    
    // 尝试确定默认网关
    let gateway = detect_gateway(timeout_duration).await;
    
    // 尝试确定DNS服务器
    let dns_servers = detect_dns_servers(timeout_duration).await;
    
    // 构建详细信息
    let mut details = String::new();
    
    details.push_str(&format!("Subnet: {}\n", network_info));
    
    if let Some(gateway) = gateway {
        details.push_str(&format!("Default Gateway: {}\n", gateway));
    }
    
    if !dns_servers.is_empty() {
        details.push_str("DNS Servers:\n");
        for (i, server) in dns_servers.iter().enumerate() {
            details.push_str(&format!("  {}: {}\n", i + 1, server));
        }
    }
    
    let result = IntranetInfo {
        subnet: network_info,
        gateway,
        dns_servers,
        details: Some(details),
    };
    
    Ok(result)
}

async fn get_network_info(timeout_duration: Duration) -> Result<String, Box<dyn std::error::Error>> {
    // 获取本地网络接口信息
    let interfaces = get_if_addrs::get_if_addrs()?;
    
    let mut subnet_info = String::new();
    
    for iface in interfaces {
        if let get_if_addrs::IfAddr::V4(ref v4) = iface.addr {
            // 忽略回环地址
            if v4.ip == Ipv4Addr::new(127, 0, 0, 1) {
                continue;
            }
            
            let ip = v4.ip;
            let netmask = v4.netmask;
            
            // 计算网络前缀长度
            let prefix_len = netmask_to_prefix_len(netmask);
            
            // 计算网络地址
            let network = calculate_network_address(ip, netmask);
            
            // 添加到子网信息
            if !subnet_info.is_empty() {
                subnet_info.push_str(", ");
            }
            
            subnet_info.push_str(&format!("{}/{}", network, prefix_len));
        }
    }
    
    if subnet_info.is_empty() {
        return Err("Failed to detect local network information".into());
    }
    
    Ok(subnet_info)
}

fn netmask_to_prefix_len(netmask: Ipv4Addr) -> u8 {
    let netmask_u32: u32 = netmask.into();
    (!netmask_u32).leading_zeros() as u8
}

fn calculate_network_address(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let ip_u32: u32 = ip.into();
    let netmask_u32: u32 = netmask.into();
    
    let network_u32 = ip_u32 & netmask_u32;
    Ipv4Addr::from(network_u32)
}

async fn detect_gateway(timeout_duration: Duration) -> Option<IpAddr> {
    // 使用路由表或ARP缓存确定默认网关
    
    // 方法1: 直接解析路由表输出
    if let Some(gateway) = parse_route_output().await {
        return Some(gateway);
    }
    
    // 方法2: 解析ARP缓存
    if let Some(gateway) = parse_arp_cache().await {
        return Some(gateway);
    }
    
    // 方法3: 尝试通用的网关地址
    let common_gateways = [
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
    ];
    
    for &ip in &common_gateways {
        let addr = format!("{}:80", ip);
        
        match timeout(
            Duration::from_millis(500), // 短超时
            tokio::net::TcpStream::connect(&addr),
        ).await {
            Ok(Ok(_)) => return Some(IpAddr::V4(ip)),
            _ => continue,
        }
    }
    
    None
}

async fn parse_route_output() -> Option<IpAddr> {
    let output = match tokio::process::Command::new("route")
        .arg("print")
        .arg("0.0.0.0")
        .output()
        .await {
        Ok(output) if output.status.success() => output,
        _ => {
            // 尝试Linux的ip route命令
            match tokio::process::Command::new("ip")
                .arg("route")
                .arg("show")
                .arg("default")
                .output()
                .await {
                Ok(output) if output.status.success() => output,
                _ => return None,
            }
        }
    };
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // 解析Windows route输出
    if output_str.contains("0.0.0.0") {
        for line in output_str.lines() {
            if line.contains("0.0.0.0") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for (i, &part) in parts.iter().enumerate() {
                    if part == "0.0.0.0" && i + 2 < parts.len() {
                        if let Ok(ip) = parts[i + 2].parse::<Ipv4Addr>() {
                            return Some(IpAddr::V4(ip));
                        }
                    }
                }
            }
        }
    } 
    // 解析Linux ip route输出
    else if output_str.contains("default") {
        for line in output_str.lines() {
            if line.contains("default") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for (i, &part) in parts.iter().enumerate() {
                    if part == "via" && i + 1 < parts.len() {
                        if let Ok(ip) = parts[i + 1].parse::<Ipv4Addr>() {
                            return Some(IpAddr::V4(ip));
                        }
                    }
                }
            }
        }
    }
    
    None
}

async fn parse_arp_cache() -> Option<IpAddr> {
    let output = match tokio::process::Command::new("arp")
        .arg("-a")
        .output()
        .await {
        Ok(output) if output.status.success() => output,
        _ => return None,
    };
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // 查找动态条目（通常是网关）
    for line in output_str.lines() {
        if line.contains("dynamic") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    // 假设第一个动态条目是网关
                    return Some(IpAddr::V4(ip));
                }
            }
        }
    }
    
    None
}

async fn detect_dns_servers(timeout_duration: Duration) -> Vec<IpAddr> {
    let mut dns_servers = Vec::new();
    
    // 方法1: 解析resolv.conf
    if let Some(mut servers) = parse_resolv_conf().await {
        dns_servers.append(&mut servers);
    }
    
    // 方法2: Windows的ipconfig命令
    if let Some(mut servers) = parse_ipconfig_output().await {
        dns_servers.append(&mut servers);
    }
    
    // 方法3: 常见DNS服务器
    if dns_servers.is_empty() {
        let common_dns = [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),      // Google DNS
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),      // Google DNS备用
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),      // Cloudflare DNS
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),      // Quad9
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), // OpenDNS
        ];
        
        for &ip in &common_dns {
            // 尝试查询以确认DNS服务器可用
            if is_dns_server_available(ip, timeout_duration).await {
                dns_servers.push(ip);
                // 只添加一个可用的DNS服务器即可
                break;
            }
        }
    }
    
    // 去重
    dns_servers.sort();
    dns_servers.dedup();
    
    dns_servers
}

async fn parse_resolv_conf() -> Option<Vec<IpAddr>> {
    use tokio::fs::File;
    use tokio::io::{AsyncBufReadExt, BufReader};
    
    match File::open("/etc/resolv.conf").await {
        Ok(file) => {
            let reader = BufReader::new(file);
            let mut lines = reader.lines();
            let mut dns_servers = Vec::new();
            
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(ip) = parts[1].parse::<IpAddr>() {
                            dns_servers.push(ip);
                        }
                    }
                }
            }
            
            if !dns_servers.is_empty() {
                return Some(dns_servers);
            }
        },
        _ => {}
    }
    
    None
}

async fn parse_ipconfig_output() -> Option<Vec<IpAddr>> {
    let output = match tokio::process::Command::new("ipconfig")
        .arg("/all")
        .output()
        .await {
        Ok(output) if output.status.success() => output,
        _ => return None,
    };
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut dns_servers = Vec::new();
    
    for line in output_str.lines() {
        let line = line.trim();
        if line.contains("DNS Servers") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let server_part = parts[1].trim();
                if let Ok(ip) = server_part.parse::<IpAddr>() {
                    dns_servers.push(ip);
                }
            }
        }
    }
    
    if !dns_servers.is_empty() {
        return Some(dns_servers);
    }
    
    None
}

async fn is_dns_server_available(ip: IpAddr, timeout_duration: Duration) -> bool {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::AsyncResolver;
    
    // 创建指向特定DNS服务器的解析器
    let mut config = ResolverConfig::new();
    config.add_name_server(format!("{}:53", ip).parse().unwrap());
    
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout_duration;
    
    match AsyncResolver::tokio(config, opts) {
        Ok(resolver) => {
            // 尝试解析一个已知域名
            match timeout(
                timeout_duration,
                resolver.lookup_ip("www.google.com"),
            ).await {
                Ok(Ok(_)) => true,
                _ => false,
            }
        },
        _ => false,
    }
}
