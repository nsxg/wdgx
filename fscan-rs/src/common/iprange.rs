use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use anyhow::{Result, anyhow};
use ipnetwork::Ipv4Network;

/// 解析目标参数为IP地址列表
pub fn parse_targets(target: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    
    // 按逗号分隔多个目标
    for part in target.split(',') {
        let part = part.trim();
        
        if part.contains('/') {
            // CIDR格式 (192.168.1.0/24)
            parse_cidr(part, &mut ips)?;
        } else if part.contains('-') {
            // 范围格式 (192.168.1.1-192.168.1.254)
            parse_range(part, &mut ips)?;
        } else {
            // 单IP格式
            let ip = IpAddr::from_str(part)
                .map_err(|_| anyhow!("Invalid IP address: {}", part))?;
            ips.push(ip);
        }
    }
    
    Ok(ips)
}

/// 解析CIDR格式
fn parse_cidr(cidr: &str, ips: &mut Vec<IpAddr>) -> Result<()> {
    let network = Ipv4Network::from_str(cidr)
        .map_err(|_| anyhow!("Invalid CIDR: {}", cidr))?;
    
    // 添加网络中的所有IP地址（除了网络地址和广播地址）
    for ip in network.iter() {
        if ip != network.network() && ip != network.broadcast() {
            ips.push(IpAddr::V4(ip));
        }
    }
    
    Ok(())
}

/// 解析IP范围格式
fn parse_range(range: &str, ips: &mut Vec<IpAddr>) -> Result<()> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid IP range: {}", range));
    }
    
    let start_ip = Ipv4Addr::from_str(parts[0].trim())
        .map_err(|_| anyhow!("Invalid start IP: {}", parts[0]))?;
    
    let end_ip = if parts[1].trim().contains('.') {
        // 完整IP地址
        Ipv4Addr::from_str(parts[1].trim())
            .map_err(|_| anyhow!("Invalid end IP: {}", parts[1]))?
    } else {
        // 只有最后一个部分 (192.168.1.1-254)
        let start_octets = start_ip.octets();
        let last_octet = parts[1].trim().parse::<u8>()
            .map_err(|_| anyhow!("Invalid end octet: {}", parts[1]))?;
        
        Ipv4Addr::new(
            start_octets[0],
            start_octets[1],
            start_octets[2],
            last_octet
        )
    };
    
    let start_u32 = u32::from(start_ip);
    let end_u32 = u32::from(end_ip);
    
    if start_u32 > end_u32 {
        return Err(anyhow!("Start IP is greater than end IP: {} > {}", start_ip, end_ip));
    }
    
    for i in start_u32..=end_u32 {
        let ip = Ipv4Addr::from(i);
        ips.push(IpAddr::V4(ip));
    }
    
    Ok(())
}
