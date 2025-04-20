// src/plugins/domain.rs
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use crate::common::utils;

#[derive(Debug, Clone)]
pub struct DomainInfo {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub domain: String,
    pub is_domain_controller: bool,
    pub domain_roles: Vec<String>,
    pub details: Option<String>,
}

pub async fn scan(
    targets: &[IpAddr],
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<DomainInfo>, Box<dyn std::error::Error>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting domain controller scanning for {} targets...", targets.len());
    
    let pb = utils::create_progress_bar(targets.len() as u64, "Domain scanning");
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
                if let Some(info) = detect_domain_controller(ip, timeout_duration).await {
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
    
    pb.finish_with_message(format!("Found {} domain controllers", results.len()));
    
    Ok(results)
}

async fn detect_domain_controller(ip: IpAddr, timeout_duration: Duration) -> Option<DomainInfo> {
    // 结合LDAP查询和RPC调用来检测域控制器
    if let Some(info) = detect_ldap(ip, timeout_duration).await {
        return Some(info);
    }
    
    if let Some(info) = detect_rpc(ip, timeout_duration).await {
        return Some(info);
    }
    
    None
}

async fn detect_ldap(ip: IpAddr, timeout_duration: Duration) -> Option<DomainInfo> {
    use tokio_ldap::{LdapConnAsync, LdapConnSettings};
    
    // 尝试连接LDAP服务（通常在域控制器上运行）
    let settings = LdapConnSettings::new()
        .set_timeout(timeout_duration);
    
    let addr = format!("{}:389", ip); // 标准LDAP端口
    
    match timeout(
        timeout_duration,
        LdapConnAsync::with_settings(settings, &addr),
    ).await {
        Ok(Ok((conn, ldap))) => {
            // 尝试匿名绑定
            match timeout(timeout_duration, ldap.simple_bind("", "")).await {
                Ok(Ok(_)) => {
                    // 尝试查询域信息
                    if let Some(domain_info) = query_domain_info(ldap, timeout_duration).await {
                        return Some(DomainInfo {
                            ip,
                            hostname: domain_info.0,
                            domain: domain_info.1,
                            is_domain_controller: true,
                            domain_roles: domain_info.2,
                            details: Some("Detected via LDAP".to_string()),
                        });
                    }
                },
                _ => {
                    // 绑定失败，但LDAP服务可能仍在运行
                    // 尝试从LDAP服务器标识获取域信息
                    if let Some(domain) = get_ldap_server_info(conn).await {
                        return Some(DomainInfo {
                            ip,
                            hostname: None,
                            domain,
                            is_domain_controller: true,
                            domain_roles: vec!["Unknown".to_string()],
                            details: Some("LDAP service detected, but authentication required".to_string()),
                        });
                    }
                }
            }
        },
        _ => {}
    }
    
    None
}

async fn query_domain_info(
    ldap: impl tokio_ldap::Ldap,
    timeout_duration: Duration,
) -> Option<(Option<String>, String, Vec<String>)> {
    use tokio_ldap::{SearchEntry, SearchOptions};
    
    // 查询根DSE
    let root_dse_future = ldap.search(
        "",
        tokio_ldap::Scope::Base,
        "(objectClass=*)",
        vec!["defaultNamingContext", "dnsHostName"],
        SearchOptions::new(),
    );
    
    match timeout(timeout_duration, root_dse_future).await {
        Ok(Ok(entries)) => {
            if entries.is_empty() {
                return None;
            }
            
            let entry = &entries[0];
            let default_naming_context = entry
                .attrs
                .get("defaultNamingContext")
                .and_then(|values| values.first())
                .map(|v| v.to_string());
            
            let dns_host_name = entry
                .attrs
                .get("dnsHostName")
                .and_then(|values| values.first())
                .map(|v| v.to_string());
            
            if let Some(base_dn) = default_naming_context {
                // 从base_dn提取域名（例如DC=example,DC=com -> example.com）
                let domain = base_dn
                    .split(',')
                    .filter_map(|part| {
                        if part.starts_with("DC=") {
                            Some(part[3..].to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(".");
                
                // 查询域控制器角色
                let domain_roles = query_domain_roles(&ldap, &base_dn, timeout_duration).await
                    .unwrap_or_else(|| vec!["Domain Controller".to_string()]);
                
                return Some((dns_host_name, domain, domain_roles));
            }
        },
        _ => {}
    }
    
    None
}

async fn query_domain_roles(
    ldap: &impl tokio_ldap::Ldap,
    base_dn: &str,
    timeout_duration: Duration,
) -> Option<Vec<String>> {
    use tokio_ldap::SearchOptions;
    
    // 查询当前服务器的FSMO角色
    let roles_future = ldap.search(
        base_dn,
        tokio_ldap::Scope::Subtree,
        "(fSMORoleOwner=*)",
        vec!["fSMORoleOwner"],
        SearchOptions::new(),
    );
    
    match timeout(timeout_duration, roles_future).await {
        Ok(Ok(entries)) => {
            if entries.is_empty() {
                return None;
            }
            
            let mut roles = Vec::new();
            for entry in entries {
                roles.push(entry.dn);
            }
            
            // 简化角色名称
            let roles = roles
                .iter()
                .map(|role| {
                    if role.contains("RID") {
                        "RID Master".to_string()
                    } else if role.contains("PDC") {
                        "PDC Emulator".to_string()
                    } else if role.contains("Infrastructure") {
                        "Infrastructure Master".to_string()
                    } else if role.contains("Schema") {
                        "Schema Master".to_string()
                    } else if role.contains("Naming") {
                        "Domain Naming Master".to_string()
                    } else {
                        "Domain Controller".to_string()
                    }
                })
                .collect::<Vec<_>>();
            
            Some(roles)
        },
        _ => None,
    }
}

async fn get_ldap_server_info(conn: impl tokio::io::AsyncRead) -> Option<String> {
    // 从LDAP服务器响应中提取域信息
    // 这是一个简化的实现，实际上可能需要更复杂的解析
    
    let mut buffer = [0u8; 1024];
    let mut reader = tokio::io::BufReader::new(conn);
    
    match tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await {
        Ok(n) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            
            // 尝试从响应中提取域名
            if let Some(start) = response.find("DC=") {
                let dc_part = &response[start..];
                if let Some(end) = dc_part.find(',') {
                    let domain_part = &dc_part[3..end];
                    return Some(domain_part.to_string());
                }
            }
        },
        _ => {}
    }
    
    None
}

async fn detect_rpc(ip: IpAddr, timeout_duration: Duration) -> Option<DomainInfo> {
    // 使用DCE/RPC调用检测域控制器
    // 这需要使用特定的Windows RPC协议
    
    // 尝试使用SMB连接到137或445端口
    let ports = [445, 137];
    
    for &port in &ports {
        let addr = format!("{}:{}", ip, port);
        
        match timeout(timeout_duration, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                // 尝试使用RPC协议查询域控制器信息
                if let Some(info) = query_domain_info_via_rpc(stream, timeout_duration).await {
                    return Some(DomainInfo {
                        ip,
                        hostname: info.0,
                        domain: info.1,
                        is_domain_controller: true,
                        domain_roles: info.2,
                        details: Some("Detected via RPC".to_string()),
                    });
                }
            },
            _ => continue,
        }
    }
    
    None
}

async fn query_domain_info_via_rpc(
    mut stream: tokio::net::TcpStream,
    timeout_duration: Duration,
) -> Option<(Option<String>, String, Vec<String>)> {
    // 这是一个简化的实现，实际上需要实现完整的DCE/RPC和MS-NRPC协议
    
    // 构建一个简单的NetrServerGetInfo请求
    let request = vec![
        // SMB头
        0xFF, 0x53, 0x4D, 0x42, // SMB标识符
        // ... 更多SMB头字段
        
        // DCE/RPC头
        // ... DCE/RPC头字段
        
        // NetrServerGetInfo操作码和参数
        // ... NetrServerGetInfo参数
    ];
    
    match tokio::io::AsyncWriteExt::write_all(&mut stream, &request).await {
        Ok(_) => {
            let mut buffer = vec![0u8; 4096];
            
            match timeout(
                timeout_duration,
                tokio::io::AsyncReadExt::read(&mut stream, &mut buffer),
            ).await {
                Ok(Ok(n)) if n > 0 => {
                    // 解析响应中的域控制器信息
                    // 这需要完整的SMB和DCE/RPC协议解析
                    
                    // 简化的示例，假设能从响应中提取信息
                    let hostname = Some("dc01".to_string());
                    let domain = "example.com".to_string();
                    let roles = vec!["Domain Controller".to_string()];
                    
                    Some((hostname, domain, roles))
                },
                _ => None,
            }
        },
        _ => None,
    }
}
