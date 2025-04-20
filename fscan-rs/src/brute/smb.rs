// src/brute/smb.rs
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use crate::common::utils;
use crate::scanner::ServiceInfo;
use crate::brute::BruteResult;

pub async fn brute_force(
    services: &[&ServiceInfo],
    usernames: &[String],
    passwords: &[String],
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<BruteResult>, Box<dyn std::error::Error>> {
    if services.is_empty() || usernames.is_empty() || passwords.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting SMB brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "SMB brute force");
    
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 创建所有组合的任务
    let mut tasks = Vec::new();
    for service in services {
        for username in usernames {
            for password in passwords {
                tasks.push((
                    service.ip,
                    service.port,
                    username.clone(),
                    password.clone(),
                ));
            }
        }
    }
    
    // 分块处理
    let chunk_size = (tasks.len() + threads - 1) / threads;
    let chunks: Vec<Vec<(IpAddr, u16, String, String)>> = tasks
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let timeout_duration = timeout_duration;
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for (ip, port, username, password) in chunk {
                if let Some(result) = try_smb_login(
                    ip,
                    port,
                    &username,
                    &password,
                    timeout_duration
                ).await {
                    let _ = tx.send(result).await;
                }
                pb.inc(1);
            }
        });
    }
    
    // 丢弃原始发送者
    drop(tx);
    
    // 收集结果
    let mut results = Vec::new();
    while let Some(result) = rx.recv().await {
        results.push(result);
    }
    
    pb.finish_with_message(format!("Found {} valid SMB credentials", results.len()));
    
    Ok(results)
}

async fn try_smb_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    // SMB连接是复杂的二进制协议，我们在阻塞任务中使用smbclient库
    let ip_str = ip.to_string();
    let username_clone = username.to_string();
    let password_clone = password.to_string();
    
    let result = tokio::task::spawn_blocking(move || {
        // 使用第三方库或直接构建SMB认证数据包
        use smb_client::{SmbClient, Credentials, Options};
        
        let credentials = Credentials::new(&username_clone, &password_clone);
        let options = Options::new();
        
        // 尝试连接到SMB服务器
        let client = match SmbClient::new(&ip_str, port as u32, &credentials, &options) {
            Ok(client) => client,
            Err(_) => return None,
        };
        
        // 尝试列出可用共享以验证连接
        match client.list_shares() {
            Ok(shares) => {
                let shares_info = shares
                    .iter()
                    .map(|s| s.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                
                Some(BruteResult {
                    ip,
                    port,
                    service: "smb".to_string(),
                    username: username_clone,
                    password: password_clone,
                    details: Some(format!("Available shares: {}", shares_info)),
                })
            },
            Err(_) => {
                // 身份验证成功但无法列出共享
                Some(BruteResult {
                    ip,
                    port,
                    service: "smb".to_string(),
                    username: username_clone,
                    password: password_clone,
                    details: Some("Authentication successful but unable to list shares".to_string()),
                })
            }
        }
    });
    
    match timeout(timeout_duration, result).await {
        Ok(Ok(result)) => result,
        _ => None,
    }
}
