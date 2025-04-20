// src/brute/ftp.rs
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
    
    info!("Starting FTP brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "FTP brute force");
    
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
                if let Some(result) = try_ftp_login(
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
    
    pb.finish_with_message(format!("Found {} valid FTP credentials", results.len()));
    
    Ok(results)
}

async fn try_ftp_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    let addr = format!("{}:{}", ip, port);
    
    // 创建FTP连接
    let connect_result = timeout(
        timeout_duration, 
        async {
            // 使用tokio的异步TCP连接
            let mut stream = match tokio::net::TcpStream::connect(&addr).await {
                Ok(stream) => stream,
                Err(_) => return None,
            };
            
            // 读取欢迎消息
            let mut buffer = vec![0u8; 1024];
            let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
            if let Err(_) = read_result {
                return None;
            }
            
            // 发送用户名
            let user_cmd = format!("USER {}\r\n", username);
            if let Err(_) = tokio::io::AsyncWriteExt::write_all(&mut stream, user_cmd.as_bytes()).await {
                return None;
            }
            
            // 读取响应
            let mut buffer = vec![0u8; 1024];
            let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
            if let Err(_) = read_result {
                return None;
            }
            
            let response = String::from_utf8_lossy(&buffer);
            // 如果响应不是要求密码，则失败
            if !response.contains("331") {
                return None;
            }
            
            // 发送密码
            let pass_cmd = format!("PASS {}\r\n", password);
            if let Err(_) = tokio::io::AsyncWriteExt::write_all(&mut stream, pass_cmd.as_bytes()).await {
                return None;
            }
            
            // 读取响应
            let mut buffer = vec![0u8; 1024];
            let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
            if let Err(_) = read_result {
                return None;
            }
            
            let response = String::from_utf8_lossy(&buffer);
            // 如果响应是230，则登录成功
            if response.contains("230") {
                Some(BruteResult {
                    ip,
                    port,
                    service: "ftp".to_string(),
                    username: username.to_string(),
                    password: password.to_string(),
                    details: Some(format!("FTP login successful")),
                })
            } else {
                None
            }
        }
    ).await;
    
    match connect_result {
        Ok(result) => result,
        Err(_) => None,
    }
}
