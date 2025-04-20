// src/brute/redis.rs
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
    if services.is_empty() || passwords.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting Redis brute force for {} services with {} passwords...", 
        services.len(), passwords.len());
    
    // 计算总尝试次数 (Redis不使用用户名)
    let total_attempts = services.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "Redis brute force");
    
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // 创建所有组合的任务
    let mut tasks = Vec::new();
    for service in services {
        for password in passwords {
            tasks.push((
                service.ip,
                service.port,
                password.clone(),
            ));
        }
    }
    
    // 分块处理
    let chunk_size = (tasks.len() + threads - 1) / threads;
    let chunks: Vec<Vec<(IpAddr, u16, String)>> = tasks
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let timeout_duration = timeout_duration;
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for (ip, port, password) in chunk {
                if let Some(result) = try_redis_login(
                    ip,
                    port,
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
    
    pb.finish_with_message(format!("Found {} valid Redis credentials", results.len()));
    
    Ok(results)
}

async fn try_redis_login(
    ip: IpAddr,
    port: u16,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    let addr = format!("{}:{}", ip, port);
    
    // 创建Redis连接
    let connect_result = timeout(
        timeout_duration, 
        async {
            // 使用tokio的异步TCP连接
            let mut stream = match tokio::net::TcpStream::connect(&addr).await {
                Ok(stream) => stream,
                Err(_) => return None,
            };
            
            // 如果是空密码，尝试直接发送PING命令
            if password.is_empty() {
                let ping_cmd = "*1\r\n$4\r\nPING\r\n";
                if let Err(_) = tokio::io::AsyncWriteExt::write_all(&mut stream, ping_cmd.as_bytes()).await {
                    return None;
                }
                
                // 读取响应
                let mut buffer = vec![0u8; 1024];
                let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
                if let Err(_) = read_result {
                    return None;
                }
                
                let response = String::from_utf8_lossy(&buffer);
                // 如果响应包含+PONG，则无密码验证成功
                if response.contains("+PONG") {
                    return Some(BruteResult {
                        ip,
                        port,
                        service: "redis".to_string(),
                        username: "".to_string(),
                        password: "".to_string(),
                        details: Some("Redis requires no password".to_string()),
                    });
                }
            } else {
                // 尝试使用密码认证
                let auth_cmd = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", password.len(), password);
                if let Err(_) = tokio::io::AsyncWriteExt::write_all(&mut stream, auth_cmd.as_bytes()).await {
                    return None;
                }
                
                // 读取响应
                let mut buffer = vec![0u8; 1024];
                let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
                if let Err(_) = read_result {
                    return None;
                }
                
                let response = String::from_utf8_lossy(&buffer);
                // 如果响应包含+OK，则密码验证成功
                if response.contains("+OK") {
                    // 尝试执行PING命令以确认连接有效
                    let ping_cmd = "*1\r\n$4\r\nPING\r\n";
                    if let Err(_) = tokio::io::AsyncWriteExt::write_all(&mut stream, ping_cmd.as_bytes()).await {
                        return None;
                    }
                    
                    // 读取响应
                    let mut buffer = vec![0u8; 1024];
                    let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
                    if let Err(_) = read_result {
                        return None;
                    }
                    
                    let response = String::from_utf8_lossy(&buffer);
                    // 如果响应包含+PONG，则连接有效
                    if response.contains("+PONG") {
                        return Some(BruteResult {
                            ip,
                            port,
                            service: "redis".to_string(),
                            username: "".to_string(),
                            password: password.to_string(),
                            details: Some("Redis password authentication successful".to_string()),
                        });
                    }
                }
            }
            
            None
        }
    ).await;
    
    match connect_result {
        Ok(result) => result,
        Err(_) => None,
    }
}
