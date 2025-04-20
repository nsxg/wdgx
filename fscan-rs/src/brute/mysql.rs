// src/brute/mysql.rs
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
    
    info!("Starting MySQL brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "MySQL brute force");
    
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
                if let Some(result) = try_mysql_login(
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
    
    pb.finish_with_message(format!("Found {} valid MySQL credentials", results.len()));
    
    Ok(results)
}

async fn try_mysql_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    // MySQL认证是复杂的二进制协议，所以这里我们使用mysql crate
    // 但它不是异步的，所以在一个阻塞任务中执行
    let ip_str = ip.to_string();
    let username_clone = username.to_string();
    let password_clone = password.to_string();
    
    let result = tokio::task::spawn_blocking(move || {
        let conn_opts = mysql::OptsBuilder::new()
            .ip_or_hostname(Some(ip_str))
            .tcp_port(port)
            .user(Some(username_clone.clone()))
            .pass(Some(password_clone.clone()));
        
        match mysql::Conn::new(conn_opts) {
            Ok(conn) => {
                // 尝试执行一个简单的查询确认连接有效
                match conn.query_first::<String, _>("SELECT VERSION()") {
                    Ok(version) => {
                        let details = match version {
                            Some(v) => format!("MySQL version: {}", v),
                            None => "MySQL login successful".to_string(),
                        };
                        
                        Some(BruteResult {
                            ip: ip,
                            port,
                            service: "mysql".to_string(),
                            username: username_clone,
                            password: password_clone,
                            details: Some(details),
                        })
                    },
                    Err(_) => {
                        // 连接成功但查询失败，可能是权限问题
                        Some(BruteResult {
                            ip: ip,
                            port,
                            service: "mysql".to_string(),
                            username: username_clone,
                            password: password_clone,
                            details: Some("MySQL login successful but query failed".to_string()),
                        })
                    }
                }
            },
            Err(_) => None,
        }
    });
    
    match timeout(timeout_duration, result).await {
        Ok(Ok(result)) => result,
        _ => None,
    }
}
