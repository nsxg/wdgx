// src/brute/postgres.rs
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
    
    info!("Starting PostgreSQL brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "PostgreSQL brute force");
    
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
                if let Some(result) = try_postgres_login(
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
    
    pb.finish_with_message(format!("Found {} valid PostgreSQL credentials", results.len()));
    
    Ok(results)
}

async fn try_postgres_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    use tokio_postgres::{Config, NoTls};
    
    // 配置PostgreSQL连接
    let mut config = Config::new();
    config
        .host(&ip.to_string())
        .port(port)
        .user(username)
        .password(password)
        .dbname("postgres")  // 默认数据库
        .connect_timeout(timeout_duration);
    
    // 尝试连接
    let connect_future = config.connect(NoTls);
    
    match timeout(timeout_duration, connect_future).await {
        Ok(Ok((client, connection))) => {
            // 在后台运行连接处理器
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("PostgreSQL connection error: {}", e);
                }
            });
            
            // 尝试查询版本以验证连接
            let version_query = client.query_one("SELECT version()", &[]);
            
            match timeout(timeout_duration, version_query).await {
                Ok(Ok(row)) => {
                    let version: String = row.get(0);
                    
                    Some(BruteResult {
                        ip,
                        port,
                        service: "postgresql".to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        details: Some(format!("PostgreSQL version: {}", version)),
                    })
                },
                _ => {
                    // 连接成功但查询失败
                    Some(BruteResult {
                        ip,
                        port,
                        service: "postgresql".to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        details: Some("Authentication successful but query failed".to_string()),
                    })
                }
            }
        },
        _ => None,
    }
}
