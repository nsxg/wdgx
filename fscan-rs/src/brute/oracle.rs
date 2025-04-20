// src/brute/oracle.rs
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
    
    info!("Starting Oracle brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "Oracle brute force");
    
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
                if let Some(result) = try_oracle_login(
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
    
    pb.finish_with_message(format!("Found {} valid Oracle credentials", results.len()));
    
    Ok(results)
}

async fn try_oracle_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    // Oracle数据库连接需要使用Oracle Client库
    // 在这里使用r2d2-oracle或rusora等库，我们将使用阻塞任务实现
    let ip_str = ip.to_string();
    let username_clone = username.to_string();
    let password_clone = password.to_string();
    
    let result = tokio::task::spawn_blocking(move || {
        // 构建连接字符串
        // 格式: username/password@//host:port/service_name
        let conn_str = format!(
            "{}/{}@//{}:{}/ORCL", // ORCL是默认的SID，实际环境中可能需要配置
            username_clone,
            password_clone,
            ip_str,
            port
        );
        
        // 使用oracle客户端库连接
        // 注：此处使用伪代码表示，实际需要引入oracle客户端库
        let conn_result = oracle::Connection::connect(&conn_str, oracle::ConnParam::Default);
        
        match conn_result {
            Ok(conn) => {
                // 尝试执行简单查询以验证连接
                let version_query = conn.query("SELECT BANNER FROM V$VERSION WHERE ROWNUM = 1", &[]);
                
                match version_query {
                    Ok(rows) => {
                        let mut version = String::new();
                        if let Some(row) = rows.first() {
                            if let Some(banner) = row.get::<String>("BANNER") {
                                version = banner;
                            }
                        }
                        
                        Some(BruteResult {
                            ip,
                            port,
                            service: "oracle".to_string(),
                            username: username_clone,
                            password: password_clone,
                            details: Some(format!("Oracle version: {}", version)),
                        })
                    },
                    Err(_) => {
                        // 连接成功但查询失败
                        Some(BruteResult {
                            ip,
                            port,
                            service: "oracle".to_string(),
                            username: username_clone,
                            password: password_clone,
                            details: Some("Authentication successful but query failed".to_string()),
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
