// src/brute/mongodb.rs
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
    
    info!("Starting MongoDB brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "MongoDB brute force");
    
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
                if let Some(result) = try_mongodb_login(
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
    
    pb.finish_with_message(format!("Found {} valid MongoDB credentials", results.len()));
    
    Ok(results)
}

async fn try_mongodb_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    // 使用MongoDB Rust驱动程序
    use mongodb::{Client, options::{ClientOptions, AuthMechanism}};
    
    let connection_string = if username.is_empty() && password.is_empty() {
        // 无身份验证
        format!("mongodb://{}:{}", ip, port)
    } else {
        // 有身份验证
        format!("mongodb://{}:{}@{}:{}/admin", username, password, ip, port)
    };
    
    // 设置MongoDB连接选项
    let client_options_future = async {
        let mut client_options = ClientOptions::parse(&connection_string).await?;
        client_options.connect_timeout = Some(timeout_duration);
        client_options.server_selection_timeout = Some(timeout_duration);
        
        if !username.is_empty() && !password.is_empty() {
            client_options.credential = Some(mongodb::options::Credential {
                username: Some(username.to_string()),
                password: Some(password.to_string()),
                source: Some("admin".to_string()),
                mechanism: Some(AuthMechanism::ScramSha256),
                mechanism_properties: None,
            });
        }
        
        Ok::<_, mongodb::error::Error>(client_options)
    };
    
    let client_options_result = timeout(timeout_duration, client_options_future).await;
    
    match client_options_result {
        Ok(Ok(client_options)) => {
            // 尝试连接到MongoDB服务器
            let connect_future = async {
                let client = Client::with_options(client_options)?;
                
                // 尝试获取数据库列表以验证连接
                let dbs = client.list_database_names(None, None).await?;
                
                Ok::<_, mongodb::error::Error>((client, dbs))
            };
            
            match timeout(timeout_duration, connect_future).await {
                Ok(Ok((_, dbs))) => {
                    let dbs_str = dbs.join(", ");
                    
                    Some(BruteResult {
                        ip,
                        port,
                        service: "mongodb".to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        details: Some(format!("Available databases: {}", dbs_str)),
                    })
                },
                _ => None,
            }
        },
        _ => None,
    }
}
