// src/webscan/fingerprint.rs
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use regex::Regex;
use lazy_static::lazy_static;
use crate::common::utils;
use crate::scanner::ServiceInfo;
use crate::webscan::WebFingerprint;

// 技术指纹定义
lazy_static! {
    static ref TECH_FINGERPRINTS: HashMap<&'static str, Vec<&'static str>> = {
        let mut map = HashMap::new();
        
        // 技术 => [正则匹配模式]
        map.insert("WordPress", vec![
            r"<meta\s+name=['\"]generator['\"][^>]*content=['\"]WordPress",
            r"/wp-content/",
            r"/wp-includes/",
        ]);
        
        map.insert("Joomla", vec![
            r"<meta\s+name=['\"]generator['\"][^>]*content=['\"]Joomla",
            r"/components/com_",
        ]);
        
        map.insert("Drupal", vec![
            r"<meta\s+name=['\"]generator['\"][^>]*content=['\"]Drupal",
            r"Drupal.settings",
            r"/sites/all/",
        ]);
        
        map.insert("Apache", vec![
            r"Server: Apache",
        ]);
        
        map.insert("Nginx", vec![
            r"Server: nginx",
        ]);
        
        map.insert("PHP", vec![
            r"X-Powered-By: PHP",
            r"<\?php",
        ]);
        
        map.insert("jQuery", vec![
            r"jquery.js",
            r"jquery.min.js",
        ]);
        
        map.insert("Bootstrap", vec![
            r"bootstrap.css",
            r"bootstrap.min.css",
        ]);
        
        map.insert("Laravel", vec![
            r"laravel_session",
            r"X-XSRF-TOKEN",
        ]);
        
        map.insert("Spring", vec![
            r"X-Application-Context",
            r"org.springframework",
        ]);
        
        map.insert("Tomcat", vec![
            r"Apache Tomcat",
        ]);
        
        map.insert("WebLogic", vec![
            r"WebLogic Server",
        ]);
        
        map
    };
}

pub async fn scan(
    services: &[&ServiceInfo],
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<WebFingerprint>, Box<dyn std::error::Error>> {
    if services.is_empty() {
        return Ok(Vec::new());
    }
    
    info!("Starting web fingerprinting for {} services...", services.len());
    
    let pb = utils::create_progress_bar(services.len() as u64, "Web fingerprinting");
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // HTTP客户端
    let client = reqwest::Client::builder()
        .timeout(timeout_duration)
        .danger_accept_invalid_certs(true) // 忽略SSL证书错误
        .build()?;
    
    // 分块处理
    let chunk_size = (services.len() + threads - 1) / threads;
    let chunks: Vec<Vec<&ServiceInfo>> = services
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    for chunk in chunks {
        let tx = tx.clone();
        let client = client.clone();
        let pb = pb.clone();
        
        tokio::spawn(async move {
            for service in chunk {
                if let Some(fingerprint) = identify_web_technology(
                    service.ip,
                    service.port,
                    &client,
                    timeout_duration
                ).await {
                    let _ = tx.send(fingerprint).await;
                }
                pb.inc(1);
            }
        });
    }
    
    // 丢弃原始发送者
    drop(tx);
    
    // 收集结果
    let mut fingerprints = Vec::new();
    while let Some(fingerprint) = rx.recv().await {
        fingerprints.push(fingerprint);
    }
    
    pb.finish_with_message(format!("Identified {} web technologies", fingerprints.len()));
    
    Ok(fingerprints)
}

async fn identify_web_technology(
    ip: std::net::IpAddr,
    port: u16,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Option<WebFingerprint> {
    // 构建URL
    let protocol = if port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    };
    
    let url = format!("{}://{}:{}", protocol, ip, port);
    
    // 发送请求
    let resp_result = timeout(
        timeout_duration,
        client.get(&url).send()
    ).await;
    
    match resp_result {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let server = resp.headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            
            // 获取响应内容
            let body_result = timeout(
                timeout_duration,
                resp.text()
            ).await;
            
            let body = match body_result {
                Ok(Ok(body)) => body,
                _ => String::new(),
            };
            
            // 提取标题
            let title = extract_title(&body);
            
            // 识别技术
            let technologies = identify_technologies(&body, &server);
            
            Some(WebFingerprint {
                ip,
                port,
                url,
                title,
                server,
                technologies,
                status_code: status,
            })
        },
        _ => None,
    }
}

fn extract_title(html: &str) -> Option<String> {
    lazy_static! {
        static ref TITLE_RE: Regex = Regex::new(r"<title[^>]*>(.*?)</title>").unwrap();
    }
    
    TITLE_RE.captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn identify_technologies(html: &str, server: &Option<String>) -> Vec<String> {
    let mut techs = Vec::new();
    
    // 检查HTML内容
    for (tech, patterns) in TECH_FINGERPRINTS.iter() {
        'patterns: for pattern in patterns {
            // 创建正则表达式
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(html) {
                    techs.push(tech.to_string());
                    break 'patterns; // 一旦找到匹配，就跳出内部循环
                }
            }
        }
    }
    
    // 检查Server头
    if let Some(server_str) = server {
        let server_lower = server_str.to_lowercase();
        
        if server_lower.contains("apache") {
            techs.push("Apache".to_string());
        }
        
        if server_lower.contains("nginx") {
            techs.push("Nginx".to_string());
        }
        
        if server_lower.contains("iis") {
            techs.push("IIS".to_string());
        }
        
        if server_lower.contains("tomcat") {
            techs.push("Tomcat".to_string());
        }
        
        if server_lower.contains("weblogic") {
            techs.push("WebLogic".to_string());
        }
    }
    
    // 去重
    techs.sort();
    techs.dedup();
    
    techs
}
