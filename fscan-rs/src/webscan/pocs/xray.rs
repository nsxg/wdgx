// src/webscan/pocs/xray.rs
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use regex::Regex;
use serde_json::Value;
use crate::common::utils;
use crate::scanner::ServiceInfo;
use crate::webscan::WebVulnerability;
use crate::webscan::pocs::loader::{XrayPoc, load_xray_pocs};

pub async fn scan(
    services: &[&ServiceInfo],
    pocs_dir: Option<&Path>,
    timeout_secs: u64,
    threads: usize,
) -> Result<Vec<WebVulnerability>, Box<dyn std::error::Error>> {
    // 过滤HTTP服务
    let http_services: Vec<&ServiceInfo> = services
        .iter()
        .filter(|s| s.service.contains("http") || s.port == 80 || s.port == 443 || s.port == 8080 || s.port == 8443)
        .copied()
        .collect();
    
    if http_services.is_empty() {
        return Ok(Vec::new());
    }
    
    // 加载POCs
    let pocs = load_xray_pocs(pocs_dir);
    
    if pocs.is_empty() {
        info!("No Xray POCs loaded, skipping Xray POC scanning");
        return Ok(Vec::new());
    }
    
    info!("Starting Xray POC scanning for {} HTTP services with {} POCs...", http_services.len(), pocs.len());
    
    // 计算总任务数
    let total_tasks = http_services.len() * pocs.len();
    let pb = utils::create_progress_bar(total_tasks as u64, "Xray POC scanning");
    
    let (tx, mut rx) = mpsc::channel(threads);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    // HTTP客户端
    let client = reqwest::Client::builder()
        .timeout(timeout_duration)
        .danger_accept_invalid_certs(true) // 忽略SSL证书错误
        .build()?;
    
    // 创建任务
    for service in http_services {
        // 构建基础URL
        let protocol = if service.port == 443 || service.port == 8443 {
            "https"
        } else {
            "http"
        };
        
        let base_url = format!("{}://{}:{}", protocol, service.ip, service.port);
        
        for poc in &pocs {
            let client = client.clone();
            let tx = tx.clone();
            let base_url = base_url.clone();
            let poc = poc.clone();
            let pb = pb.clone();
            let timeout_duration = timeout_duration;
            
            tokio::spawn(async move {
                if let Some(vuln) = execute_xray_poc(
                    service.ip,
                    service.port,
                    &base_url,
                    &poc,
                    &client,
                    timeout_duration,
                ).await {
                    let _ = tx.send(vuln).await;
                }
                pb.inc(1);
            });
        }
    }
    
    // 丢弃原始发送者
    drop(tx);
    
    // 收集结果
    let mut vulnerabilities = Vec::new();
    while let Some(vuln) = rx.recv().await {
        vulnerabilities.push(vuln);
    }
    
    pb.finish_with_message(format!("Found {} vulnerabilities using Xray POCs", vulnerabilities.len()));
    
    Ok(vulnerabilities)
}

async fn execute_xray_poc(
    ip: IpAddr,
    port: u16,
    base_url: &str,
    poc: &XrayPoc,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Option<WebVulnerability> {
    // 变量集合，用于替换模板
    let mut variables = HashMap::new();
    
    // 初始化变量
    if let Some(set) = &poc.set {
        if let Value::Object(obj) = serde_json::to_value(set).unwrap_or(Value::Null) {
            for (key, value) in obj {
                if let Value::String(s) = value {
                    variables.insert(key, s);
                }
            }
        }
    }
    
    // 执行规则
    let mut rule_results = Vec::new();
    for (i, rule) in poc.rules.iter().enumerate() {
        match execute_rule(
            base_url,
            rule,
            &mut variables,
            client,
            timeout_duration,
        ).await {
            Ok(result) => {
                debug!("Rule {} result: {}", i, result);
                rule_results.push(result);
            },
            Err(e) => {
                debug!("Rule {} error: {}", i, e);
                rule_results.push(false);
            },
        }
    }
    
    // 评估最终表达式
    let is_vulnerable = if let Some(expr) = &poc.expression {
        evaluate_expression(expr, &rule_results)
    } else {
        // 如果没有表达式，任何规则匹配都视为漏洞
        rule_results.iter().any(|&r| r)
    };
    
    if is_vulnerable {
        // 提取漏洞信息
        let severity = poc.info.severity.clone().unwrap_or_else(|| "medium".to_string());
        let description = poc.info.description.clone().unwrap_or_else(|| "No description".to_string());
        
        Some(WebVulnerability {
            ip,
            port,
            url: base_url.to_string(),
            name: poc.name.clone(),
            description,
            severity,
            poc_type: "xray".to_string(),
            poc_id: poc.id.clone().unwrap_or_else(|| "unknown".to_string()),
            details: None,
        })
    } else {
        None
    }
}

async fn execute_rule(
    base_url: &str,
    rule: &crate::webscan::pocs::loader::XrayRule,
    variables: &mut HashMap<String, String>,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Result<bool, Box<dyn std::error::Error>> {
    // 替换变量
    let path = replace_variables(&rule.path, variables);
    let url = if path.starts_with("http") {
        path
    } else {
        format!("{}{}", base_url.trim_end_matches('/'), path)
    };
    
    // 构建请求
    let method = rule.method.as_deref().unwrap_or("GET");
    let mut req = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        _ => client.get(&url),
    };
    
    // 添加请求头
    if let Some(headers) = &rule.headers {
        if let Value::Object(obj) = serde_json::to_value(headers).unwrap_or(Value::Null) {
            for (key, value) in obj {
                if let Value::String(s) = value {
                    let header_value = replace_variables(&s, variables);
                    req = req.header(key, header_value);
                }
            }
        }
    }
    
    // 添加请求体
    if let Some(body) = &rule.body {
        let body_str = replace_variables(body, variables);
        req = req.body(body_str);
    }
    
    // 处理重定向
    if let Some(follow) = rule.follow_redirects {
        req = req.redirect(if follow {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        });
    }
    
    // 发送请求
    let resp_result = timeout(
        timeout_duration,
        req.send()
    ).await;
    
    match resp_result {
        Ok(Ok(resp)) => {
            // 提取响应信息
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            
            // 获取响应内容
            let body_result = timeout(
                timeout_duration,
                resp.text()
            ).await;
            
            let body = match body_result {
                Ok(Ok(body)) => body,
                _ => String::new(),
            };
            
            // 更新变量
            variables.insert("response".to_string(), body.clone());
            variables.insert("status".to_string(), status.to_string());
            
            for (key, value) in headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    variables.insert(format!("header_{}", key.as_str()), value_str.to_string());
                }
            }
            
            // 评估表达式
            let result = evaluate_rule_expression(&rule.expression, status, &body, variables);
            Ok(result)
        },
        _ => {
            // 请求超时或失败
            Ok(false)
        }
    }
}

fn replace_variables(input: &str, variables: &HashMap<String, String>) -> String {
    let mut result = input.to_string();
    
    for (key, value) in variables {
        result = result.replace(&format!("{{{}}}", key), value);
    }
    
    result
}

fn evaluate_rule_expression(
    expression: &str,
    status: u16,
    response: &str,
    variables: &HashMap<String, String>,
) -> bool {
    // 简单表达式处理
    // 实际生产中应使用专业的表达式求值器
    
    // 检查状态码
    if expression.contains("status") {
        if expression.contains(&format!("status=={}", status)) {
            return true;
        }
        
        if expression.contains("status!=200") && status != 200 {
            return true;
        }
    }
    
    // 检查响应内容是否包含特定字符串
    if expression.contains("contains") {
        let re = Regex::new(r#"contains\(['"](.*?)['"]\)"#).unwrap();
        if let Some(caps) = re.captures(expression) {
            if let Some(content) = caps.get(1) {
                let content_str = replace_variables(content.as_str(), variables);
                return response.contains(&content_str);
            }
        }
    }
    
    // 检查正则表达式匹配
    if expression.contains("matches") {
        let re = Regex::new(r#"matches\(['"](.*?)['"]\)"#).unwrap();
        if let Some(caps) = re.captures(expression) {
            if let Some(pattern) = caps.get(1) {
                if let Ok(regex) = Regex::new(pattern.as_str()) {
                    return regex.is_match(response);
                }
            }
        }
    }
    
    false
}

fn evaluate_expression(expression: &str, rule_results: &[bool]) -> bool {
    if expression == "and" {
        return rule_results.iter().all(|&r| r);
    } else if expression == "or" {
        return rule_results.iter().any(|&r| r);
    }
    
    // 处理形如 "r0 && r1" 或 "r0 || r1" 的表达式
    let expr = expression.replace("&&", " and ").replace("||", " or ");
    
    // 替换r0, r1等为实际值
    let re = Regex::new(r"r(\d+)").unwrap();
    let expr = re.replace_all(&expr, |caps: &regex::Captures| {
        let index = caps[1].parse::<usize>().unwrap_or(0);
        if index < rule_results.len() {
            if rule_results[index] { "true" } else { "false" }
        } else {
            "false"
        }
    });
    
    // 简单求值
    if expr.contains(" and ") {
        expr.split(" and ").all(|s| s.trim() == "true")
    } else if expr.contains(" or ") {
        expr.split(" or ").any(|s| s.trim() == "true")
    } else {
        expr.trim() == "true"
    }
}
