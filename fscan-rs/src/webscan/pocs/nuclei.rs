// src/webscan/pocs/nuclei.rs
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use log::{debug, info, error};
use regex::Regex;
use serde_json::Value;
use reqwest::StatusCode;
use crate::common::utils;
use crate::scanner::ServiceInfo;
use crate::webscan::WebVulnerability;
use crate::webscan::pocs::loader::{NucleiPoc, load_nuclei_pocs, NucleiMatcher};

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
    let pocs = load_nuclei_pocs(pocs_dir);
    
    if pocs.is_empty() {
        info!("No Nuclei POCs loaded, skipping Nuclei POC scanning");
        return Ok(Vec::new());
    }
    
    info!("Starting Nuclei POC scanning for {} HTTP services with {} POCs...", http_services.len(), pocs.len());
    
    // 计算总任务数
    let total_tasks = http_services.len() * pocs.len();
    let pb = utils::create_progress_bar(total_tasks as u64, "Nuclei POC scanning");
    
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
                if let Some(vuln) = execute_nuclei_poc(
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
    
    pb.finish_with_message(format!("Found {} vulnerabilities using Nuclei POCs", vulnerabilities.len()));
    
    Ok(vulnerabilities)
}

async fn execute_nuclei_poc(
    ip: IpAddr,
    port: u16,
    base_url: &str,
    poc: &NucleiPoc,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Option<WebVulnerability> {
    // 变量集合，用于替换模板
    let mut variables = HashMap::new();
    
    // 将基本URL和IP添加到变量中
    variables.insert("BaseURL".to_string(), base_url.to_string());
    variables.insert("Hostname".to_string(), ip.to_string());
    variables.insert("Port".to_string(), port.to_string());
    
    // 执行请求
    for request in &poc.requests {
        let is_vulnerable = execute_nuclei_request(
            base_url,
            request,
            &mut variables,
            client,
            timeout_duration,
        ).await;
        
        if is_vulnerable {
            // 提取漏洞信息
            let severity = poc.info.severity.clone().unwrap_or_else(|| "medium".to_string());
            let description = poc.info.description.clone().unwrap_or_else(|| "No description".to_string());
            
            // 构建详细信息
            let mut details = String::new();
            if let Some(refs) = &poc.info.reference {
                details.push_str("References:\n");
                for reference in refs {
                    details.push_str(&format!("- {}\n", reference));
                }
            }
            
            if let Some(tags) = &poc.info.tags {
                details.push_str("Tags: ");
                details.push_str(&tags.join(", "));
            }
            
            return Some(WebVulnerability {
                ip,
                port,
                url: base_url.to_string(),
                name: poc.info.name.clone(),
                description,
                severity,
                poc_type: "nuclei".to_string(),
                poc_id: poc.id.clone(),
                details: Some(details),
            });
        }
    }
    
    None
}

async fn execute_nuclei_request(
    base_url: &str,
    request: &crate::webscan::pocs::loader::NucleiRequest,
    variables: &mut HashMap<String, String>,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> bool {
    let method = request.method.as_deref().unwrap_or("GET");
    
    // 尝试每个路径
    for path in &request.path {
        // 替换变量
        let path = replace_variables(path, variables);
        let url = if path.starts_with("http") {
            path
        } else {
            format!("{}{}", base_url.trim_end_matches('/'), path)
        };
        
        // 构建请求
        let mut req = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            "HEAD" => client.head(&url),
            _ => client.get(&url),
        };
        
        // 添加请求头
        if let Some(headers) = &request.headers {
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
        if let Some(body) = &request.body {
            let body_str = replace_variables(body, variables);
            req = req.body(body_str);
        }
        
        // 发送请求
        let resp_result = timeout(
            timeout_duration,
            req.send()
        ).await;
        
        match resp_result {
            Ok(Ok(resp)) => {
                // 获取状态码和响应头
                let status = resp.status();
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
                variables.insert("status_code".to_string(), status.as_u16().to_string());
                
                for (key, value) in headers.iter() {
                    if let Ok(value_str) = value.to_str() {
                        variables.insert(format!("header_{}", key.as_str()), value_str.to_string());
                    }
                }
                
                // 检查匹配条件
                if match_nuclei_condition(status, &headers, &body, &request.matchers) {
                    return true;
                }
            },
            _ => {
                // 请求失败则尝试下一个路径
                continue;
            }
        }
    }
    
    false
}

fn replace_variables(input: &str, variables: &HashMap<String, String>) -> String {
    let mut result = input.to_string();
    
    for (key, value) in variables {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }
    
    result
}

fn match_nuclei_condition(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: &str,
    matchers: &Vec<NucleiMatcher>,
) -> bool {
    // 如果没有匹配器，默认不匹配
    if matchers.is_empty() {
        return false;
    }
    
    // 检查每个匹配器
    for matcher in matchers {
        let matched = match matcher.matcher_type.as_str() {
            "status" => {
                if let Some(status_list) = &matcher.status {
                    status_list.contains(&status.as_u16())
                } else {
                    false
                }
            },
            "word" => {
                if let Some(words) = &matcher.words {
                    let part = matcher.part.as_deref().unwrap_or("body");
                    match part {
                        "body" => words.iter().any(|word| body.contains(word)),
                        "header" => {
                            if let Some(header_name) = words.first() {
                                if let Some(header_value) = headers.get(header_name) {
                                    if let Ok(header_str) = header_value.to_str() {
                                        if words.len() > 1 {
                                            words[1..].iter().any(|word| header_str.contains(word))
                                        } else {
                                            true
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        },
                        _ => false,
                    }
                } else {
                    false
                }
            },
            "regex" => {
                if let Some(regexes) = &matcher.regex {
                    let part = matcher.part.as_deref().unwrap_or("body");
                    match part {
                        "body" => {
                            regexes.iter().any(|regex_str| {
                                if let Ok(re) = Regex::new(regex_str) {
                                    re.is_match(body)
                                } else {
                                    false
                                }
                            })
                        },
                        "header" => {
                            if let Some(header_name) = regexes.first() {
                                if let Some(header_value) = headers.get(header_name) {
                                    if let Ok(header_str) = header_value.to_str() {
                                        if regexes.len() > 1 {
                                            regexes[1..].iter().any(|regex_str| {
                                                if let Ok(re) = Regex::new(regex_str) {
                                                    re.is_match(header_str)
                                                } else {
                                                    false
                                                }
                                            })
                                        } else {
                                            true
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        },
                        _ => false,
                    }
                } else {
                    false
                }
            },
            _ => false,
        };
        
        // 根据条件判断是否匹配
        let condition = matcher.condition.as_deref().unwrap_or("or");
        match condition {
            "and" => {
                if !matched {
                    return false;
                }
            },
            _ => {
                if matched {
                    return true;
                }
            },
        }
    }
    
    // 如果所有"and"条件都匹配，或者有任何"or"条件匹配
    let all_and = matchers.iter().all(|m| m.condition.as_deref().unwrap_or("or") == "and");
    all_and
}
