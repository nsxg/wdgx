// src/output/report.rs
use std::net::IpAddr;
use std::path::Path;
use chrono::Local;
use serde::Serialize;
use crate::brute::BruteResult;
use crate::scanner::ServiceInfo;
use crate::webscan::WebVulnerability;
use crate::output::file;

#[derive(Serialize)]
struct Report {
    timestamp: String,
    summary: Summary,
    alive_hosts: Vec<IpAddr>,
    services: Vec<ServiceInfo>,
    vulnerabilities: Vec<String>,
    credentials: Vec<BruteResult>,
    web_vulnerabilities: Vec<WebVulnerability>,
    other_findings: Vec<String>,
}

#[derive(Serialize)]
struct Summary {
    total_hosts: usize,
    alive_hosts: usize,
    services: usize,
    vulnerabilities: usize,
    credentials: usize,
    web_vulnerabilities: usize,
}

pub fn generate(
    output_path: &Path,
    alive_hosts: &[IpAddr],
    services: &[ServiceInfo],
    vulnerabilities: &[String],
    credentials: &[BruteResult],
    web_vulnerabilities: &[WebVulnerability],
    other_findings: &[String],
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建报告
    let report = Report {
        timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        summary: Summary {
            total_hosts: alive_hosts.len(),
            alive_hosts: alive_hosts.len(),
            services: services.len(),
            vulnerabilities: vulnerabilities.len(),
            credentials: credentials.len(),
            web_vulnerabilities: web_vulnerabilities.len(),
        },
        alive_hosts: alive_hosts.to_vec(),
        services: services.to_vec(),
        vulnerabilities: vulnerabilities.to_vec(),
        credentials: credentials.to_vec(),
        web_vulnerabilities: web_vulnerabilities.to_vec(),
        other_findings: other_findings.to_vec(),
    };
    
    // 根据格式生成报告
    match format.to_lowercase().as_str() {
        "json" => generate_json_report(output_path, &report)?,
        "csv" => generate_csv_report(output_path, &report)?,
        _ => generate_text_report(output_path, &report)?,
    }
    
    Ok(())
}

fn generate_text_report(
    output_path: &Path,
    report: &Report,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::new();
    
    // 标题
    content.push_str(&format!("# FSCAN-RS SCAN REPORT\n"));
    content.push_str(&format!("Date: {}\n\n", report.timestamp));
    
    // 摘要
    content.push_str("## SUMMARY\n");
    content.push_str(&format!("Total Hosts: {}\n", report.summary.total_hosts));
    content.push_str(&format!("Alive Hosts: {}\n", report.summary.alive_hosts));
    content.push_str(&format!("Services: {}\n", report.summary.services));
    content.push_str(&format!("Vulnerabilities: {}\n", report.summary.vulnerabilities));
    content.push_str(&format!("Credentials: {}\n", report.summary.credentials));
    content.push_str(&format!("Web Vulnerabilities: {}\n\n", report.summary.web_vulnerabilities));
    
    // 存活主机
    content.push_str("## ALIVE HOSTS\n");
    for host in &report.alive_hosts {
        content.push_str(&format!("- {}\n", host));
    }
    content.push_str("\n");
    
    // 开放服务
    content.push_str("## SERVICES\n");
    for service in &report.services {
        content.push_str(&format!("- {}:{} - {}\n", service.ip, service.port, service.service));
        if let Some(version) = &service.version {
            content.push_str(&format!("  Version: {}\n", version));
        }
        if !service.banner.is_empty() {
            let banner_short = if service.banner.len() > 100 {
                format!("{}...", &service.banner[..100])
            } else {
                service.banner.clone()
            };
            content.push_str(&format!("  Banner: {}\n", banner_short));
        }
    }
    content.push_str("\n");
    
    // 漏洞
    if !report.vulnerabilities.is_empty() {
        content.push_str("## VULNERABILITIES\n");
        for vuln in &report.vulnerabilities {
            content.push_str(&format!("- {}\n", vuln));
        }
        content.push_str("\n");
    }
    
    // 凭证
    if !report.credentials.is_empty() {
        content.push_str("## CREDENTIALS\n");
        for cred in &report.credentials {
            content.push_str(&format!(
                "- {}:{} - {} - username: '{}', password: '{}'\n", 
                cred.ip, 
                cred.port, 
                cred.service,
                cred.username,
                cred.password
            ));
            if let Some(details) = &cred.details {
                content.push_str(&format!("  Details: {}\n", details));
            }
        }
        content.push_str("\n");
    }
    
    // Web漏洞
    if !report.web_vulnerabilities.is_empty() {
        content.push_str("## WEB VULNERABILITIES\n");
        for vuln in &report.web_vulnerabilities {
            content.push_str(&format!(
                "- {}:{} - {}\n", 
                vuln.ip, 
                vuln.port, 
                vuln.name
            ));
            content.push_str(&format!("  URL: {}\n", vuln.url));
            content.push_str(&format!("  Severity: {}\n", vuln.severity));
            content.push_str(&format!("  Type: {} ({})\n", vuln.poc_type, vuln.poc_id));
            content.push_str(&format!("  Description: {}\n", vuln.description));
            if let Some(details) = &vuln.details {
                content.push_str(&format!("  Details: {}\n", details));
            }
        }
        content.push_str("\n");
    }
    
    // 其他发现
    if !report.other_findings.is_empty() {
        content.push_str("## OTHER FINDINGS\n");
        for finding in &report.other_findings {
            content.push_str(&format!("- {}\n", finding));
        }
        content.push_str("\n");
    }
    
    // 写入文件
    file::write_to_file(output_path, &content)?;
    
    Ok(())
}

fn generate_json_report(
    output_path: &Path,
    report: &Report,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(report)?;
    file::write_to_file(output_path, &json)?;
    Ok(())
}

fn generate_csv_report(
    output_path: &Path,
    report: &Report,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::new();
    
    // 存活主机
    content.push_str("# ALIVE HOSTS\n");
    content.push_str("IP\n");
    for host in &report.alive_hosts {
        content.push_str(&format!("{}\n", host));
    }
    content.push_str("\n");
    
    // 开放服务
    content.push_str("# SERVICES\n");
    content.push_str("IP,Port,Service,Version,Banner\n");
    for service in &report.services {
        let version = service.version.as_deref().unwrap_or("");
        let banner = service.banner.replace(",", ";").replace("\n", " ");
        content.push_str(&format!(
            "{},{},{},{},{}\n", 
            service.ip, 
            service.port, 
            service.service,
            version,
            if banner.len() > 100 { banner[..100].to_string() } else { banner }
        ));
    }
    content.push_str("\n");
    
    // 漏洞
    if !report.vulnerabilities.is_empty() {
        content.push_str("# VULNERABILITIES\n");
        content.push_str("Description\n");
        for vuln in &report.vulnerabilities {
            content.push_str(&format!("{}\n", vuln.replace(",", ";")));
        }
        content.push_str("\n");
    }
    
    // 凭证
    if !report.credentials.is_empty() {
        content.push_str("# CREDENTIALS\n");
        content.push_str("IP,Port,Service,Username,Password,Details\n");
        for cred in &report.credentials {
            let details = cred.details.as_deref().unwrap_or("").replace(",", ";");
            content.push_str(&format!(
                "{},{},{},{},{},{}\n", 
                cred.ip, 
                cred.port, 
                cred.service,
                cred.username.replace(",", ";"),
                cred.password.replace(",", ";"),
                details
            ));
        }
        content.push_str("\n");
    }
    
    // Web漏洞
    if !report.web_vulnerabilities.is_empty() {
        content.push_str("# WEB VULNERABILITIES\n");
        content.push_str("IP,Port,URL,Name,Severity,Type,ID,Description,Details\n");
        for vuln in &report.web_vulnerabilities {
            let details = vuln.details.as_deref().unwrap_or("").replace(",", ";").replace("\n", " ");
            content.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n", 
                vuln.ip, 
                vuln.port, 
                vuln.url.replace(",", ";"),
                vuln.name.replace(",", ";"),
                vuln.severity,
                vuln.poc_type,
                vuln.poc_id,
                vuln.description.replace(",", ";").replace("\n", " "),
                details
            ));
        }
    }
    
    // 写入文件
    file::write_to_file(output_path, &content)?;
    
    Ok(())
}
