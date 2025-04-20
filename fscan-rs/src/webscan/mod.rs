// src/webscan/mod.rs
pub mod fingerprint;
pub mod pocs;

use crate::scanner::ServiceInfo;

#[derive(Debug, Clone)]
pub struct WebFingerprint {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub url: String,
    pub title: Option<String>,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub status_code: u16,
}

#[derive(Debug, Clone)]
pub struct WebVulnerability {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub url: String,
    pub name: String,
    pub description: String,
    pub severity: String, // 严重程度: critical, high, medium, low, info
    pub poc_type: String, // xray or nuclei
    pub poc_id: String,   // POC的唯一标识
    pub details: Option<String>,
}
