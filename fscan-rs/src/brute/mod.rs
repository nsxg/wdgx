// src/brute/mod.rs
pub mod ssh;
pub mod ftp;
pub mod mysql;
pub mod mssql;
pub mod redis;
pub mod smb;
pub mod mongodb;
pub mod postgres;
pub mod oracle;

#[derive(Debug, Clone)]
pub struct BruteResult {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub service: String,
    pub username: String,
    pub password: String,
    pub details: Option<String>,
}
