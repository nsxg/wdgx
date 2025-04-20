pub mod alive;
pub mod port;
pub mod service;

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub service: String,
    pub banner: String,
    pub version: Option<String>,
}
