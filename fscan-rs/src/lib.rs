// src/lib.rs
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use std::str::FromStr;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use ipnet::IpNet;
use std::io::{Read, Write};

// 导出公共结构体和函数
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    pub is_open: bool,
    pub version: Option<String>,
    pub cve: Vec<String>,
}

// IP和端口范围解析模块
pub mod utils {
    use super::*;
    
    // 解析IP范围(单IP、CIDR格式或IP范围)
    pub fn parse_ip_range(range: &str) -> Vec<String> {
        let mut ips = Vec::new();
        
        // 处理CIDR格式 (例如 192.168.1.0/24)
        if range.contains('/') {
            match range.parse::<IpNet>() {
                Ok(net) => {
                    for ip in net.hosts() {
                        ips.push(ip.to_string());
                    }
                },
                Err(_) => {
                    // 如果不是有效的CIDR，就当作单个IP处理
                    ips.push(range.to_string());
                }
            }
        } else if range.contains('-') {
            // 处理范围格式 (例如 192.168.1.1-192.168.1.10)
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (
                    IpAddr::from_str(parts[0].trim()),
                    IpAddr::from_str(parts[1].trim()),
                ) {
                    if let (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) = (start, end) {
                        let start_num = u32::from(start_v4);
                        let end_num = u32::from(end_v4);
                        
                        for i in start_num..=end_num {
                            let octets = [
                                (i >> 24) as u8,
                                (i >> 16) as u8,
                                (i >> 8) as u8,
                                i as u8,
                            ];
                            ips.push(IpAddr::from(octets).to_string());
                        }
                    }
                }
            }
        } else {
            // 单个IP
            ips.push(range.to_string());
        }
        
        ips
    }
    
    // 解析端口范围(单端口、端口列表或端口范围)
    pub fn parse_port_range(range: &str) -> Vec<u16> {
        let mut ports = Vec::new();
        
        for part in range.split(',') {
            if part.contains('-') {
                // 处理范围格式 (例如 80-100)
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        range_parts[0].trim().parse::<u16>(),
                        range_parts[1].trim().parse::<u16>(),
                    ) {
                        for port in start..=end {
                            ports.push(port);
                        }
                    }
                }
            } else {
                // 单个端口
                if let Ok(port) = part.trim().parse::<u16>() {
                    ports.push(port);
                }
            }
        }
        
        ports
    }

    // 检查主机是否存活 (使用简单的TCP ping)
    pub fn is_host_alive(ip: &str, timeout_ms: u64) -> bool {
        // 尝试连接常见端口
        for port in [80, 443, 22, 445] {
            let addr = match IpAddr::from_str(ip) {
                Ok(addr) => addr,
                Err(_) => return false,
            };
            
            let socket_addr = SocketAddr::new(addr, port);
            if TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)).is_ok() {
                return true;
            }
        }
        false
    }
}

// 网络扫描模块
pub mod scan {
    use super::*;
    
    // 检查单个端口是否开放
    pub fn scan_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
        let addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        let socket_addr = SocketAddr::new(addr, port);
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    // 识别服务并获取banner
    pub fn identify_service(ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceInfo> {
        if !scan_port(ip, port, timeout_ms) {
            return None;
        }
        
        // 简单的服务识别逻辑
        let service = match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 | 8080 | 8000 => "http",
            443 | 8443 => "https",
            139 | 445 => "smb",
            1433 => "mssql",
            3306 => "mysql",
            5432 => "postgres",
            6379 => "redis",
            27017 => "mongodb",
            1521 => "oracle",
            _ => "unknown",
        };
        
        // 尝试获取服务banner
        let banner = get_banner(ip, port, service, timeout_ms);
        
        // 尝试识别版本信息
        let version = extract_version(&banner);
        
        // 检查是否存在已知漏洞
        let cve = check_vulnerabilities(service, &version);
        
        Some(ServiceInfo {
            ip: ip.to_string(),
            port,
            service: service.to_string(),
            banner,
            is_open: true,
            version,
            cve,
        })
    }
    
    // 根据服务类型获取banner
    fn get_banner(ip: &str, port: u16, service: &str, timeout_ms: u64) -> Option<String> {
        let addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        let socket_addr = SocketAddr::new(addr, port);
        
        match service {
            "http" | "https" => get_http_banner(ip, port, timeout_ms),
            "ssh" => get_ssh_banner(ip, port, timeout_ms),
            "ftp" => get_ftp_banner(ip, port, timeout_ms),
            "smtp" => get_smtp_banner(ip, port, timeout_ms),
            _ => {
                // 通用Banner获取
                match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
                    Ok(mut stream) => {
                        // 设置读取超时
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
                        
                        // 简单的banner获取逻辑
                        let mut buffer = [0; 1024];
                        match stream.read(&mut buffer) {
                            Ok(size) if size > 0 => {
                                // 尝试将buffer转为字符串
                                if let Ok(banner) = String::from_utf8(buffer[..size].to_vec()) {
                                    return Some(banner.trim().to_string());
                                }
                            },
                            _ => {}
                        }
                        None
                    },
                    Err(_) => None,
                }
            }
        }
    }

    // HTTP服务Banner获取
    fn get_http_banner(ip: &str, port: u16, timeout_ms: u64) -> Option<String> {
        let addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        let socket_addr = SocketAddr::new(addr, port);
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(mut stream) => {
                // 设置超时
                let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
                
                // 发送HTTP HEAD请求
                let request = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", ip);
                if stream.write_all(request.as_bytes()).is_err() {
                    return None;
                }
                
                // 读取响应头
                let mut buffer = [0; 4096];
                match stream.read(&mut buffer) {
                    Ok(size) if size > 0 => {
                        if let Ok(response) = String::from_utf8(buffer[..size].to_vec()) {
                            // 提取Server头
                            for line in response.lines() {
                                if line.to_lowercase().starts_with("server:") {
                                    return Some(line.trim().to_string());
                                }
                            }
                            return Some(response.lines().next().unwrap_or("").to_string());
                        }
                    },
                    _ => {}
                }
                None
            },
            Err(_) => None,
        }
    }

    // SSH服务Banner获取
    fn get_ssh_banner(ip: &str, port: u16, timeout_ms: u64) -> Option<String> {
        let addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        let socket_addr = SocketAddr::new(addr, port);
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(mut stream) => {
                // 设置超时
                let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
                
                // 读取SSH banner
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(size) if size > 0 => {
                        if let Ok(banner) = String::from_utf8(buffer[..size].to_vec()) {
                            return Some(banner.trim().to_string());
                        }
                    },
                    _ => {}
                }
                None
            },
            Err(_) => None,
        }
    }

    // FTP服务Banner获取
    fn get_ftp_banner(ip: &str, port: u16, timeout_ms: u64) -> Option<String> {
        let addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        let socket_addr = SocketAddr::new(addr, port);
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(mut stream) => {
                // 设置超时
                let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
                
                // 读取FTP banner
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(size) if size > 0 => {
                        if let Ok(banner) = String::from_utf8(buffer[..size].to_vec()) {
                            return Some(banner.trim().to_string());
                        }
                    },
                    _ => {}
                }
                None
            },
            Err(_) => None,
        }
    }

    // SMTP服务Banner获取
    fn get_smtp_banner(ip: &str, port: u16, timeout_ms: u64) -> Option<String> {
        let addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        let socket_addr = SocketAddr::new(addr, port);
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(mut stream) => {
                // 设置超时
                let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
                
                // 读取SMTP banner
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(size) if size > 0 => {
                        if let Ok(banner) = String::from_utf8(buffer[..size].to_vec()) {
                            return Some(banner.trim().to_string());
                        }
                    },
                    _ => {}
                }
                None
            },
            Err(_) => None,
        }
    }
    
    // 从Banner中提取版本信息
    fn extract_version(banner: &Option<String>) -> Option<String> {
        if let Some(banner_str) = banner {
            // 通用版本号匹配模式
            let version_patterns = [
                r"(?i)version[:\s]+([0-9]+(?:\.[0-9]+)+)",
                r"(?i)([0-9]+(?:\.[0-9]+){1,})",
                r"(?i)/([0-9]+(?:\.[0-9]+)+)"
            ];
            
            for pattern in version_patterns {
                // 使用常规字符串方法匹配
                if let Some(start) = banner_str.to_lowercase().find(&pattern.to_lowercase()) {
                    let remaining = &banner_str[start..];
                    if let Some(end) = remaining.find(|c: char| !c.is_digit(10) && c != '.') {
                        let version = &remaining[..end];
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }
    
    // 检查已知漏洞
    fn check_vulnerabilities(service: &str, version: &Option<String>) -> Vec<String> {
        let mut vulnerabilities = Vec::new();
        
        // 这里应该有一个漏洞数据库或API调用
        // 以下是简单示例
        if let Some(ver) = version {
            match service {
                "ssh" => {
                    if ver.starts_with("5.") || ver.starts_with("6.") {
                        vulnerabilities.push("CVE-2018-15473".to_string());
                    }
                },
                "http" => {
                    if ver.contains("1.0") {
                        vulnerabilities.push("CVE-2019-0211".to_string());
                    }
                },
                "ftp" => {
                    if ver.starts_with("2.3.4") {
                        vulnerabilities.push("CVE-2013-4559".to_string());
                    }
                },
                _ => {}
            }
        }
        
        vulnerabilities
    }
    
    // 多线程扫描
    pub fn scan_ports_threaded(ip: &str, ports: Vec<u16>, timeout_ms: u64, threads: usize) -> Vec<ServiceInfo> {
        let ports = Arc::new(Mutex::new(ports));
        let results = Arc::new(Mutex::new(Vec::new()));
        let ip = ip.to_string();
        
        let mut handles = vec![];
        
        for _ in 0..threads {
            let ports_clone = Arc::clone(&ports);
            let results_clone = Arc::clone(&results);
            let ip_clone = ip.clone();
            
            let handle = thread::spawn(move || {
                loop {
                    // 获取下一个要扫描的端口
                    let port = {
                        let mut ports = ports_clone.lock().unwrap();
                        if ports.is_empty() {
                            break;
                        }
                        ports.pop().unwrap()
                    };
                    
                    // 扫描端口
                    if let Some(service_info) = identify_service(&ip_clone, port, timeout_ms) {
                        let mut results = results_clone.lock().unwrap();
                        results.push(service_info);
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // 等待所有线程完成
        for handle in handles {
            let _ = handle.join();
        }
        
        // 返回结果
        let results = Arc::try_unwrap(results)
            .expect("还有其他线程持有results的引用")
            .into_inner()
            .expect("无法解锁results");
        
        results
    }
    
    // 扫描多个IP
    pub fn scan_ips(ips: Vec<String>, ports: Vec<u16>, timeout_ms: u64, threads: usize, skip_ping: bool) -> HashMap<String, Vec<ServiceInfo>> {
        let mut results = HashMap::new();
        
        for ip in ips {
            // 检查主机是否存活（除非跳过ping检查）
            if !skip_ping && !utils::is_host_alive(&ip, timeout_ms) {
                continue;
            }
            
            let services = scan_ports_threaded(&ip, ports.clone(), timeout_ms, threads);
            if !services.is_empty() {
                results.insert(ip, services);
            }
        }
        
        results
    }
}

// 暴力破解模块
pub mod brute {
    use super::*;
    
    // SSH暴力破解
    pub fn brute_ssh(service: &ServiceInfo, user: &str, pass: &str, timeout_ms: u64) -> bool {
        let addr = match IpAddr::from_str(&service.ip) {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        let socket_addr = SocketAddr::new(addr, service.port);
        
        // 尝试建立TCP连接
        if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            // 设置超时
            let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
            
            // 读取SSH banner
            let mut buffer = [0; 1024];
            if stream.read(&mut buffer).is_err() {
                return false;
            }
            
            // 这里应该有完整的SSH认证逻辑
            // 简单模拟：如果用户名是"admin"且密码是"password"，则认为成功
            return user == "admin" && pass == "password";
        }
        
        false
    }
    
    // FTP暴力破解
    pub fn brute_ftp(service: &ServiceInfo, user: &str, pass: &str, timeout_ms: u64) -> bool {
        let addr = match IpAddr::from_str(&service.ip) {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        let socket_addr = SocketAddr::new(addr, service.port);
        
        // 尝试建立TCP连接
        if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            // 设置超时
            let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
            
            // 读取FTP banner
            let mut buffer = [0; 1024];
            if stream.read(&mut buffer).is_err() {
                return false;
            }
            
            // 发送用户名
            let user_cmd = format!("USER {}\r\n", user);
            if stream.write_all(user_cmd.as_bytes()).is_err() {
                return false;
            }
            
            // 读取响应
            if stream.read(&mut buffer).is_err() {
                return false;
            }
            
            // 发送密码
            let pass_cmd = format!("PASS {}\r\n", pass);
            if stream.write_all(pass_cmd.as_bytes()).is_err() {
                return false;
            }
            
            // 读取响应
            if let Ok(size) = stream.read(&mut buffer) {
                if let Ok(response) = String::from_utf8(buffer[..size].to_vec()) {
                    // 检查是否登录成功
                    return response.contains("230") || response.contains("Login successful");
                }
            }
        }
        
        false
    }
    
    // MySQL暴力破解
    pub fn brute_mysql(service: &ServiceInfo, user: &str, pass: &str, _timeout_ms: u64) -> bool {
        // 简单模拟
        println!("尝试MySQL破解: {}:{} 用户: {} 密码: {}", service.ip, service.port, user, pass);
        false
    }
    
    // 批量尝试用户名密码列表
    pub fn brute_force(service: &ServiceInfo, users: &[String], passwords: &[String], timeout_ms: u64) -> Option<(String, String)> {
        for user in users {
            for pass in passwords {
                let success = match service.service.as_str() {
                    "ssh" => brute_ssh(service, user, pass, timeout_ms),
                    "ftp" => brute_ftp(service, user, pass, timeout_ms),
                    "mysql" => brute_mysql(service, user, pass, timeout_ms),
                    _ => false
                };
                
                if success {
                    return Some((user.clone(), pass.clone()));
                }
            }
        }
        
        None
    }
}

// 漏洞利用模块
pub mod exploit {
    use super::*;
    
    // 返回已知漏洞列表
    pub fn find_vulnerabilities(service: &ServiceInfo) -> Vec<String> {
        service.cve.clone()
    }
    
    // 尝试利用漏洞
    pub fn try_exploit(service: &ServiceInfo, cve: &str) -> bool {
        println!("尝试利用 {}:{} 的漏洞 {}", service.ip, service.port, cve);
        
        // 实际漏洞利用逻辑应该放在这里
        match cve {
            "CVE-2018-15473" => {
                println!("SSH用户枚举漏洞检测中...");
                // 模拟漏洞检测
                false
            },
            "CVE-2019-0211" => {
                println!("Apache HTTP服务器ROOT提权漏洞检测中...");
                // 模拟漏洞检测
                false
            },
            _ => false
        }
    }
}
