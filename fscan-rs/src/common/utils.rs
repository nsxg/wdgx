use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;
use tokio::net::TcpStream;

/// 从文件中读取行
pub fn read_lines_from_file(file_path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            lines.push(line.to_string());
        }
    }
    
    Ok(lines)
}

/// 异步检查TCP端口是否开放
pub async fn check_port_open(ip: IpAddr, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    let timeout_duration = Duration::from_secs(timeout_secs);
    
    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// 创建进度条
pub fn create_progress_bar(total: u64, message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new(total);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=>-")
    );
    pb.set_message(message.to_string());
    pb
}

/// 对字符串进行简单的哈希（用于测试）
pub fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    
    for c in s.bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u64);
    }
    
    hash
}
