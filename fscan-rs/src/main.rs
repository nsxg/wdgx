// src/main.rs
use clap::{App, Arg, ArgGroup};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::Instant;
use std::process;
use std::collections::HashSet;

// 从本地库导入
use fscan_rs::{ServiceInfo, scan, utils, brute, exploit};

fn main() {
    // 解析命令行参数
    let matches = App::new("fscan-rs")
        .version("0.1.0")
        .about("一个用Rust编写的网络扫描器")
        .arg(
            Arg::with_name("target")
                .help("目标IP或IP范围，支持CIDR格式")
                .long("target")
                .short("t")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("target-file")
                .help("包含目标IP的文件(每行一个)")
                .long("target-file")
                .short("f")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port")
                .help("要扫描的端口(例如 80,443,1-1000)")
                .long("port")
                .short("p")
                .default_value("21,22,80,81,135,139,443,445,1433,3306,5432,6379,8080,8443,9000,9001,9090,27017")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("timeout")
                .help("连接超时(毫秒)")
                .long("timeout")
                .short("to")
                .default_value("1000")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("threads")
                .help("并发线程数")
                .long("threads")
                .short("n")
                .default_value("400")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("output")
                .help("输出文件")
                .long("output")
                .short("o")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("format")
                .help("输出格式(text, json)")
                .long("format")
                .possible_values(&["text", "json"])
                .default_value("text")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("skip-ping")
                .help("跳过ping检查")
                .long("skip-ping")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("no-brute")
                .help("禁用暴力破解")
                .long("no-brute")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("no-exploit")
                .help("禁用漏洞检查")
                .long("no-exploit")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("no-web")
                .help("禁用Web扫描")
                .long("no-web")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("no-plugins")
                .help("禁用插件")
                .long("no-plugins")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("verbose")
                .help("详细模式")
                .long("verbose")
                .short("v")
                .multiple(true)
                .takes_value(false)
        )
        .arg(
            Arg::with_name("user-file")
                .help("包含用户名的文件")
                .long("user-file")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("password-file")
                .help("包含密码的文件")
                .long("password-file")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("user")
                .help("用于认证的用户名")
                .long("user")
                .short("u")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("password")
                .help("用于认证的密码")
                .long("password")
                .short("pwd")
                .takes_value(true)
        )
        .group(
            ArgGroup::with_name("targets")
                .args(&["target", "target-file"])
                .required(true)
        )
        .get_matches();

    // 获取参数
    let timeout_ms = matches.value_of("timeout")
        .unwrap_or("1000")
        .parse::<u64>()
        .unwrap_or(1000);
    
    let thread_count = matches.value_of("threads")
        .unwrap_or("400")
        .parse::<usize>()
        .unwrap_or(400);
    
    let ports_str = matches.value_of("port").unwrap();
    let ports = utils::parse_port_range(ports_str);
    
    let skip_ping = matches.is_present("skip-ping");
    let no_brute = matches.is_present("no-brute");
    let no_exploit = matches.is_present("no-exploit");
    let verbose = matches.is_present("verbose");
    
    // 获取目标IPs
    let targets = if matches.is_present("target") {
        let target_str = matches.value_of("target").unwrap();
        utils::parse_ip_range(target_str)
    } else if matches.is_present("target-file") {
        let file_path = matches.value_of("target-file").unwrap();
        read_targets_from_file(file_path)
    } else {
        eprintln!("需要指定目标IP或目标文件");
        process::exit(1);
    };
    
    if targets.is_empty() {
        eprintln!("没有有效的目标IP");
        process::exit(1);
    }
    
    // 开始扫描
    println!("\n[*] 开始扫描，目标: {} 个IP, {} 个端口, {} 个线程", 
        targets.len(), ports.len(), thread_count);
    let start_time = Instant::now();
    
    // 使用多线程扫描
    let results = scan::scan_ips(targets, ports, timeout_ms, thread_count, skip_ping);
    
    // 输出结果
    let mut total_services = 0;
    let mut vulnerabilities = HashSet::new();
    
    println!("\n[+] 扫描结果:");
    for (ip, services) in &results {
        if !services.is_empty() {
            println!("\n[+] 主机: {} 开放端口: {}", ip, services.len());
            for service in services {
                println!("  [+] {:5} - {}", service.port, service.service);
                
                if let Some(version) = &service.version {
                    println!("      版本: {}", version);
                }
                
                if let Some(banner) = &service.banner {
                    if !banner.is_empty() && verbose {
                        println!("      Banner: {}", banner);
                    }
                }
                
                // 显示漏洞信息
                if !service.cve.is_empty() && !no_exploit {
                    println!("      发现漏洞:");
                    for cve in &service.cve {
                        println!("        - {}", cve);
                        vulnerabilities.insert(cve.clone());
                    }
                }
            }
            total_services += services.len();
        }
    }
    
    // 爆破功能(如果启用)
    if !no_brute {
        let mut users = Vec::new();
        let mut passwords = Vec::new();
        
        // 添加单个用户名和密码
        if matches.is_present("user") {
            users.push(matches.value_of("user").unwrap().to_string());
        }
        
        if matches.is_present("password") {
            passwords.push(matches.value_of("password").unwrap().to_string());
        }
        
        // 从文件加载用户名列表
        if matches.is_present("user-file") {
            let file_path = matches.value_of("user-file").unwrap();
            users.extend(read_lines_from_file(file_path));
        }
        
        // 从文件加载密码列表
        if matches.is_present("password-file") {
            let file_path = matches.value_of("password-file").unwrap();
            passwords.extend(read_lines_from_file(file_path));
        }
        
        // 如果没有指定用户名和密码，使用默认值
        if users.is_empty() {
            users.push("admin".to_string());
            users.push("root".to_string());
            users.push("user".to_string());
        }
        
        if passwords.is_empty() {
            passwords.push("admin".to_string());
            passwords.push("password".to_string());
            passwords.push("123456".to_string());
        }
        
        // 执行爆破
        if !users.is_empty() && !passwords.is_empty() {
            println!("\n[*] 开始爆破，使用 {} 个用户名和 {} 个密码", users.len(), passwords.len());
            
            let mut successful_logins = 0;
            
            for (_, services) in &results {
                for service in services {
                    if ["ssh", "ftp", "mysql"].contains(&service.service.as_str()) {
                        println!("  [*] 尝试破解 {}:{} ({})", service.ip, service.port, service.service);
                        
                        if let Some((user, pass)) = brute::brute_force(service, &users, &passwords, timeout_ms) {
                            println!("  [+] 成功! 用户名: {}, 密码: {}", user, pass);
                            successful_logins += 1;
                        }
                    }
                }
            }
            
            println!("[+] 爆破完成，成功次数: {}", successful_logins);
        }
    }
    
    // 尝试漏洞利用(如果启用)
    if !no_exploit && !vulnerabilities.is_empty() {
        println!("\n[*] 发现漏洞总数: {}", vulnerabilities.len());
        println!("[*] 开始验证漏洞");
        
        for (_, services) in &results {
            for service in services {
                for cve in &service.cve {
                    println!("  [*] 尝试利用 {}:{} 的漏洞 {}", service.ip, service.port, cve);
                    let result = exploit::try_exploit(service, cve);
                    
                    if result {
                        println!("  [+] 漏洞利用成功: {}", cve);
                    } else {
                        println!("  [-] 漏洞利用失败或不适用: {}", cve);
                    }
                }
            }
        }
    }
    
    // 输出扫描总结
    let duration = start_time.elapsed();
    println!("\n[*] 扫描完成! 用时: {:.2}秒", duration.as_secs_f64());
    println!("[*] 发现 {} 个有效主机, {} 个开放端口/服务", results.len(), total_services);
    if !no_exploit {
        println!("[*] 发现 {} 个潜在漏洞", vulnerabilities.len());
    }
}

// 从文件读取目标IP
fn read_targets_from_file(file_path: &str) -> Vec<String> {
    let path = Path::new(file_path);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("无法打开文件 {}: {}", file_path, e);
            return Vec::new();
        }
    };
    
    let reader = BufReader::new(file);
    let mut targets = Vec::new();
    
    for line in reader.lines() {
        if let Ok(line) = line {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                let ips = utils::parse_ip_range(line);
                targets.extend(ips);
            }
        }
    }
    
    targets
}

// 从文件读取行
fn read_lines_from_file(file_path: &str) -> Vec<String> {
    let path = Path::new(file_path);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("无法打开文件 {}: {}", file_path, e);
            return Vec::new();
        }
    };
    
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    
    for line in reader.lines() {
        if let Ok(line) = line {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                lines.push(line.to_string());
            }
        }
    }
    
    lines
}
