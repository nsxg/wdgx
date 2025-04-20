// src/doc.rs
//! # fscan-rs
//! 
//! `fscan-rs` 是一个用Rust编写的功能丰富的内网综合扫描工具，类似于fscan。
//! 
//! ## 特性
//! 
//! * 端口扫描与服务识别
//! * 各类服务的弱口令检测
//! * Web应用程序检测与漏洞扫描
//! * 内网信息收集（域控、NetBIOS、SNMP等）
//! * 支持多种输出格式（文本、JSON、CSV）
//! 
//! ## 用法
//! 
//! ```
//! # 扫描指定目标
//! fscan-rs --target 192.168.1.1/24
//! 
//! # 指定端口扫描
//! fscan-rs --target 192.168.1.1 --port 22,80,443,3306,8080
//! 
//! # 从文件读取目标
//! fscan-rs --target-file targets.txt
//! 
//! # 禁用特定功能
//! fscan-rs --target 192.168.1.1 --no-brute --no-web
//! 
//! # 自定义爆破字典
//! fscan-rs --target 192.168.1.1 --user-file users.txt --password-file passwords.txt
//! ```

// 命令行参数说明
pub const USAGE: &str = r#"
fscan-rs 0.1.0
一个用Rust编写的功能丰富的内网综合扫描工具

用法:
    fscan-rs [选项]

选项:
    -t, --target TARGET         目标IP、IP范围(例如 192.168.1.1-50)或子网(例如 192.168.1.0/24)
    -T, --target-file FILE      包含目标的文件，每行一个
    -p, --port PORTS            要扫描的端口 (默认: 常用端口)
        --timeout SECONDS       每次连接尝试的超时时间(秒)
    -n, --threads NUM           并发线程数
    -o, --output FILE           输出文件 (默认: output.txt)
        --format FORMAT         输出格式 (txt, json, csv)
        --skip-ping             跳过Ping检查并扫描所有主机
        --no-brute              禁用暴力破解攻击
        --no-exploit            禁用漏洞利用尝试
        --no-web                禁用Web扫描
        --no-plugins            禁用插件(NetBIOS, Domain等)
    -v, --verbose               启用详细输出
        --user-file FILE        包含用于暴力破解的用户名的文件，每行一个
        --password-file FILE    包含用于暴力破解的密码的文件，每行一个
        --user USERS            用于暴力破解的用户名列表，逗号分隔
        --password PASSWORDS    用于暴力破解的密码列表，逗号分隔
        --poc-dir DIR           包含POC文件的目录
        --xray-pocs             启用Xray POC扫描
        --nuclei-pocs           启用Nuclei POC扫描
        --community COMMUNITY   SNMP社区字符串，逗号分隔

示例:
    fscan-rs -t 192.168.1.1/24
    fscan-rs -t 192.168.1.1-100 -p 22,80,3306,8080
    fscan-rs -T targets.txt --skip-ping --no-brute -o results.json --format json
"#;
