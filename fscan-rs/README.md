# fscan-rs

一个用Rust编写的功能丰富的内网综合扫描工具，类似于fscan。

## 特性

- 端口扫描与服务识别
- 各类服务的弱口令检测（SSH, FTP, MySQL, MSSQL, Redis, SMB, MongoDB, PostgreSQL, Oracle等）
- Web应用程序检测与漏洞扫描（支持Xray POC和Nuclei POC）
- 内网信息收集（域控、NetBIOS、SNMP等）
- 支持多种输出格式（文本、JSON、CSV）

## 安装

### 从源码编译

确保已安装Rust和Cargo:

```bash
git clone https://github.com/yourusername/fscan-rs.git
cd fscan-rs
cargo build --release
