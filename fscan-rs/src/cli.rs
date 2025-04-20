use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(
    name = "fscan-rs",
    version = "0.1.0",
    author = "Your Name <your.email@example.com>",
    about = "A Rust port of fscan - A comprehensive internal network scanner"
)]
pub struct Args {
    /// Target IP, IP range (192.168.1.1-192.168.1.254) or CIDR (192.168.1.0/24)
    #[clap(short, long, required = true)]
    pub target: String,
    
    /// Ports to scan (default: top 400 ports)
    #[clap(short, long, default_value = "21,22,23,25,53,80,81,110,111,135,139,143,161,389,443,445,465,500,515,520,523,548,623,636,873,902,1080,1099,1433,1521,1883,2049,2181,2375,2379,2580,3000,3001,3128,3306,3307,3389,3690,4430,4848,5000,5001,5432,5555,5601,5672,5900,5984,6379,7000,7001,7002,7003,7004,7005,7070,7071,7080,7443,7777,8000,8001,8009,8010,8042,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8161,8443,8545,8686,8848,8880,8888,8983,9000,9001,9002,9043,9060,9080,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9200,9300,9418,9443,9448,9500,9990,9999,10000,10250,10443,11211,15672,27017,28017,37777,50000,50050,50070,61616")]
    pub ports: String,
    
    /// Connection timeout in seconds
    #[clap(short, long, default_value = "3")]
    pub timeout: u64,
    
    /// Number of threads
    #[clap(short = 'T', long, default_value = "400")]
    pub threads: usize,
    
    /// Skip host discovery
    #[clap(long)]
    pub skip_alive: bool,
    
    /// Disable vulnerability scanning
    #[clap(long)]
    pub no_scan_vulns: bool,
    
    /// Disable password brute forcing
    #[clap(long)]
    pub no_brute: bool,
    
    /// Disable SSH brute forcing
    #[clap(long)]
    pub no_brute_ssh: bool,
    
    /// Disable FTP brute forcing
    #[clap(long)]
    pub no_brute_ftp: bool,
    
    /// Disable MySQL brute forcing
    #[clap(long)]
    pub no_brute_mysql: bool,
    
    /// Disable MSSQL brute forcing
    #[clap(long)]
    pub no_brute_mssql: bool,
    
    /// Disable Redis brute forcing
    #[clap(long)]
    pub no_brute_redis: bool,
    
    /// Disable SMB brute forcing
    #[clap(long)]
    pub no_brute_smb: bool,
    
    /// Disable MongoDB brute forcing
    #[clap(long)]
    pub no_brute_mongodb: bool,
    
    /// Disable PostgreSQL brute forcing
    #[clap(long)]
    pub no_brute_postgres: bool,
    
    /// Disable Oracle brute forcing
    #[clap(long)]
    pub no_brute_oracle: bool,
    
    /// Username file for brute forcing
    #[clap(long)]
    pub user_file: Option<PathBuf>,
    
    /// Password file for brute forcing
    #[clap(long)]
    pub pass_file: Option<PathBuf>,
    
    /// Disable web scanning
    #[clap(long)]
    pub no_web_scan: bool,
    
    /// Use nuclei instead of xray for POC scanning
    #[clap(long)]
    pub use_nuclei: bool,
    
    /// Custom POC path
    #[clap(long)]
    pub poc_path: Option<PathBuf>,
    
    /// Disable plugins
    #[clap(long)]
    pub no_plugins: bool,
    
    /// Output file
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    
    /// Output format (txt, json, csv)
    #[clap(long)]
    pub output_format: Option<String>,
    
    /// Log file
    #[clap(long)]
    pub log_file: Option<PathBuf>,
    
    /// Verbose output
    #[clap(short, long)]
    pub verbose: bool,
    
    /// Silent mode (no banner)
    #[clap(short, long)]
    pub silent: bool,
}
