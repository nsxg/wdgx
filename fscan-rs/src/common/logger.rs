use log::{LevelFilter, info};
use std::path::Path;
use std::fs::File;
use std::io::Write;
use chrono::Local;
use env_logger::{Builder, Target};

pub fn init(verbose: bool, silent: bool, log_file: &Option<impl AsRef<Path>>) -> Result<(), Box<dyn std::error::Error>> {
    let level = if verbose {
        LevelFilter::Debug
    } else if silent {
        LevelFilter::Error
    } else {
        LevelFilter::Info
    };
    
    let mut builder = Builder::new();
    builder.filter_level(level);
    
    if let Some(log_file) = log_file {
        let log_path = log_file.as_ref();
        let file = File::create(log_path)?;
        builder.target(Target::Pipe(Box::new(file)));
        info!("Logging to file: {}", log_path.display());
    } else {
        builder.target(Target::Stdout);
    }
    
    builder.format(|buf, record| {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(
            buf,
            "[{}] [{}] {}",
            timestamp,
            record.level(),
            record.args()
        )
    });
    
    builder.init();
    
    Ok(())
}
