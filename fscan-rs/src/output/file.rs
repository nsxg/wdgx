// src/output/file.rs
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub fn write_to_file(
    path: &Path,
    content: &str,
) -> io::Result<()> {
    // 确保目录存在
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // 写入文件
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    
    Ok(())
}

pub fn append_to_file(
    path: &Path,
    content: &str,
) -> io::Result<()> {
    // 确保目录存在
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // 以追加模式打开文件
    let mut file = if path.exists() {
        fs::OpenOptions::new()
            .append(true)
            .open(path)?
    } else {
        File::create(path)?
    };
    
    file.write_all(content.as_bytes())?;
    
    Ok(())
}
