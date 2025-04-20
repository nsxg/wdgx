// src/webscan/pocs/loader.rs
use std::path::{Path, PathBuf};
use std::fs;
use log::{info, error, debug};
use serde::{Deserialize, Serialize};
use glob::glob;

// Xray POC结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XrayPoc {
    pub name: String,
    pub id: Option<String>,
    pub info: XrayPocInfo,
    pub rules: Vec<XrayRule>,
    pub expression: Option<String>,
    pub set: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XrayPocInfo {
    pub name: String,
    pub severity: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<serde_yaml::Value>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XrayRule {
    pub method: Option<String>,
    pub path: String,
    pub headers: Option<serde_yaml::Value>,
    pub body: Option<String>,
    pub follow_redirects: Option<bool>,
    pub expression: String,
}

// Nuclei POC结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NucleiPoc {
    pub id: String,
    pub info: NucleiInfo,
    pub requests: Vec<NucleiRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NucleiInfo {
    pub name: String,
    pub author: Option<String>,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub reference: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NucleiRequest {
    pub method: Option<String>,
    pub path: Vec<String>,
    pub headers: Option<serde_yaml::Value>,
    pub body: Option<String>,
    pub matchers: Vec<NucleiMatcher>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NucleiMatcher {
    #[serde(rename = "type")]
    pub matcher_type: String,
    pub part: Option<String>,
    pub condition: Option<String>,
    pub regex: Option<Vec<String>>,
    pub words: Option<Vec<String>>,
    pub status: Option<Vec<u16>>,
}

// 加载Xray POCs
pub fn load_xray_pocs(pocs_dir: Option<&Path>) -> Vec<XrayPoc> {
    let default_dir = PathBuf::from("./webscan/xray");
    let pocs_path = pocs_dir.unwrap_or(&default_dir);
    
    if !pocs_path.exists() || !pocs_path.is_dir() {
        error!("Xray POCs directory does not exist or is not a directory: {}", pocs_path.display());
        return Vec::new();
    }
    
    info!("Loading Xray POCs from: {}", pocs_path.display());
    
    let mut pocs = Vec::new();
    let glob_pattern = format!("{}/**/*.yml", pocs_path.display());
    
    match glob(&glob_pattern) {
        Ok(paths) => {
            for entry in paths {
                match entry {
                    Ok(path) => {
                        match fs::read_to_string(&path) {
                            Ok(content) => {
                                match serde_yaml::from_str::<XrayPoc>(&content) {
                                    Ok(poc) => {
                                        debug!("Loaded Xray POC: {}", poc.name);
                                        pocs.push(poc);
                                    },
                                    Err(e) => {
                                        error!("Failed to parse Xray POC file {}: {}", path.display(), e);
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Failed to read POC file {}: {}", path.display(), e);
                            }
                        }
                    },
                    Err(e) => {
                        error!("Error accessing POC file: {}", e);
                    }
                }
            }
        },
        Err(e) => {
            error!("Failed to search for POC files: {}", e);
        }
    }
    
    info!("Loaded {} Xray POCs", pocs.len());
    pocs
}

// 加载Nuclei POCs
pub fn load_nuclei_pocs(pocs_dir: Option<&Path>) -> Vec<NucleiPoc> {
    let default_dir = PathBuf::from("./webscan/nuclei");
    let pocs_path = pocs_dir.unwrap_or(&default_dir);
    
    if !pocs_path.exists() || !pocs_path.is_dir() {
        error!("Nuclei POCs directory does not exist or is not a directory: {}", pocs_path.display());
        return Vec::new();
    }
    
    info!("Loading Nuclei POCs from: {}", pocs_path.display());
    
    let mut pocs = Vec::new();
    let glob_pattern = format!("{}/**/*.yml", pocs_path.display());
    
    match glob(&glob_pattern) {
        Ok(paths) => {
            for entry in paths {
                match entry {
                    Ok(path) => {
                        match fs::read_to_string(&path) {
                            Ok(content) => {
                                match serde_yaml::from_str::<NucleiPoc>(&content) {
                                    Ok(poc) => {
                                        debug!("Loaded Nuclei POC: {}", poc.id);
                                        pocs.push(poc);
                                    },
                                    Err(e) => {
                                        error!("Failed to parse Nuclei POC file {}: {}", path.display(), e);
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Failed to read POC file {}: {}", path.display(), e);
                            }
                        }
                    },
                    Err(e) => {
                        error!("Error accessing POC file: {}", e);
                    }
                }
            }
        },
        Err(e) => {
            error!("Failed to search for POC files: {}", e);
        }
    }
    
    info!("Loaded {} Nuclei POCs", pocs.len());
    pocs
}
