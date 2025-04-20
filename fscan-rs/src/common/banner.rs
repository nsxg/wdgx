use colored::*;

pub fn show() {
    let banner = r#"
    ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗      ██████╗ ███████╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║      ██╔══██╗██╔════╝
    █████╗  ███████╗██║     ███████║██╔██╗ ██║█████╗██████╔╝███████╗
    ██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║╚════╝██╔══██╗╚════██║
    ██║     ███████║╚██████╗██║  ██║██║ ╚████║      ██║  ██║███████║
    ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚══════╝
                                                     
    "#;
    
    println!("{}", banner.bright_red());
    println!("    {}", "A comprehensive internal network scanner written in Rust".bright_yellow());
    println!("    {}", "Original project: https://github.com/".bright_yellow());
    println!("    {}", "Version: 0.1.0".bright_yellow());
    println!("");
}
