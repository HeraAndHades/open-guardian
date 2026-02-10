use colored::*;

pub fn print_banner() {
    let banner = r#"
   ____                      _____                      _ _             
  / __ \                    / ____|                    | (_)            
 | |  | |_ __   ___ _ __   | |  __ _   _  __ _ _ __  __| |_  __ _ _ __  
 | |  | | '_ \ / _ \ '_ \  | | |_ | | | |/ _` | '__|/ _` | |/ _` | '_ \ 
 | |__| | |_) |  __/ | | | | |__| | |_| | (_| | |  | (_| | | (_| | | | |
  \____/| .__/ \___|_| |_|  \_____|\__,_|\__,_|_|   \__,_|_|\__,_|_| |_|
        | |                                                             
        |_|                                                             
    "#;

    println!("{}", banner.bright_cyan().bold());
    println!("{}", "   Stopping AI agents from doing stupid things".bright_white().italic());
    println!("{}", "   ===============================================".bright_black());
    println!();
}

pub fn print_step(msg: &str) {
    println!("{} {}", "➜".bright_blue().bold(), msg);
    tracing::info!("STEP: {}", msg);
}

pub fn print_success(msg: &str) {
    println!("{} {}", "✔".bright_green().bold(), msg);
    tracing::info!("SUCCESS: {}", msg);
}

pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".bright_yellow().bold(), msg);
    tracing::warn!("WARNING: {}", msg);
}

pub fn print_error(msg: &str) {
    println!("{} {}", "✘".bright_red().bold(), msg);
    tracing::error!("ERROR: {}", msg);
}
