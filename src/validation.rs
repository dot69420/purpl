use regex::Regex;
use std::sync::OnceLock;

static IP_DOMAIN_REGEX: OnceLock<Regex> = OnceLock::new();
static URL_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_ip_domain_regex() -> &'static Regex {
    IP_DOMAIN_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9\.\-_]+$").unwrap()
    })
}

fn get_url_regex() -> &'static Regex {
    URL_REGEX.get_or_init(|| {
        Regex::new(r"^(http|https)://[a-zA-Z0-9\.\-_:/?=&]+$").unwrap()
    })
}

pub fn validate_target(target: &str) -> Result<(), String> {
    if target.trim().is_empty() {
        return Err("Target cannot be empty".to_string());
    }
    
    if target.starts_with('-') {
        return Err("Target cannot start with a hyphen".to_string());
    }

    if target.len() > 255 {
        return Err("Target is too long".to_string());
    }

    if target.contains(';') || target.contains('|') || target.contains('&') || target.contains('$') || target.contains('`') {
         return Err("Target contains illegal shell characters".to_string());
    }
    
    // Allow CIDR for Nmap
    if target.contains('/') {
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".to_string());
        }
        if !get_ip_domain_regex().is_match(parts[0]) {
            return Err("Invalid IP in CIDR".to_string());
        }
        if parts[1].parse::<u8>().is_err() {
            return Err("Invalid mask in CIDR".to_string());
        }
        return Ok(());
    }

    if get_ip_domain_regex().is_match(target) {
        return Ok(());
    }

    // For web targets (URLs)
    if target.starts_with("http") && get_url_regex().is_match(target) {
        return Ok(());
    }

    Err("Invalid target format. Must be IP, Domain, or URL.".to_string())
}

pub fn validate_nmap_flags(flags: &[String]) -> Result<(), String> {
    let dangerous_flags = [
        "--script", // Scripts can be arbitrary
        "-oG", "-oN", "-oX", "-oA", // Output overwrite
        "--interactive", // Old nmap
        "--resume", // Resume file
        "--stylesheet", // XSL injection
        "--datadir", // Path traversal
    ];

    for flag in flags {
        for danger in dangerous_flags {
            if flag.starts_with(danger) {
                return Err(format!("Dangerous flag detected: {}", danger));
            }
        }
        // General shell safety check
        if flag.contains(';') || flag.contains('|') || flag.contains('&') || flag.contains('$') || flag.contains('`') {
            return Err(format!("Flag contains illegal characters: {}", flag));
        }
    }
    Ok(())
}

pub fn validate_web_flags(flags: &[String]) -> Result<(), String> {
    for flag in flags {
        if flag.contains(';') || flag.contains('|') || flag.contains('&') || flag.contains('$') || flag.contains('`') {
            return Err(format!("Flag contains illegal characters: {}", flag));
        }
    }
    Ok(())
}
