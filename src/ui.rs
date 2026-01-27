use colored::*;
use crate::io_handler::IoHandler;
use std::process::Command;

pub fn clear_screen() {
    let _ = Command::new("clear").status();
}

pub fn print_main_menu_banner(io: &dyn IoHandler) {
    io.println(&format!("{}", "    ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ".magenta().bold()));
    io.println(&format!("{}", "    ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ".bright_black().bold()));
    io.println(&format!("{}", "    ██████╔╝██║   ██║██████╔╝██████╔╝██║     ".magenta().bold()));
    io.println(&format!("{}", "    ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ".bright_black().bold()));
    io.println(&format!("{}", "    ██║     ╚██████╔╝██║  ██║██║     ███████╗".magenta().bold()));
    io.println(&format!("{}", "    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝".bright_black().bold()));
    io.println(&format!("\n{}", "              Purple Team Helper Tool\n".magenta().bold()));
}

pub fn print_header(io: &dyn IoHandler, _title: &str, subtitle: Option<&str>) {
    let width = 60;
    let border = "=".repeat(width).purple().bold();
    
    io.println(&format!("{}", border));
    io.println(&format!("{:^width$}", "PURPL - Purple Team Helper Tool", width = width).magenta().bold());
    
    if let Some(sub) = subtitle {
        io.println(&format!("{:^width$}", sub, width = width).white().bold());
    }
    
    io.println(&format!("{}", border));
    io.println("");
}

pub struct MenuItem<T> {
    pub label: String,
    pub value: T,
}

impl<T> MenuItem<T> {
    pub fn new(label: &str, value: T) -> Self {
        Self {
            label: label.to_string(),
            value,
        }
    }
}

pub enum MenuResult {
    Item(usize),
    Extra(String), // Key of the extra option
    Back,
}

pub fn show_menu_loop<T>(
    io: &dyn IoHandler,
    title: &str,
    items: &[MenuItem<T>],
    extra_options: &[(&str, &str)],
    is_main_menu: bool,
) -> MenuResult {
    loop {
        clear_screen();
        if is_main_menu {
            print_main_menu_banner(io);
        } else {
            print_header(io, "PURPL CLI", Some(title));
        }

        for (i, item) in items.iter().enumerate() {
             io.println(&format!(" {} {} {}", 
                format!("[{}]", i + 1).purple().bold(), 
                "-".dimmed(),
                item.label
            ));
        }

        if !extra_options.is_empty() {
             io.println("");
             for (label, key) in extra_options {
                 io.println(&format!(" {} {} {}", 
                    format!("[{}]", key).yellow().bold(), 
                    "-".dimmed(),
                    label
                ));
            }
        }

        io.print(&format!("\n{}", "Select >> ".purple().bold()));
        io.flush();

        let input = io.read_line();
        let trimmed = input.trim();
        
        if input.is_empty() { return MenuResult::Back; }

        if let Ok(idx) = trimmed.parse::<usize>() {
            if idx > 0 && idx <= items.len() {
                return MenuResult::Item(idx - 1);
            }
        }
        
        for (_, key) in extra_options {
            if trimmed == *key {
                return MenuResult::Extra(key.to_string());
            }
        }

        io.println(&format!("{}", "[!] Invalid selection.".red()));
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
