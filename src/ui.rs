use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;
use colored::*;
use std::process::Command;

pub fn clear_screen() {
    let _ = Command::new("clear").status();
}

pub fn print_main_menu_banner(io: &dyn IoHandler) {
    io.println(&format!(
        "{}",
        "        ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     "
            .magenta()
            .bold()
    ));
    io.println(&format!(
        "{}",
        "        ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     "
            .bright_black()
            .bold()
    ));
    io.println(&format!(
        "{}",
        "        ██████╔╝██║   ██║██████╔╝██████╔╝██║     "
            .magenta()
            .bold()
    ));
    io.println(&format!(
        "{}",
        "        ██╔═══╝ ██║   ██║██╔══██╗██╔══██╗██║     "
            .bright_black()
            .bold()
    ));
    io.println(&format!(
        "{}",
        "        ██║     ╚██████╔╝██║  ██║██║     ███████╗"
            .magenta()
            .bold()
    ));
    io.println(&format!(
        "{}",
        "        ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝"
            .bright_black()
            .bold()
    ));
    io.println(&format!(
        "\n{}",
        "                  Purple Team Helper Tool\n"
            .magenta()
            .bold()
    ));
}

pub fn print_header(io: &dyn IoHandler, _title: &str, subtitle: Option<&str>) {
    let width = 60;
    // Hacker style: use a more "tech" border or just distinct colors
    let border_char = "━";
    let border = border_char.repeat(width).bright_magenta().bold();

    io.println(&format!("{}", border));
    io.println(
        &format!(
            "{:^width$}",
            "PURPL - Purple Team Helper Tool",
            width = width
        )
        .magenta()
        .bold(),
    );

    if let Some(sub) = subtitle {
        io.println(&format!("{:^width$}", sub, width = width).white().italic());
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
            print_header(io, "PURPL CLI", Some("Main Menu"));
        } else {
            print_header(io, "PURPL CLI", Some(title));
        }

        for (i, item) in items.iter().enumerate() {
            // Style: [ 1 ] Option
            io.println(&format!(
                " {}{}{} {}",
                "[".bright_magenta().dimmed(),
                (i + 1).to_string().magenta().bold(),
                "]".bright_magenta().dimmed(),
                // "-".dimmed(), // Removed dash for cleaner look
                item.label.white()
            ));
        }

        if !extra_options.is_empty() {
            io.println("");
            for (label, key) in extra_options {
                io.println(&format!(
                    " {} {} {}  {}",
                    "[".cyan().dimmed(),
                    key.cyan().bold(),
                    "]".cyan().dimmed(),
                    label.dimmed()
                ));
            }
        }

        // Prompt
        io.print(&format!("\n{}", "Select >> ".bright_magenta().bold()));
        io.flush();

        let input = io.read_line();
        let trimmed = input.trim();

        if input.is_empty() {
            return MenuResult::Back;
        }

        if let Ok(idx) = trimmed.parse::<usize>() {
            if idx > 0 && idx <= items.len() {
                return MenuResult::Item(idx - 1);
            }
        }

        for (_, key) in extra_options {
            if trimmed.eq_ignore_ascii_case(key) {
                return MenuResult::Extra(key.to_string());
            }
        }

        io.println(&format!("{}", "[!] Invalid selection.".red()));
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn get_input_styled(io: &dyn IoHandler, prompt: &str) -> String {
    io.print(&format!(
        "\n{} {}",
        prompt.cyan().bold(),
        ">>".bright_magenta().bold().blink()
    ));
    io.flush();
    io.read_line().trim().to_string()
}

pub fn ask_and_enable_sudo(
    executor: &dyn CommandExecutor,
    io: &dyn IoHandler,
    context_msg: Option<&str>,
) -> Result<bool, ()> {
    let operation = context_msg.unwrap_or("This operation");
    let prompt = format!(
        "[!] {} requires ROOT privileges. Attempt to elevate with sudo?",
        operation
    );

    loop {
        let input = get_input_styled(io, &format!("{} [Y/n]", prompt.red()));
        let trimmed = input.trim();

        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("y")
            || trimmed.eq_ignore_ascii_case("yes")
        {
            // Interactive sudo authentication
            let status = executor.execute("sudo", &["-v"]);
            match status {
                Ok(s) if s.success() => return Ok(true),
                _ => {
                    io.println(&format!(
                        "{}",
                        "[-] Sudo authentication failed. Aborting.".red()
                    ));
                    return Err(());
                }
            }
        } else if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
            return Ok(false);
        } else {
            // Check if it starts with y but has extra content (likely a leaked password)
            if trimmed.to_lowercase().starts_with('y') {
                io.println(&format!(
                    "{}",
                    "[!] Security Warning: Do not type your password on the confirmation line."
                        .yellow()
                        .bold()
                ));
                io.println("    Please type 'y' to confirm, then enter your password securely when prompted by sudo.");
                continue;
            }
            // Other invalid input, just loop or treat as no? strict loop is safer.
            io.println(&format!(
                "{}",
                "[!] Invalid input. Please enter 'y' or 'n'.".yellow()
            ));
        }
    }
}
