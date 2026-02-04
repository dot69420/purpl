use crate::io_handler::IoHandler;
use crate::tool_model::{ToolInput, ToolProfile};
use crate::validation::validate_target;
use colored::*;

/// Abstraction for gathering tool parameters.
/// Allows swapping CLI prompts with API payloads or Config files.
pub trait InputProvider {
    /// Resolve a standard ToolInput (Target, Interface, etc.)
    fn resolve(&self, input: &ToolInput) -> Option<String>;

    /// Resolve a generic text prompt
    fn resolve_text(&self, label: &str, default: Option<&str>) -> Option<String>;

    /// Select a profile from a list
    fn select_profile(&self, profiles: &[ToolProfile]) -> Option<usize>;

    /// Ask if the task should run in background
    fn confirm_background(&self) -> bool;
}

/// Standard CLI implementation using prompts
pub struct CliInputProvider<'a> {
    pub io: &'a dyn IoHandler,
}

impl<'a> CliInputProvider<'a> {
    pub fn new(io: &'a dyn IoHandler) -> Self {
        Self { io }
    }

    fn prompt_styled(&self, label: &str) -> String {
        self.io.print(&format!(
            "\n{} {}",
            label.cyan().bold(),
            ">>".bright_magenta().bold().blink()
        ));
        self.io.flush();
        self.io.read_line().trim().to_string()
    }
}

impl<'a> InputProvider for CliInputProvider<'a> {
    fn resolve(&self, input: &ToolInput) -> Option<String> {
        let label = match input {
            ToolInput::Target => "Enter Target IP/URL:",
            ToolInput::Interface => "Enter Network Interface:",
            ToolInput::Wordlist => "Enter Wordlist Path:",
            ToolInput::Text(l) => l.as_str(),
            ToolInput::None => return Some(String::new()),
        };

        loop {
            let val = self.prompt_styled(label);

            if val.is_empty() {
                if label.contains("Optional") || label.contains("Leave empty") {
                    return Some(String::new());
                }
                self.io.println(&format!("{}", "[!] Input required.".red()));
                // If it's just required, loop again
                continue;
            }

            // Validation Logic
            if matches!(input, ToolInput::Target) {
                if let Err(e) = validate_target(&val) {
                    self.io
                        .println(&format!("{} {}", "[!] Invalid Target:".red(), e));
                    continue;
                }
            }

            // Side effect: Save history for targets
            if matches!(input, ToolInput::Target) || label.to_lowercase().contains("target") {
                crate::history::save_last_target(&val);
            }

            return Some(val);
        }
    }

    fn resolve_text(&self, label: &str, default: Option<&str>) -> Option<String> {
        let prompt = if let Some(d) = default {
            format!("{} [Default: {}]", label, d)
        } else {
            label.to_string()
        };

        let val = self.prompt_styled(&prompt);
        if val.is_empty() {
            return default.map(|s| s.to_string());
        }
        Some(val)
    }

    fn select_profile(&self, profiles: &[ToolProfile]) -> Option<usize> {
        if profiles.is_empty() {
            return None;
        }

        self.io
            .println(&format!("\n{}", "Select Profile:".blue().bold()));
        for (i, p) in profiles.iter().enumerate() {
            self.io.println(&format!(
                "[{}] {} - {}",
                i + 1,
                p.name.green(),
                p.description
            ));
        }

        let input = self.prompt_styled(&format!("Choose [1-{}]:", profiles.len()));
        if let Ok(idx) = input.parse::<usize>() {
            if idx > 0 && idx <= profiles.len() {
                return Some(idx - 1);
            }
        }
        None
    }

    fn confirm_background(&self) -> bool {
        self.io.print("\nRun task in background? (y/N): ");
        self.io.flush();
        let input = self.io.read_line();
        input.trim().eq_ignore_ascii_case("y")
    }
}
