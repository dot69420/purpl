use std::io::{self, Write};
use std::cell::RefCell;

pub trait IoHandler {
    fn println(&self, msg: &str);
    fn print(&self, msg: &str);
    fn flush(&self);
    fn read_line(&self) -> String;
    fn read_input(&self, prompt: &str, default: Option<&str>) -> String;
}

pub struct RealIoHandler;

impl IoHandler for RealIoHandler {
    fn println(&self, msg: &str) {
        println!("{}", msg);
    }

    fn print(&self, msg: &str) {
        print!("{}", msg);
    }

    fn flush(&self) {
        let _ = io::stdout().flush();
    }

    fn read_line(&self) -> String {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();
        input
    }

    fn read_input(&self, prompt: &str, default: Option<&str>) -> String {
        let prompt_text = if let Some(def) = default {
            format!("{} [{}] ", prompt, def)
        } else {
            format!("{} ", prompt)
        };
        self.print(&prompt_text);
        self.flush();
        let input = self.read_line();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            default.unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        }
    }
}

pub struct MockIoHandler {
    pub output: RefCell<Vec<String>>,
    pub input_queue: RefCell<Vec<String>>,
}

impl MockIoHandler {
    pub fn new() -> Self {
        Self {
            output: RefCell::new(Vec::new()),
            input_queue: RefCell::new(Vec::new()),
        }
    }

    pub fn add_input(&self, input: &str) {
        self.input_queue.borrow_mut().push(input.to_string());
    }

    pub fn get_output(&self) -> String {
        self.output.borrow().join("")
    }
}

impl IoHandler for MockIoHandler {
    fn println(&self, msg: &str) {
        self.output.borrow_mut().push(format!("{}\n", msg));
    }

    fn print(&self, msg: &str) {
        self.output.borrow_mut().push(msg.to_string());
    }

    fn flush(&self) {
        // No-op for mock
    }

    fn read_line(&self) -> String {
        if !self.input_queue.borrow().is_empty() {
            self.input_queue.borrow_mut().remove(0)
        } else {
            String::new()
        }
    }

    fn read_input(&self, prompt: &str, default: Option<&str>) -> String {
        let prompt_text = if let Some(def) = default {
            format!("{} [{}] ", prompt, def)
        } else {
            format!("{} ", prompt)
        };
        self.print(&prompt_text);
        
        let input = self.read_line();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            default.unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        }
    }
}
