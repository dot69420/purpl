use std::io::{self, BufRead, BufReader};
use std::process::{Command, ExitStatus, Output, Stdio};
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::io::Cursor;

pub trait CommandExecutor: Sync + Send {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus>;
    fn execute_with_input(&self, program: &str, args: &[&str], input: &str) -> io::Result<ExitStatus>;
    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output>;
    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus>;
    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>>;
    fn is_root(&self) -> bool;
}

pub struct ShellExecutor;

impl CommandExecutor for ShellExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
    }

    fn execute_with_input(&self, program: &str, args: &[&str], input: &str) -> io::Result<ExitStatus> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(input.as_bytes());
        }

        child.wait()
    }

    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        Command::new(program)
            .args(args)
            .output()
    }

    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    }

    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>> {
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not capture stdout"))?;

        Ok(Box::new(BufReader::new(stdout)))
    }

    fn is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(test)]
use std::collections::HashMap;

// ... (ShellExecutor implementation remains unchanged)

// Mock for testing
#[cfg(test)]
#[derive(Clone)]
pub struct ExecutedCall {
    pub command: String,
    pub args: Vec<String>,
}

#[cfg(test)]
#[derive(Clone)]
pub struct MockBehavior {
    pub output: Output,
    pub status: ExitStatus,
}

#[cfg(test)]
impl Default for MockBehavior {
    fn default() -> Self {
        use std::os::unix::process::ExitStatusExt;
        Self {
            output: Output {
                status: ExitStatusExt::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            status: ExitStatusExt::from_raw(0),
        }
    }
}

#[cfg(test)]
pub struct MockExecutor {
    pub expected_calls: Mutex<Vec<ExecutedCall>>,
    pub registry: Mutex<HashMap<String, MockBehavior>>,
    pub root_status: bool,
}

#[cfg(test)]
impl MockExecutor {
    pub fn new() -> Self {
        Self {
            expected_calls: Mutex::new(Vec::new()),
            registry: Mutex::new(HashMap::new()),
            root_status: true,
        }
    }

    pub fn set_root(&mut self, is_root: bool) {
        self.root_status = is_root;
    }

    pub fn register(&self, program: &str, behavior: MockBehavior) {
        self.registry.lock().unwrap().insert(program.to_string(), behavior);
    }

    pub fn register_success(&self, program: &str) {
        self.register(program, MockBehavior::default());
    }

    pub fn register_output(&self, program: &str, stdout: &[u8]) {
        use std::os::unix::process::ExitStatusExt;
        let behavior = MockBehavior {
            output: Output {
                status: ExitStatusExt::from_raw(0),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
            },
            status: ExitStatusExt::from_raw(0),
        };
        self.register(program, behavior);
    }

    pub fn get_calls(&self) -> Vec<ExecutedCall> {
        self.expected_calls.lock().unwrap().clone()
    }

    fn get_behavior(&self, program: &str) -> MockBehavior {
        if let Some(b) = self.registry.lock().unwrap().get(program) {
            b.clone()
        } else {
            // Default to success if not registered, to avoid crashes in loose tests
            MockBehavior::default()
        }
    }
}

#[cfg(test)]
impl CommandExecutor for MockExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.expected_calls.lock().unwrap().push(ExecutedCall {
            command: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });

        Ok(self.get_behavior(program).status)
    }

    fn execute_with_input(&self, program: &str, args: &[&str], _input: &str) -> io::Result<ExitStatus> {
        self.execute(program, args)
    }

    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.expected_calls.lock().unwrap().push(ExecutedCall {
            command: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });

        Ok(self.get_behavior(program).output)
    }

    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.execute(program, args)
    }

    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>> {
        self.expected_calls.lock().unwrap().push(ExecutedCall {
            command: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });

        let output = self.get_behavior(program).output.stdout;
        let output_str = String::from_utf8_lossy(&output).to_string();

        Ok(Box::new(BufReader::new(Cursor::new(output_str.into_bytes()))))
    }

    fn is_root(&self) -> bool {
        self.root_status
    }
}
