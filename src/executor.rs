use std::io::{self, BufRead, BufReader, Cursor};
use std::process::{Command, ExitStatus, Output, Stdio};
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::collections::VecDeque;

pub trait CommandExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus>;
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

// Mock for testing
#[cfg(test)]
pub struct ExecutedCall {
    pub command: String,
    pub args: Vec<String>,
}

#[cfg(test)]
pub struct MockExecutor {
    pub expected_calls: RefCell<Vec<(String, Vec<String>)>>,
    pub mock_output: RefCell<VecDeque<Output>>,
    pub mock_stream_output: RefCell<VecDeque<String>>,
    pub mock_status: RefCell<VecDeque<ExitStatus>>,
    pub root_status: bool,
}

#[cfg(test)]
impl MockExecutor {
    pub fn new() -> Self {
        Self {
            expected_calls: RefCell::new(Vec::new()),
            mock_output: RefCell::new(VecDeque::new()),
            mock_stream_output: RefCell::new(VecDeque::new()),
            mock_status: RefCell::new(VecDeque::new()),
            root_status: true,
        }
    }

    pub fn set_root(&mut self, is_root: bool) {
        self.root_status = is_root;
    }

    pub fn add_output(&self, output: Output) {
        self.mock_output.borrow_mut().push_back(output);
    }

    pub fn add_stream_output(&self, output: &str) {
        self.mock_stream_output.borrow_mut().push_back(output.to_string());
    }

    pub fn add_status(&self, status: ExitStatus) {
        self.mock_status.borrow_mut().push_back(status);
    }

    pub fn get_calls(&self) -> Vec<ExecutedCall> {
        self.expected_calls.borrow().iter().map(|(cmd, args)| {
            ExecutedCall {
                command: cmd.clone(),
                args: args.clone(),
            }
        }).collect()
    }
}

#[cfg(test)]
impl CommandExecutor for MockExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.expected_calls.borrow_mut().push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));

        if let Some(status) = self.mock_status.borrow_mut().pop_front() {
            Ok(status)
        } else {
             Ok(std::os::unix::process::ExitStatusExt::from_raw(0))
        }
    }

    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.expected_calls.borrow_mut().push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));

        if let Some(output) = self.mock_output.borrow_mut().pop_front() {
            Ok(output)
        } else {
            Ok(Output {
                status: std::os::unix::process::ExitStatusExt::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.execute(program, args)
    }

    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>> {
        self.expected_calls.borrow_mut().push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));

        let output = if let Some(out) = self.mock_stream_output.borrow_mut().pop_front() {
            out
        } else {
            String::new()
        };

        Ok(Box::new(BufReader::new(Cursor::new(output.into_bytes()))))
    }

    fn is_root(&self) -> bool {
        self.root_status
    }
}
