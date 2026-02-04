use std::io::{self, BufRead, BufReader};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(test)]
use std::io::Cursor;
#[cfg(test)]
use std::sync::Mutex;

pub trait CommandExecutor: Sync + Send {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus>;
    fn execute_with_input(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
    ) -> io::Result<ExitStatus>;
    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output>;
    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus>;
    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>>;
    fn is_root(&self) -> bool;

    // New method for cancellable execution
    fn execute_cancellable(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
    ) -> io::Result<ExitStatus>;

    // New method for streaming output capture
    fn execute_streamed(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
        on_stdout: Box<dyn Fn(&str) + Send + Sync + '_>,
    ) -> io::Result<ExitStatus>;
}

pub struct ShellExecutor;

impl CommandExecutor for ShellExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.execute_cancellable(program, args, "", None)
    }

    fn execute_with_input(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
    ) -> io::Result<ExitStatus> {
        self.execute_cancellable(program, args, input, None)
    }

    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        Command::new(program).args(args).output()
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

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not capture stdout"))?;

        Ok(Box::new(BufReader::new(stdout)))
    }

    fn is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn execute_cancellable(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
    ) -> io::Result<ExitStatus> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        if !input.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(input.as_bytes());
            }
        }

        if let Some(t) = token {
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {
                        if t.load(Ordering::SeqCst) {
                            let _ = child.kill();
                            let _ = child.wait(); // Reap zombie
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Process cancelled",
                            ));
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            child.wait()
        }
    }

    fn execute_streamed(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
        on_stdout: Box<dyn Fn(&str) + Send + Sync + '_>,
    ) -> io::Result<ExitStatus> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        if !input.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(input.as_bytes());
            }
        }

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        on_stdout(&l);
                        // Also print to real stdout for CLI feedback
                        println!("{}", l);
                    }
                    Err(_) => break,
                }
            }
        }

        if let Some(t) = token {
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {
                        if t.load(Ordering::SeqCst) {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Process cancelled",
                            ));
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            child.wait()
        }
    }
}

pub struct DockerExecutor {
    pub image: String,
}

impl DockerExecutor {
    pub fn new(image: &str) -> Self {
        Self {
            image: image.to_string(),
        }
    }

    fn build_args<'a>(&self, program: &'a str, args: &[&'a str]) -> Vec<String> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let mount_arg = format!("{}:/workdir", current_dir.to_string_lossy());

        let mut docker_args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--net=host".to_string(), // Crucial for network scanning
            "-v".to_string(),
            mount_arg,
            "-w".to_string(),
            "/workdir".to_string(),
            "--init".to_string(), // Handle signals
            self.image.clone(),
            program.to_string(),
        ];

        docker_args.extend(args.iter().map(|s| s.to_string()));
        docker_args
    }
}

impl CommandExecutor for DockerExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.execute_cancellable(program, args, "", None)
    }

    fn execute_with_input(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
    ) -> io::Result<ExitStatus> {
        self.execute_cancellable(program, args, input, None)
    }

    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        let docker_args = self.build_args(program, args);
        let final_args: Vec<&str> = docker_args.iter().map(|s| s.as_str()).collect();
        Command::new("docker").args(&final_args).output()
    }

    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        let docker_args = self.build_args(program, args);
        let final_args: Vec<&str> = docker_args.iter().map(|s| s.as_str()).collect();
        Command::new("docker")
            .args(&final_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    }

    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>> {
        let docker_args = self.build_args(program, args);
        let final_args: Vec<&str> = docker_args.iter().map(|s| s.as_str()).collect();

        let mut child = Command::new("docker")
            .args(&final_args)
            .stdout(Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not capture stdout"))?;

        Ok(Box::new(BufReader::new(stdout)))
    }

    fn is_root(&self) -> bool {
        // In container we are root
        true
    }

    fn execute_cancellable(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
    ) -> io::Result<ExitStatus> {
        let docker_args = self.build_args(program, args);
        let final_args: Vec<&str> = docker_args.iter().map(|s| s.as_str()).collect();

        let mut child = Command::new("docker")
            .args(&final_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        if !input.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(input.as_bytes());
            }
        }

        if let Some(t) = token {
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {
                        if t.load(Ordering::SeqCst) {
                            let _ = child.kill(); // Kills docker client, --init/--rm should handle container cleanup
                            let _ = child.wait();
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Process cancelled",
                            ));
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            child.wait()
        }
    }

    fn execute_streamed(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
        on_stdout: Box<dyn Fn(&str) + Send + Sync + '_>,
    ) -> io::Result<ExitStatus> {
        let docker_args = self.build_args(program, args);
        let final_args: Vec<&str> = docker_args.iter().map(|s| s.as_str()).collect();

        let mut child = Command::new("docker")
            .args(&final_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        if !input.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(input.as_bytes());
            }
        }

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        on_stdout(&l);
                        println!("{}", l); // Passthrough to real term
                    }
                    Err(_) => break,
                }
            }
        }

        if let Some(t) = token {
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {
                        if t.load(Ordering::SeqCst) {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Process cancelled",
                            ));
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            child.wait()
        }
    }
}

pub struct HybridExecutor {
    local: ShellExecutor,
    docker: DockerExecutor,
}

impl HybridExecutor {
    pub fn new(image: &str) -> Self {
        Self {
            local: ShellExecutor,
            docker: DockerExecutor::new(image),
        }
    }

    fn select_executor(&self, program: &str) -> &dyn CommandExecutor {
        match program {
            // Tools that need hardware access or are typically local-only scripts
            "wifite" | "hciconfig" | "hcitool" | "l2ping" | "sdptool" | "tcpdump" | "ip"
            | "iwconfig" | "airmon-ng" => &self.local,
            _ => &self.docker,
        }
    }
}

impl CommandExecutor for HybridExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.select_executor(program).execute(program, args)
    }

    fn execute_with_input(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
    ) -> io::Result<ExitStatus> {
        self.select_executor(program)
            .execute_with_input(program, args, input)
    }

    fn execute_output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.select_executor(program).execute_output(program, args)
    }

    fn execute_silent(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.select_executor(program).execute_silent(program, args)
    }

    fn spawn_stdout(&self, program: &str, args: &[&str]) -> io::Result<Box<dyn BufRead + Send>> {
        self.select_executor(program).spawn_stdout(program, args)
    }

    fn is_root(&self) -> bool {
        // Users using hybrid mode for Wifite should run `sudo purpl` if they want local hardware access.
        // We return true so that 'sudo' is NOT automatically prepended for Docker commands.
        true
    }

    fn execute_cancellable(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
    ) -> io::Result<ExitStatus> {
        self.select_executor(program)
            .execute_cancellable(program, args, input, token)
    }

    fn execute_streamed(
        &self,
        program: &str,
        args: &[&str],
        input: &str,
        token: Option<Arc<AtomicBool>>,
        on_stdout: Box<dyn Fn(&str) + Send + Sync + '_>,
    ) -> io::Result<ExitStatus> {
        self.select_executor(program)
            .execute_streamed(program, args, input, token, on_stdout)
    }
}

#[cfg(test)]
use std::collections::HashMap;

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
        self.registry
            .lock()
            .unwrap()
            .insert(program.to_string(), behavior);
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
            MockBehavior::default()
        }
    }
}

#[cfg(test)]
impl CommandExecutor for MockExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        self.execute_cancellable(program, args, "", None)
    }

    fn execute_with_input(
        &self,
        program: &str,
        args: &[&str],
        _input: &str,
    ) -> io::Result<ExitStatus> {
        self.execute_cancellable(program, args, _input, None)
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

        Ok(Box::new(BufReader::new(Cursor::new(
            output_str.into_bytes(),
        ))))
    }

    fn is_root(&self) -> bool {
        self.root_status
    }

    fn execute_cancellable(
        &self,
        program: &str,
        args: &[&str],
        _input: &str,
        _token: Option<Arc<AtomicBool>>,
    ) -> io::Result<ExitStatus> {
        self.expected_calls.lock().unwrap().push(ExecutedCall {
            command: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });

        Ok(self.get_behavior(program).status)
    }

    fn execute_streamed(
        &self,
        program: &str,
        args: &[&str],
        _input: &str,
        _token: Option<Arc<AtomicBool>>,
        _on_stdout: Box<dyn Fn(&str) + Send + Sync + '_>,
    ) -> io::Result<ExitStatus> {
        self.execute(program, args)
    }
}
