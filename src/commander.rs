use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::Utc;

pub fn run_iter(command: &str, input_file: &str) -> Result<(), Box<dyn Error>> {
    let infile = File::open(input_file)?;
    let reader = BufReader::new(infile);

    let mut log = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("results.log")?,
    );

    let now_ms = || -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    };

    for (idx, line_res) in reader.lines().enumerate() {
        let line = match line_res {
            Ok(s) => s,
            Err(e) => {
                writeln!(
                    log,
                    "[{}] [line {}] <READ_ERROR> {}",
                    now_ms(),
                    idx + 1,
                    e
                )?;
                continue;
            }
        };

        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                writeln!(
                    log,
                    "[{}] [line {}] <SPAWN_ERROR> cmd=\"{}\" err=\"{}\"",
                    now_ms(),
                    idx + 1,
                    command,
                    e
                )?;
                continue;
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = writeln!(stdin, "{}", line) {
                writeln!(
                    log,
                    "[{}] [line {}] <STDIN_WRITE_ERROR> err=\"{}\"",
                    now_ms(),
                    idx + 1,
                    e
                )?;
            }
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                writeln!(
                    log,
                    "[{}] [line {}] <WAIT_ERROR> err=\"{}\"",
                    now_ms(),
                    idx + 1,
                    e
                )?;
                continue;
            }
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);

        writeln!(log, "===== BEGIN RUN @{} ms =====", now_ms())?;
        writeln!(log, "LineNumber: {}", idx + 1)?;
        writeln!(log, "Command: {}", command)?;
        let chronox: String = Utc::now().to_string();
        writeln!(log, "Time: {}", chronox)?;
        writeln!(log, "Supplied STDIN: {}", line)?;
        writeln!(log, "Exit Status: {}", output.status)?;
        if !stdout_str.is_empty() {
            writeln!(log, "--- STDOUT ---")?;
            write!(log, "{}", stdout_str)?;
        } else {
            writeln!(log, "--- STDOUT (empty) ---")?;
        }
        if !stderr_str.is_empty() {
            writeln!(log, "--- STDERR ---")?;
            write!(log, "{}", stderr_str)?;
        } else {
            writeln!(log, "--- STDERR (empty) ---")?;
        }
        writeln!(log, "===== END RUN =====\n")?;
        log.flush()?;
    }

    Ok(())
}
