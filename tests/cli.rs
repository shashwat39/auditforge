use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_auditforge")
}

fn sample_log() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/sample-audit.log")
}

fn write_temp(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("auditforge-{name}-{}", std::process::id()));
    std::fs::write(&path, contents).expect("write temp input");
    path
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> (i32, String, String) {
    let mut command = Command::new(bin());
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("spawn auditforge");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait");
    let code = output.status.code().unwrap_or(127);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    (code, stdout, stderr)
}

fn json_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|err| panic!("invalid JSON {line}: {err}"))
        })
        .collect()
}

#[test]
fn version_command() {
    let (code, stdout, stderr) = run(&["version"], None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        stdout.trim(),
        format!("auditforge {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(stderr.is_empty());
}

#[test]
fn parses_sample_file() {
    let path = sample_log();
    let (code, stdout, stderr) = run(&["parse", "--input", path.to_str().unwrap()], None);
    assert_eq!(code, 0, "{stderr}");
    let events = json_lines(&stdout);
    assert_eq!(events.len(), 4, "{stdout}");

    assert_eq!(events[0]["timestamp"], "2026-10-04T12:00:00Z");
    assert_eq!(events[0]["event_id"], "1234");
    assert_eq!(events[0]["record_type"], "SYSCALL");
    assert_eq!(events[0]["operation"], "open");
    assert_eq!(events[0]["user"], "root");
    assert_eq!(events[0]["success"], true);
    assert!(events[0]["raw"].as_str().unwrap().contains("syscall=2"));

    assert_eq!(events[1]["event_id"], "1235");
    assert_eq!(events[1]["operation"], "execve");
    assert_eq!(events[1]["user"], "1000");
    assert_eq!(events[1]["success"], false);

    assert_eq!(events[2]["record_type"], "USER_AUTH");
    assert_eq!(events[2]["user"], "root");
    assert!(events[2]["success"].is_null());
    assert!(events[2]["operation"].is_null());

    assert!(events[3]["record_type"].is_null());
    assert_eq!(events[3]["raw"], "this is not an audit record");
    assert!(stderr.contains("malformed record at line"));
}

#[test]
fn multiple_records_and_missing_fields() {
    let path = write_temp(
        "multi",
        "type=CWD msg=audit(0.0:9): cwd=\"/tmp\"\n\
         type=SYSCALL msg=audit(1791115200:7): syscall=257 success=yes uid=0\n",
    );
    let (code, stdout, stderr) = run(&["parse", "--input", path.to_str().unwrap()], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let events = json_lines(&stdout);
    assert_eq!(events.len(), 2);
    assert!(events[0]["operation"].is_null());
    assert!(events[0]["user"].is_null());
    assert!(events[0]["success"].is_null());
    assert_eq!(events[1]["operation"], "open");
    assert_eq!(events[1]["user"], "root");
    let _ = std::fs::remove_file(path);
}

#[test]
fn malformed_record_does_not_crash() {
    let (code, stdout, stderr) = run(&["parse", "--input", "-"], Some(b"garbage\n"));
    assert_eq!(code, 0, "{stderr}");
    let events = json_lines(&stdout);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["raw"], "garbage");
    assert!(events[0]["event_id"].is_null());
    assert!(stderr.contains("malformed record"));
}

#[test]
fn empty_input_emits_nothing() {
    let (code, stdout, stderr) = run(&["parse", "--input", "-"], Some(b""));
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());

    let (code, stdout, stderr) = run(&["parse", "--input", "-"], Some(b"\n\n"));
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn stdin_input() {
    let line = b"type=SYSCALL msg=audit(1791115200.000:1234): syscall=2 success=yes uid=0\n";
    let (code, stdout, stderr) = run(&["parse", "--input", "-"], Some(line));
    assert_eq!(code, 0, "{stderr}");
    let events = json_lines(&stdout);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["operation"], "open");
    assert_eq!(events[0]["user"], "root");
}

#[test]
fn very_long_line_is_valid_json() {
    let mut line =
        String::from("type=SYSCALL msg=audit(1791115200:55): syscall=2 success=yes uid=0 comm=\"");
    line.push_str(&"a".repeat(256 * 1024));
    line.push_str("\"\n");
    let (code, stdout, stderr) = run(&["parse", "--input", "-"], Some(line.as_bytes()));
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let events = json_lines(&stdout);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_id"], "55");
    assert!(events[0]["raw"].as_str().unwrap().len() > 256 * 1024);
}

#[test]
fn overlong_line_does_not_crash() {
    let mut line = vec![b'x'; 1024 * 1024 + 64];
    line.push(b'\n');
    let (code, stdout, stderr) = run(&["parse", "--input", "-"], Some(&line));
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("exceeds 1 MiB"));
}

#[test]
fn output_lines_are_json_objects() {
    let path = sample_log();
    let (code, stdout, _) = run(&["parse", "--input", path.to_str().unwrap()], None);
    assert_eq!(code, 0);
    for value in json_lines(&stdout) {
        assert!(value.is_object());
        assert!(value.get("raw").is_some());
        assert!(value.get("timestamp").is_some());
        assert!(value.get("success").is_some());
    }
}

#[test]
fn run_exits_on_sigterm() {
    let path = write_temp(
        "follow",
        "type=SYSCALL msg=audit(1791115200:1): syscall=2 success=yes uid=0\n",
    );
    let mut child = Command::new(bin())
        .args(["run", "--input", path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn run");

    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let _ = sender.send((result, line));
    });

    let (read, line) = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("timed out waiting for output");
    read.expect("read stdout");
    assert!(line.contains("\"event_id\":\"1\""), "{line}");

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(status.success(), "kill failed");

    let started = Instant::now();
    let exit = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("auditforge run did not exit after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(exit.code(), Some(0));
    let _ = std::fs::remove_file(path);
}
