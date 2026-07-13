#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Backend for Command Runner: it actually runs the commands the UI configures.
//! Two transports — local PowerShell and remote SSH — both stream their output
//! back to the front end line by line over the `exec://line` event and return a
//! final `{ stdout, stderr, code }` once the command exits.

use base64::Engine;
use serde::Serialize;
use tauri::Window;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Serialize)]
struct ExecResult {
    stdout: String,
    stderr: String,
    code: i32,
}

fn emit_line(window: &Window, run_id: &str, line: &str, stream: &str) {
    let _ = window.emit(
        "exec://line",
        serde_json::json!({ "runId": run_id, "line": line, "stream": stream }),
    );
}

/// Decode one accumulated line (bytes up to and including `\n`) with a lossy
/// UTF-8 conversion, strip the trailing CR/LF, and clear the buffer for reuse.
fn take_line(buf: &mut Vec<u8>) -> String {
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    let s = String::from_utf8_lossy(buf).into_owned();
    buf.clear();
    s
}

/// PowerShell wants its script as base64 of UTF-16LE (`-EncodedCommand`); that
/// sidesteps every quoting/escaping problem with multi-line scripts.
fn encode_ps(script: &str) -> String {
    // `chcp 65001` switches the hidden console to UTF-8 so native tools
    // (ipconfig, netsh, …) emit UTF-8 instead of the locale's OEM code page —
    // otherwise their non-ASCII lines are garbled. The encoding assignments
    // align PowerShell's own streams to match.
    let prelude = "chcp 65001 > $null;\
                   $ErrorActionPreference='Continue';\
                   $OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8;\n";
    let full = format!("{prelude}{script}");
    let mut bytes = Vec::with_capacity(full.len() * 2);
    for u in full.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tauri::command]
async fn run_powershell(
    window: Window,
    run_id: String,
    script: String,
) -> Result<ExecResult, String> {
    let mut cmd = tokio::process::Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &encode_ps(&script),
    ]);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());

    // Don't flash a console window on Windows (windows_subsystem=windows hides
    // ours, but a spawned child would still pop its own without this flag).
    // tokio's Command exposes this as an inherent method on Windows.
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not start PowerShell: {e}"))?;

    // Read raw bytes, not UTF-8 `Lines`: native tools emit locale bytes that
    // aren't valid UTF-8, and `Lines::next_line` would return Err and abort the
    // whole stream on the first such line. `read_until` + lossy decode keeps
    // reading. The buffers live outside the select so a branch cancelled by the
    // other completing keeps its partial line for the next poll.
    let mut out_reader = BufReader::new(child.stdout.take().unwrap());
    let mut err_reader = BufReader::new(child.stderr.take().unwrap());
    let (mut out_buf, mut err_buf) = (Vec::new(), Vec::new());

    let mut stdout = String::new();
    let mut stderr = String::new();
    let (mut out_done, mut err_done) = (false, false);
    while !(out_done && err_done) {
        tokio::select! {
            r = out_reader.read_until(b'\n', &mut out_buf), if !out_done => match r {
                Ok(0) => out_done = true,
                Ok(_) => { let l = take_line(&mut out_buf); emit_line(&window, &run_id, &l, "out"); stdout.push_str(&l); stdout.push('\n'); }
                Err(_) => out_done = true,
            },
            r = err_reader.read_until(b'\n', &mut err_buf), if !err_done => match r {
                Ok(0) => err_done = true,
                Ok(_) => { let l = take_line(&mut err_buf); emit_line(&window, &run_id, &l, "err"); stderr.push_str(&l); stderr.push('\n'); }
                Err(_) => err_done = true,
            },
        }
    }
    // Emit any final line that had no trailing newline.
    if !out_buf.is_empty() { let l = take_line(&mut out_buf); emit_line(&window, &run_id, &l, "out"); stdout.push_str(&l); stdout.push('\n'); }
    if !err_buf.is_empty() { let l = take_line(&mut err_buf); emit_line(&window, &run_id, &l, "err"); stderr.push_str(&l); stderr.push('\n'); }

    let status = child.wait().await.map_err(|e| e.to_string())?;
    Ok(ExecResult {
        stdout: stdout.trim_end().to_string(),
        stderr: stderr.trim_end().to_string(),
        code: status.code().unwrap_or(-1),
    })
}

mod ssh {
    use russh::client;
    use russh::ChannelMsg;
    use std::sync::Arc;

    struct AcceptAll;
    impl client::Handler for AcceptAll {
        type Error = russh::Error;
        // ponytail: trust-on-first-use skipped — host key is accepted unconditionally.
        // Add known-hosts pinning if these sessions ever cross an untrusted network.
        async fn check_server_key(
            &mut self,
            _key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    pub struct Output {
        pub code: i32,
        pub stdout: String,
        pub stderr: String,
    }

    pub async fn run(
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        script: &str,
        mut on_line: impl FnMut(&str, &str),
    ) -> Result<Output, String> {
        let config = Arc::new(client::Config::default());
        let mut session = client::connect(config, (host, port), AcceptAll)
            .await
            .map_err(|e| format!("connect failed: {e}"))?;

        let ok = session
            .authenticate_password(user, pass)
            .await
            .map_err(|e| format!("auth error: {e}"))?;
        if !ok.success() {
            return Err("authentication failed (check username / password)".into());
        }

        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| e.to_string())?;
        channel.exec(true, script).await.map_err(|e| e.to_string())?;

        let mut code = -1;
        let mut stdout = String::new();
        let mut stderr = String::new();
        let (mut out_buf, mut err_buf) = (String::new(), String::new());

        // Emit only whole lines; hold the partial tail until more data arrives.
        fn flush(buf: &mut String, sink: &str, dst: &mut String, on: &mut impl FnMut(&str, &str)) {
            while let Some(i) = buf.find('\n') {
                let line: String = buf.drain(..=i).collect();
                let line = line.trim_end_matches(['\n', '\r']);
                on(line, sink);
                dst.push_str(line);
                dst.push('\n');
            }
        }

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    out_buf.push_str(&String::from_utf8_lossy(data));
                    flush(&mut out_buf, "out", &mut stdout, &mut on_line);
                }
                ChannelMsg::ExtendedData { ref data, ext } if ext == 1 => {
                    err_buf.push_str(&String::from_utf8_lossy(data));
                    flush(&mut err_buf, "err", &mut stderr, &mut on_line);
                }
                ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
                _ => {}
            }
        }
        for (buf, sink, dst) in [(out_buf, "out", &mut stdout), (err_buf, "err", &mut stderr)] {
            let tail = buf.trim_end_matches(['\n', '\r']);
            if !tail.is_empty() {
                on_line(tail, sink);
                dst.push_str(tail);
                dst.push('\n');
            }
        }

        Ok(Output {
            code,
            stdout: stdout.trim_end().to_string(),
            stderr: stderr.trim_end().to_string(),
        })
    }
}

#[tauri::command]
async fn run_ssh(
    window: Window,
    run_id: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    script: String,
) -> Result<ExecResult, String> {
    if host.is_empty() {
        return Err("SSH host is empty".into());
    }
    let out = ssh::run(&host, port, &username, &password, &script, |line, stream| {
        emit_line(&window, &run_id, line, stream);
    })
    .await?;
    Ok(ExecResult {
        stdout: out.stdout,
        stderr: out.stderr,
        code: out.code,
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_powershell, run_ssh])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
