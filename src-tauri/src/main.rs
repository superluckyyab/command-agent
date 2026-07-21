#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Backend for Command Runner: it actually runs the commands the UI configures.
//! Two transports — local PowerShell and remote SSH — both stream their output
//! back to the front end line by line over the `exec://line` event and return a
//! final `{ stdout, stderr, code }` once the command exits.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{State, Window};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Serialize)]
struct ExecResult {
    stdout: String,
    stderr: String,
    code: i32,
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    size: u64,
}

#[derive(Deserialize, Serialize)]
struct StoredConfig {
    version: u8,
    admin_salt: String,
    admin_hash: String,
    settings: serde_json::Value,
}

struct AuthState(Mutex<HashSet<String>>);

fn app_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| "cannot resolve executable directory".into())
}

fn config_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("command-runner.config.enc"))
}

fn key_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join(".command-runner.key"))
}

fn factory_marker_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join(".command-runner.factory-provisioned"))
}

fn provision_factory_config(factory_dir: &Path) -> Result<(), String> {
    let config = config_path()?;
    let key = key_path()?;
    if config.exists() && key.exists() {
        return Ok(());
    }
    if config.exists() || key.exists() || factory_marker_path()?.exists() {
        return Err("encrypted factory configuration is missing or incomplete; reinstall the application".into());
    }
    let factory_config = factory_dir.join("command-runner.config.enc");
    let factory_key = factory_dir.join(".command-runner.key");
    std::fs::copy(&factory_config, &config).map_err(|_| "factory encrypted configuration is missing".to_string())?;
    std::fs::copy(&factory_key, &key).map_err(|_| "factory configuration key is missing".to_string())?;
    std::fs::write(factory_marker_path()?, b"provisioned").map_err(|e| e.to_string())?;
    Ok(())
}

fn config_key() -> Result<[u8; 32], String> {
    let path = key_path()?;
    let key = std::fs::read(&path)
        .map_err(|_| "encrypted configuration key is missing; reinstall the application".to_string())?;
    key.try_into().map_err(|_| "invalid configuration key".into())
}

fn password_hash(salt: &[u8], password: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash.finalize())
}

fn save_stored_config(config: &StoredConfig) -> Result<(), String> {
    let key = config_key()?;
    let plain = serde_json::to_vec(config).map_err(|e| e.to_string())?;
    let mut nonce = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), plain.as_ref()).map_err(|e| e.to_string())?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&encrypted);
    std::fs::write(config_path()?, output).map_err(|e| e.to_string())
}

fn load_stored_config() -> Result<StoredConfig, String> {
    let path = config_path()?;
    if !path.exists() {
        return Err("encrypted configuration is missing; reinstall the application".into());
    }
    let encrypted = std::fs::read(path).map_err(|e| e.to_string())?;
    if encrypted.len() <= 12 {
        return Err("invalid encrypted configuration".into());
    }
    let key = config_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| "cannot decrypt configuration".to_string())?;
    serde_json::from_slice(&plain).map_err(|e| e.to_string())
}

fn require_session(state: &AuthState, token: &str) -> Result<(), String> {
    if state.0.lock().map_err(|_| "authentication state unavailable")?.contains(token) {
        Ok(())
    } else {
        Err("administrator authentication required".into())
    }
}

#[tauri::command]
fn load_config() -> Result<serde_json::Value, String> {
    Ok(load_stored_config()?.settings)
}

#[tauri::command]
fn login_admin(password: String, state: State<AuthState>) -> Result<String, String> {
    let config = load_stored_config()?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(config.admin_salt)
        .map_err(|_| "invalid administrator credentials")?;
    if password_hash(&salt, &password) != config.admin_hash {
        return Err("incorrect password".into());
    }
    let mut session = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut session);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session);
    state.0.lock().map_err(|_| "authentication state unavailable")?.insert(token.clone());
    Ok(token)
}

#[tauri::command]
fn save_config(token: String, config: serde_json::Value, state: State<AuthState>) -> Result<(), String> {
    require_session(&state, &token)?;
    let mut stored = load_stored_config()?;
    stored.settings = config;
    save_stored_config(&stored)
}

#[tauri::command]
fn change_admin_password(token: String, password: String, state: State<AuthState>) -> Result<(), String> {
    require_session(&state, &token)?;
    if password.trim().is_empty() {
        return Err("password cannot be empty".into());
    }
    let mut stored = load_stored_config()?;
    let mut salt = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    stored.admin_salt = base64::engine::general_purpose::STANDARD.encode(salt);
    stored.admin_hash = password_hash(&salt, &password);
    save_stored_config(&stored)
}

/// The user's working folder: `files/` next to the executable. Scripts and tools
/// dropped here are run and referenced by PowerShell (it cd's here, adds it to
/// PATH, and exposes it as `$Dir`). Created on first access.
fn files_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe
        .parent()
        .ok_or("cannot resolve executable directory")?
        .join("files");
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Reject anything that isn't a bare file name so a caller can't escape the dir.
fn safe_name(name: &str) -> Result<&str, String> {
    if name.is_empty()
        || name.contains(['/', '\\'])
        || name.contains("..")
        || name == "."
    {
        return Err("invalid file name".into());
    }
    Ok(name)
}

#[tauri::command]
fn get_files_dir() -> Result<String, String> {
    Ok(files_dir()?.to_string_lossy().into_owned())
}

#[tauri::command]
fn list_files() -> Result<Vec<FileEntry>, String> {
    let dir = files_dir()?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_file() {
            out.push(FileEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                size: meta.len(),
            });
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(out)
}

#[tauri::command]
fn delete_file(name: String) -> Result<(), String> {
    let dir = files_dir()?;
    std::fs::remove_file(dir.join(safe_name(&name)?)).map_err(|e| e.to_string())
}

#[tauri::command]
fn open_files_dir() -> Result<(), String> {
    let dir = files_dir()?;
    #[cfg(windows)]
    {
        std::process::Command::new("explorer")
            .arg(&dir)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    {
        let _ = &dir;
    }
    Ok(())
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
    // (ipconfig, netsh, …) emit UTF-8 instead of the locale's OEM code page.
    // `$ProgressPreference=SilentlyContinue` stops progress records from being
    // dumped as CLIXML on stderr. Wrapping the script in `& { … } 2>&1` merges
    // the error stream into stdout so failures like "Access is denied" arrive
    // as plain readable text instead of a CLIXML blob.
    let prelude = "chcp 65001 > $null;\
                   $ErrorActionPreference='Continue';\
                   $ProgressPreference='SilentlyContinue';\
                   $OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8;\n";
    let full = format!("{prelude}& {{\n{script}\n}} 2>&1\n");
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
    // Make the files/ folder the working directory, put it on PATH, and expose
    // it as $Dir so scripts and tools dropped there can be called by name
    // (`.\deploy.ps1`, `pscp …`, `$Dir\tool.exe`).
    let dir_setup = match files_dir() {
        Ok(dir) => {
            let d = dir.to_string_lossy().replace('\'', "''");
            format!("$Dir = '{d}'; Set-Location -LiteralPath $Dir; $env:Path = \"$Dir;\" + $env:Path;\n")
        }
        Err(_) => String::new(),
    };

    let mut cmd = tokio::process::Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &encode_ps(&format!("{dir_setup}{script}")),
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
        .setup(|app| {
            let factory_config = app
                .path_resolver()
                .resolve_resource("factory-config/command-runner.config.enc")
                .ok_or_else(|| std::io::Error::other("factory encrypted configuration resource is missing"))?;
            let factory_dir = factory_config
                .parent()
                .ok_or_else(|| std::io::Error::other("factory configuration resource is invalid"))?;
            provision_factory_config(factory_dir).map_err(std::io::Error::other)?;
            load_stored_config().map_err(std::io::Error::other)?;
            Ok(())
        })
        .manage(AuthState(Mutex::new(HashSet::new())))
        .invoke_handler(tauri::generate_handler![
            run_powershell,
            run_ssh,
            get_files_dir,
            list_files,
            delete_file,
            open_files_dir,
            load_config,
            login_admin,
            save_config,
            change_admin_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
