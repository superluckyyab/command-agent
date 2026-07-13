# Command Runner

A Windows desktop tool for configuring **PowerShell** and **SSH** commands with
if/else result logic and running them for real. Built with [Tauri](https://tauri.app/)
(Rust backend + the Claude-designed `.dc.html` front end).

## Features

- **Console** — run every configured command in order; live, streamed output.
- **Commands** — PowerShell, remote SSH, or a Computer-Control (IP config) command,
  each with `if result … then … else …` rules evaluated against real output/exit code.
- **Shortcuts** — one-click PowerShell buttons in the top bar.
- **User Settings** — pick the network adapter, set the Configuration password
  (default `admin` — change it), see whether the execution backend is connected.
- Commands, shortcuts and settings persist locally between runs.

> IP configuration and adapter restarts need the app started **as Administrator**.

## How it works

The single source of truth for the UI is [`Command Runner.dc.html`](Command%20Runner.dc.html).
`build.mjs` assembles a self-contained `dist/` (React + the dc runtime + fonts +
icons, all vendored — no CDN) that Tauri bundles. The Rust backend in
[`src-tauri/src/main.rs`](src-tauri/src/main.rs) runs the commands:

- `run_powershell` — `powershell -EncodedCommand …`, output streamed line by line.
- `run_ssh` — real SSH via [`russh`](https://crates.io/crates/russh) (pure Rust).

## Develop

```bash
npm install
npm run tauri dev      # runs build.mjs, then Tauri (Windows: real execution)
```

In a plain browser there is no backend, so commands report that instead of running.

## Build / Release

Push a `v*` tag; the [workflow](.github/workflows/release.yml) builds on
`windows-latest` and publishes an NSIS installer plus a portable zip to a GitHub
Release. You can also trigger it manually from the Actions tab.

## Security notes

- SSH and admin passwords are stored **in plaintext** in the app's local storage —
  same trust level as the machine's user. The SSH host key is accepted
  unconditionally (no known-hosts pinning).
