use anyhow::{Context, Result};
use std::env;
use std::os::unix::process::CommandExt;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::process::Command;

/// Apply a macOS seatbelt sandbox to the current process by re‑executing
/// ourselves under `sandbox-exec`.
#[cfg(target_os = "macos")]
pub fn apply_sandbox(write_paths: &[PathBuf]) -> Result<()> {
    let _ = write_paths; // TODO: use this

    // Avoid an infinite re‑exec loop if we're already sandboxed.
    if env::var_os("GOOSE_SANDBOX_APPLIED").is_some() {
        return Ok(());
    }

    // Collect the directories that Goose should be allowed to write to.
    // Fallbacks are chosen so the program keeps working even if the caller
    // hasn't set the env‑vars.
    let target_dir = env::var("TARGET_DIR")
        .ok()
        .unwrap_or_else(|| env::current_dir().unwrap().to_string_lossy().into_owned());

    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let goose_local_dir = env::var("GOOSE_LOCAL_DIR").unwrap_or_else(|_| format!("{home}/.goose"));
    let goose_state_dir = env::var("GOOSE_STATE_DIR").unwrap_or_else(|_| "/tmp/goose_state".into());
    let goose_config_dir =
        env::var("GOOSE_CONFIG_DIR").unwrap_or_else(|_| "/tmp/goose_config".into());

    // Build the seatbelt profile.
    let profile = format!(
        r#"(version 1)
(allow default)

;; deny writes everywhere …
(deny file-write*)

;; …but allow them under explicit subpaths
(allow file-write*
    (subpath "{target}")
    (subpath "{local}")
    (subpath "{state}")
    (subpath "{config}")
)
"#,
        target = target_dir,
        local = goose_local_dir,
        state = goose_state_dir,
        config = goose_config_dir,
    );

    // Persist the profile to a temporary file so we can point sandbox‑exec at it.
    let mut tmp = tempfile::NamedTempFile::new().context("creating temporary sandbox profile")?;
    use std::io::Write;
    tmp.write_all(profile.as_bytes())
        .context("writing sandbox profile")?;
    tmp.flush()?;

    // Re‑exec ourselves under sandbox‑exec with the profile.
    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-f").arg(tmp.path());
    cmd.arg(env::current_exe()?);
    for arg in env::args_os().skip(1) {
        cmd.arg(arg);
    }
    cmd.env("GOOSE_SANDBOX_APPLIED", "1");

    // `exec` only returns if it fails. Convert that error into anyhow::Error so
    // the caller can handle it in the usual way.
    cmd.exec();
}

/// Non‑macOS platforms: do nothing.
#[cfg(not(target_os = "macos"))]
fn apply_sandbox() -> Result<()> {
    Ok(())
}
