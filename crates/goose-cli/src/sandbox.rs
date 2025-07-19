use anyhow::{Context, Result};
use std::env;
use std::os::unix::process::CommandExt;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::process::Command;

fn build_profile(write_paths: &[PathBuf]) -> Result<String> {
    // Collect the directories that Goose should be allowed to write to.

    // TODO: Figure out how we want to handle failure here.
    // TODO: Figure out all the right paths.
    let home = env::var("HOME").expect("HOME is not set");
    let goose_local_dir = format!("{home}/.goose");
    let goose_share_dir = format!("{home}/.local/share/goose");
    let goose_state_dir_local = format!("{home}/.local/state/goose");
    let goose_config_home = format!("{home}/.config/goose");
    let uv_cache_dir = format!("{home}/.cache/uv");
    let uv_cache_home = format!("{home}/.cache");

    let extras: Vec<String> = write_paths
        .iter()
        .filter_map(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .collect();

    // Seatbelt requires a separate `(subpath "...")` line for each directory.
    let extra_rules: String = extras
        .iter()
        .map(|p| format!("    (subpath \"{p}\")\n"))
        .collect();

    // (allow file-read* file-write* file-link file-clone

    // Build the seatbelt profile.
    let profile = format!(
        r#"(version 1)
(allow default)

;; deny everywhere ...
(deny file-write* file-link file-clone)

;; ...but allow them under explicit subpaths...
(allow file-write* file-link file-clone
    (subpath "{local}")
    (subpath "{share}")
    (subpath "{config}")
    (subpath "{state}")
    (subpath "{uv_cache}")
    (subpath "{cache}")
{extra_rules}
)
"#,
        local = goose_local_dir,
        share = goose_share_dir,
        config = goose_config_home,
        state = goose_state_dir_local,
        uv_cache = uv_cache_dir,
        cache = uv_cache_home,
        extra_rules = extra_rules,
    );

    println!("profile: {}", profile);

    Ok(profile)
}

/// Apply a macOS seatbelt sandbox to the current process by re‑executing
/// ourselves under `sandbox-exec`.
#[cfg(target_os = "macos")]
pub fn apply_sandbox(write_paths: &[PathBuf]) -> Result<()> {
    // Avoid an infinite re‑exec loop if we're already sandboxed.
    if env::var_os("GOOSE_SANDBOX_APPLIED").is_some() {
        return Ok(());
    }

    let profile = build_profile(write_paths)?;

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
    Err(cmd.exec().into())
}
