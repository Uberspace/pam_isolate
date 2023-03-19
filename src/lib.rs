use core::slice;
use std::{
    ffi::{c_char, c_int, CStr, CString, OsStr, OsString},
    os::unix::prelude::OsStrExt,
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;
use log::LevelFilter;
use pam::{constants::PamResultCode, module::PamHandle};

use crate::config::Config;

mod bindings;
mod config;

use bindings::{getpwnam, mount, umount, unshare, CLONE_NEWNS, MS_NODEV, MS_NOEXEC, MS_NOSUID};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(short, long, default_value_t = LevelFilter::Warn)]
    log_level: LevelFilter,
}

fn open_session(args: Args, pamh: &PamHandle) -> anyhow::Result<()> {
    let config = Config::load(args.config)?;

    let user = pamh
        .get_user(None)
        .map_err(|err| anyhow::anyhow!("get_user: {err:?}"))?;
    if !config.users.ignore.is_empty() && config.users.ignore.contains(&user) {
        log::debug!("[pam_isolate] Ignored user {user}.");
        return Ok(());
    }

    if unsafe { unshare(CLONE_NEWNS as _) } == -1 {
        return Err(std::io::Error::last_os_error()).context("unshare");
    }

    log::debug!("[pam_isolate] unshare(CLONE_NEWNS) successful.");

    let user_c = CString::new(user).unwrap();
    let passwd = unsafe { getpwnam(user_c.as_ptr()) };

    const TMPFS_RAW: &[u8; 6] = b"tmpfs\0";
    let path = CString::new(config.mount.tmp).unwrap();
    let options = CString::new(format!(
        "size={},uid={},gid={},mode=777",
        config.mount.size,
        unsafe { (*passwd).pw_uid },
        unsafe { (*passwd).pw_gid }
    ))
    .unwrap();

    if unsafe { umount(path.as_ptr() as _) } == -1 {
        return Err(std::io::Error::last_os_error()).context("umount");
    }

    if unsafe {
        mount(
            TMPFS_RAW.as_ptr() as _,
            path.as_ptr() as _,
            TMPFS_RAW.as_ptr() as _,
            (MS_NOEXEC | MS_NOSUID | MS_NODEV) as _,
            options.as_ptr() as _,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error()).context("mount");
    }

    drop(options);
    drop(path);
    drop(user_c);

    // continue here
    log::info!("[pam_isolate] User logged in");

    Ok(())
}

/// A new PAM session is opened.
///
/// # Safety
/// Only called by C code, which presumably knows what it's doing. `argv` needs to point to valid memory.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const u8,
) -> PamResultCode {
    let arg0 = OsString::new();
    let args = std::iter::once(arg0.as_ref()).chain(
        slice::from_raw_parts(argv, argc as _)
            .iter()
            .map(|arg| OsStr::from_bytes(CStr::from_ptr(*arg as *const i8).to_bytes())),
    );

    let args = Args::parse_from(args);

    systemd_journal_logger::init().unwrap();
    log::set_max_level(args.log_level);

    match open_session(args, &*pamh) {
        Ok(()) => PamResultCode::PAM_SUCCESS,
        Err(err) => {
            log::error!("[pam_isolate] {err:?}");
            PamResultCode::PAM_ABORT
        }
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}
