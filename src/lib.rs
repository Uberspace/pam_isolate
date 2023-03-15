use core::slice;
use std::{
    ffi::{c_char, c_int, CStr, OsStr, OsString},
    os::unix::prelude::OsStrExt,
    path::PathBuf,
};

use clap::Parser;
use log::LevelFilter;
use pam::{constants::PamResultCode, module::PamHandle};

use crate::config::Config;

mod config;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(short, long, default_value_t = LevelFilter::Warn)]
    log_level: LevelFilter,
}

fn open_session(args: Args, pamh: &PamHandle) -> anyhow::Result<()> {
    let config = Config::load(args.config)?;

    if !config.users.ignore.is_empty() {
        let user = pamh
            .get_user(None)
            .map_err(|err| anyhow::anyhow!("{err:?}"))?;
        if config.users.ignore.contains(&user) {
            log::debug!("[pam_isolate] Ignored user {user}.");
            return Ok(());
        }
    }

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
            log::error!("[pam_isolate] {err}");
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
