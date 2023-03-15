use core::slice;
use std::{
    ffi::{c_char, c_int, CStr, OsStr},
    os::unix::prelude::OsStrExt,
    path::PathBuf,
};

use clap::Parser;
use pam::{constants::PamResultCode, module::PamHandle};

use crate::config::Config;

mod config;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

fn open_session(args: Args, pamh: &PamHandle) -> anyhow::Result<()> {
    let config = Config::load(args.config)?;

    if !config.ignore_users.is_empty() {
        let user = pamh
            .get_user(None)
            .map_err(|err| anyhow::anyhow!("{err:?}"))?;
        if config.ignore_users.contains(&user) {
            return Ok(());
        }
    }

    // continue here

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
    let args = slice::from_raw_parts(argv, argc as _)
        .iter()
        .map(|arg| OsStr::from_bytes(CStr::from_ptr(*arg as *const i8).to_bytes()));

    let args = Args::parse_from(args);

    match open_session(args, &*pamh) {
        Ok(()) => PamResultCode::PAM_SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
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
