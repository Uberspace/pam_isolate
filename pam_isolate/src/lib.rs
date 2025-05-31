use core::slice;
use std::{
    ffi::{CStr, CString, OsStr, OsString, c_char, c_int},
    os::unix::prelude::OsStrExt,
    path::PathBuf,
};

use clap::Parser;
use lib_pam_isolate::{Config, create_namespaces, try_setup_sysctl};
use log::LevelFilter;
use nix::unistd::User;
use pam::{constants::PamResultCode, module::PamHandle};
use systemd_journal_logger::JournalLog;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, value_hint = clap::ValueHint::DirPath)]
    config: PathBuf,
    #[arg(short, long, default_value_t = LevelFilter::Warn)]
    log_level: LevelFilter,
}

unsafe extern "C" {
    unsafe fn pam_putenv(pamh: *const PamHandle, name_value: *const c_char);
}

fn open_session(args: Args, pamh: &PamHandle) -> anyhow::Result<()> {
    let config = Config::load(args.config)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let username = pamh
        .get_user(None)
        .map_err(|err| anyhow::anyhow!("get_user: {err:?}"))?;
    if !config.users.ignore.is_empty() && config.users.ignore.contains(&username) {
        log::debug!("[pam_isolate] Ignored user {username}.");
        return Ok(());
    }

    let Some(passwd) = User::from_name(&username)? else {
        log::error!("[pam_isolate] Unknown user name {username}");
        return Ok(());
    };

    create_namespaces(
        &rt,
        &username,
        passwd.uid,
        passwd.gid,
        &config.mount,
        &config.user_env,
        &config.net.loopback,
        |key, value| {
            let s = CString::new(format!("{key}={value}")).unwrap();
            unsafe {
                pam_putenv(pamh as *const PamHandle, s.as_ptr());
                std::env::set_var(key, value);
            }
        },
    )?;

    if !config.sysctl.is_empty() {
        try_setup_sysctl(&config.sysctl);
    }

    log::info!("[pam_isolate] User logged in");

    Ok(())
}

/// A new PAM session is opened.
///
/// # Safety
/// Only called by C code, which presumably knows what it's doing. `argv` needs to point to valid memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const u8,
) -> PamResultCode {
    let arg0 = OsString::new();
    let args = std::iter::once(arg0.as_ref()).chain(unsafe {
        slice::from_raw_parts(argv, argc as _)
            .iter()
            .map(|arg| OsStr::from_bytes(CStr::from_ptr(*arg as *const i8).to_bytes()))
    });

    let args = Args::parse_from(args);

    JournalLog::new()
        .unwrap()
        .with_extra_fields(vec![("OBJECT_EXE", "pam_isolate.so")])
        .install()
        .unwrap();
    log::set_max_level(args.log_level);

    match open_session(args, unsafe { &*pamh }) {
        Ok(()) => PamResultCode::PAM_SUCCESS,
        Err(err) => {
            log::error!("[pam_isolate] open_session: {err:?}");
            PamResultCode::PAM_ABORT
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}
