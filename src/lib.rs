use core::slice;
use std::{
    ffi::{c_char, c_int, CStr, CString, OsStr, OsString},
    fs::File,
    os::unix::prelude::OsStrExt,
    path::PathBuf,
};

use clap::Parser;
use fs4::FileExt;
use log::LevelFilter;
use pam::{constants::PamResultCode, module::PamHandle};
use rtnetlink::{new_connection, NetworkNamespace};

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

fn create_interface(username: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        log::debug!("[pam_isolate] Starting network setup");
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        match NetworkNamespace::child_process_create_ns(format!("{username}_ns")) {
            Ok(path) => log::info!("[pam_isolate] Namespace created at {path}"),
            Err(err) => {
                if let rtnetlink::Error::NamespaceError(msg) = &err {
                    if msg.contains("EEXIST") {
                        log::info!("[pam_isolate] Namespace already exists");
                    } else {
                        return Err(err.into());
                    }
                } else {
                    return Err(err.into());
                }
            }
        }

        let mut links = handle
            .link()
            .add()
            .veth("inside0".to_owned(), "outside0".to_owned());
        links
            .message_mut()
            .nlas
            .push(netlink_packet_route::link::nlas::Nla::NewNetnsId(
                format!("{username}_ns").as_bytes().to_vec(),
            ));

        match links.execute().await {
            Ok(()) => {
                log::info!("[pam_isolate] Link created");
                Ok(())
            }
            Err(err) => {
                if let rtnetlink::Error::NetlinkError(err_msg) = &err {
                    if err_msg.code == -17 {
                        log::info!("[pam_isolate] Link already exists");
                        Ok(())
                    } else {
                        Err(err.into())
                    }
                } else {
                    Err(err.into())
                }
            }
        }
    })
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

    let user_c = CString::new(user.clone()).unwrap();
    let passwd = unsafe { getpwnam(user_c.as_ptr()) };
    let uid = unsafe { (*passwd).pw_uid };

    let run_path: PathBuf = ["/", "var", "run", "user", &uid.to_string(), "pam_isolate"]
        .iter()
        .collect();
    std::fs::create_dir_all(&run_path).expect("mkdir {run_path}");

    let mut lock_path = run_path.clone();
    lock_path.push("lockfile");
    log::debug!("[pam_isolate] lock file path: {lock_path:?}");
    let mut mnt_ns_path = run_path;
    mnt_ns_path.push("mnt.ns");
    log::debug!("[pam_isolate] mount namespace file path: {mnt_ns_path:?}");

    let lock_file = File::create(lock_path)?;
    lock_file.lock_exclusive()?;
    create_interface(&user)?;

    // if unsafe { unshare(CLONE_NEWNS as _) } == -1 {
    //     return Err(std::io::Error::last_os_error()).context("unshare");
    // }
    // log::debug!("[pam_isolate] unshare(CLONE_NEWNS) successful.");

    // let mnt_ns: PathBuf = ["/", "proc", "self", "ns", "mnt"].iter().collect();

    // const TMPFS_RAW: &[u8; 6] = b"tmpfs\0";
    // let path = CString::new(config.mount.tmp).unwrap();
    // let options = CString::new(format!(
    //     "size={},uid={},gid={},mode=777",
    //     config.mount.size,
    //     unsafe { (*passwd).pw_uid },
    //     unsafe { (*passwd).pw_gid }
    // ))
    // .unwrap();

    // if unsafe { umount(path.as_ptr() as _) } == -1 {
    //     return Err(std::io::Error::last_os_error()).context("umount");
    // }

    // if unsafe {
    //     mount(
    //         TMPFS_RAW.as_ptr() as _,
    //         path.as_ptr() as _,
    //         TMPFS_RAW.as_ptr() as _,
    //         (MS_NOEXEC | MS_NOSUID | MS_NODEV) as _,
    //         options.as_ptr() as _,
    //     )
    // } == -1
    // {
    //     return Err(std::io::Error::last_os_error()).context("mount");
    // }

    // drop(options);
    // drop(path);
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

    systemd_journal_logger::init_with_extra_fields(vec![("OBJECT_EXE", "pam_isolate.so")]).unwrap();
    log::set_max_level(args.log_level);

    match open_session(args, &*pamh) {
        Ok(()) => PamResultCode::PAM_SUCCESS,
        Err(err) => {
            log::error!("[pam_isolate] open_session: {err:?}");
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
