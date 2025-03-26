use std::{ffi::CString, os::unix::prelude::OsStrExt};

use anyhow::anyhow;
use lib_pam_isolate::{create_namespaces, try_setup_sysctl, Config};
use log::LevelFilter;
use nix::unistd::{execv, getegid, geteuid, getgid, getuid, setgid, setuid, User};

fn main() -> anyhow::Result<()> {
    systemd_journal_logger::init_with_extra_fields(vec![("OBJECT_EXE", "wrapns")]).unwrap();
    log::set_max_level(LevelFilter::Warn);

    let args: Vec<_> = std::env::args_os().collect();
    if args.len() < 2 {
        log::error!("Pass a command to execute");
        return Err(anyhow!("Pass a command to execute"));
    }

    let config = Config::load(Config::default_path())?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let uid = getuid();
    let euid = geteuid();
    let gid = getgid();
    let egid = getegid();

    let Some(passwd) = User::from_uid(uid)? else {
        log::error!("Unknown user with id {uid}");
        return Err(anyhow!("Unknown user"));
    };

    if !config.users.ignore.is_empty() && config.users.ignore.contains(&passwd.name) {
        log::debug!("Ignored user {}.", passwd.name);
        return Err(anyhow!("Ignored user"));
    }

    setuid(euid)?;
    setgid(egid)?;
    create_namespaces(
        &rt,
        &passwd.name,
        uid,
        gid,
        &config.mount,
        &config.user_env,
        &config.net.loopback,
        |key, value| {
            std::env::set_var(key, value);
        },
    )?;
    if !config.sysctl.is_empty() {
        try_setup_sysctl(&config.sysctl);
    }
    setgid(gid)?;
    setuid(uid)?;

    execv(
        &CString::new(args[1].as_bytes())?,
        &args
            .into_iter()
            .skip(1)
            .map(|arg| CString::new(arg.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?,
    )?;

    Ok(())
}
