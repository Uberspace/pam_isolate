use std::{
    fmt::Write,
    fs::{File, OpenOptions},
    io::Read,
    os::fd::IntoRawFd,
    path::PathBuf,
};

use fs4::FileExt;
use nix::{
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    unistd::{Gid, Uid},
};
use rtnetlink::{new_connection, NetworkNamespace};
use tokio::runtime::Runtime;

mod config;
pub use config::*;

async fn create_interface(username: &str) -> anyhow::Result<()> {
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
}

fn create_namespaces_exclusive(
    rt: &Runtime,
    username: &str,
    uid: Uid,
    gid: Gid,
    mount_config: &config::Mount,
    lock_file: &mut File,
    mut mnt_ns_path: PathBuf,
) -> anyhow::Result<()> {
    rt.block_on(create_interface(username))?;

    mnt_ns_path.push("mnt.ns");
    log::debug!("[pam_isolate] mount namespace file path: {mnt_ns_path:?}");

    let mut lock_data = String::new();
    lock_file.read_to_string(&mut lock_data)?;

    if lock_data.is_empty() {
        unshare(CloneFlags::CLONE_NEWNS)?;
        log::debug!("[pam_isolate] unshare(CLONE_NEWNS) successful.");
        mount(
            Some("/proc/self/ns/mnt"),
            &mnt_ns_path,
            None::<&PathBuf>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        umount(mount_config.tmp.as_str())?;
        mount(
            Some("tmpfs"),
            mount_config.tmp.as_str(),
            Some("tmpfs"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(
                format!(
                    "size={},uid={},gid={},mode=777",
                    mount_config.size, uid, gid,
                )
                .as_str(),
            ),
        )?;

        lock_data.write_str("initialized")?;
    } else {
        let mntns = File::open(mnt_ns_path)?;
        setns(mntns.into_raw_fd(), CloneFlags::CLONE_NEWNS)?;
    }
    Ok(())
}

pub fn create_namespaces(
    rt: &Runtime,
    username: &str,
    uid: Uid,
    gid: Gid,
    mount_config: &config::Mount,
) -> anyhow::Result<()> {
    let run_path: PathBuf = ["/", "var", "run", "user", &uid.to_string(), "pam_isolate"]
        .iter()
        .collect();
    std::fs::create_dir_all(&run_path).expect("mkdir {run_path}");

    let mut lock_path = run_path.clone();
    lock_path.push("lockfile");
    log::debug!("[pam_isolate] lock file path: {lock_path:?}");

    let mut lock_file = OpenOptions::new().create(true).open(lock_path)?;
    lock_file.lock_exclusive()?;

    // We have to make sure to unlock the file afterwards, even in the case of an error!
    let result = create_namespaces_exclusive(
        rt,
        username,
        uid,
        gid,
        mount_config,
        &mut lock_file,
        run_path,
    );
    lock_file.unlock()?;

    result
}
