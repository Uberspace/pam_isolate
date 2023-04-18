use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use fs4::FileExt;
use nix::{
    fcntl::{open, OFlag},
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::stat::Mode,
    unistd::{close, getpid, Gid, Uid},
};
use rtnetlink::{new_connection, NetworkNamespace};
use tokio::runtime::Runtime;

mod config;
pub use config::*;

async fn create_interface(username: &str, uid: Uid) -> anyhow::Result<()> {
    log::debug!("[pam_isolate] Starting network setup");

    let netns = format!("{username}_ns");
    let netns_path = ["/", "run", "netns", &netns].iter().collect::<PathBuf>();

    if netns_path.exists() {
        let netns_fd = open(Path::new(&netns_path), OFlag::O_RDONLY, Mode::empty())?;
        setns(netns_fd, CloneFlags::CLONE_NEWNET)?;
        close(netns_fd)?;

        log::info!("[pam_isolate] Joined existing namespace.");
        Ok(())
    } else {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let netns_path = NetworkNamespace::child_process_create_ns(netns)?;
        NetworkNamespace::unshare_processing(netns_path.clone())?;
        log::info!("Created net namespace {netns_path:?}");
        let netns_fd = open(Path::new(&netns_path), OFlag::O_RDONLY, Mode::empty())?;

        let mut links = handle
            .link()
            .add()
            .veth(format!("veth_{uid}_out"), format!("veth_{uid}_in"));
        links
            .message_mut()
            .nlas
            .push(netlink_packet_route::link::nlas::Nla::NetNsFd(netns_fd));
        let result = links.execute().await;
        if result.is_ok() {
            log::info!("[pam_isolate] Link created");
        }
        close(netns_fd)?;
        result.map_err(|err| err.into())
    }
}

fn create_namespaces_exclusive(
    rt: &Runtime,
    username: &str,
    uid: Uid,
    gid: Gid,
    run_path: &Path,
    mount_config: &config::Mount,
) -> anyhow::Result<()> {
    rt.block_on(create_interface(username, uid))?;

    let mut mnt_ns: PathBuf = run_path.to_owned();
    mnt_ns.push("mntns");
    let mntns_fd = open(&mnt_ns, OFlag::O_RDONLY, Mode::empty());
    if let Ok(mntns_fd) = mntns_fd {
        log::info!("[pam_isolate] Attaching to existing mount namespace");
        setns(mntns_fd, CloneFlags::CLONE_NEWNS)?;
        close(mntns_fd)?;
    } else {
        unshare(CloneFlags::CLONE_NEWNS)?;
        log::debug!("[pam_isolate] unshare(CLONE_NEWNS) successful.");

        let mntns_fd = open(&mnt_ns, OFlag::O_CREAT, Mode::from_bits_truncate(0o644))?;
        close(mntns_fd)?;
        mount(
            Some(
                &["/", "proc", &getpid().to_string(), "ns", "mnt"]
                    .iter()
                    .collect::<PathBuf>(),
            ),
            &mnt_ns,
            None::<&Path>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
        log::info!("[pam_isolate] bind mounted mount namespace to {mnt_ns:?}");

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
    let run_path: PathBuf = ["/", "run", "user", &uid.to_string(), "pam_isolate"]
        .iter()
        .collect();
    std::fs::create_dir_all(&run_path).expect("mkdir {run_path}");

    let mut lock_path = run_path.clone();
    lock_path.push("lockfile");

    log::debug!("[pam_isolate] lock file path: {lock_path:?}");

    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)?;
    lock_file.lock_exclusive()?;

    let run_path: PathBuf = ["/", "home", username, ".pam_isolate"].iter().collect();
    std::fs::create_dir_all(&run_path).expect("mkdir {run_path}");

    // We have to make sure to unlock the file afterwards, even in the case of an error!
    let result = create_namespaces_exclusive(rt, username, uid, gid, &run_path, mount_config);
    let result2 = lock_file.unlock();

    if result.is_err() {
        drop(lock_file);
        result
    } else {
        result2.map_err(|err| err.into())
    }
}
