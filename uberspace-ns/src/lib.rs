use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use fs4::FileExt;
use nix::{
    fcntl::{open, readlink, OFlag},
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::stat::Mode,
    unistd::{close, symlinkat, unlink, Gid, Uid},
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
    mount_config: &config::Mount,
    lock_file: &mut File,
    mut mnt_ns_path: PathBuf,
) -> anyhow::Result<()> {
    rt.block_on(create_interface(username, uid))?;

    mnt_ns_path.push("mnt.ns");
    log::debug!("[pam_isolate] mount namespace file path: {mnt_ns_path:?}");

    let mut lock_data = String::new();
    lock_file.read_to_string(&mut lock_data)?;

    if lock_data.is_empty() {
        unshare(CloneFlags::CLONE_NEWNS)?;
        log::debug!("[pam_isolate] unshare(CLONE_NEWNS) successful.");
        let namespace_link = readlink("/proc/self/ns/mnt")?;
        eprintln!("namespace_link = {namespace_link:?}");
        unlink(&mnt_ns_path).ok();
        symlinkat(namespace_link.as_os_str(), None, &mnt_ns_path)?;

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

        write!(lock_file, "initialized")?;
    } else {
        let mntns_fd = open(Path::new(&mnt_ns_path), OFlag::O_RDONLY, Mode::empty())?;
        setns(mntns_fd, CloneFlags::CLONE_NEWNS)?;
        close(mntns_fd)?;
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

    let mut lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)?;
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
    let result2 = lock_file.unlock();

    if result.is_err() {
        drop(lock_file);
        unlink(&lock_path)?;
        result
    } else {
        result2.map_err(|err| err.into())
    }
}
