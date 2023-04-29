use std::{
    fs::{read_dir, OpenOptions},
    path::{Path, PathBuf},
};

use fs4::FileExt;
use nix::{
    fcntl::{open, OFlag},
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::stat::Mode,
    unistd::{close, Gid, Pid, Uid},
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

fn get_first_process_by_uid(uid: Uid) -> anyhow::Result<Option<Pid>> {
    // Read the '/proc' directory
    let proc_dir = read_dir("/proc")?;

    // Find the PID of a process belonging to the specified user
    for entry in proc_dir.flatten() {
        let entry_path = entry.path();
        if let Some(pid_str) = entry_path.file_name().and_then(|s| s.to_str()) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                // Check if the process belongs to the specified user
                if let Ok(status) = nix::sys::stat::stat(entry_path.join("status").as_path()) {
                    if Uid::from_raw(status.st_uid) == uid {
                        return Ok(Some(Pid::from_raw(pid)));
                    }
                }
            }
        }
    }

    Ok(None)
}

fn create_namespaces_exclusive(
    rt: &Runtime,
    username: &str,
    uid: Uid,
    gid: Gid,
    mount_config: &config::Mount,
) -> anyhow::Result<()> {
    rt.block_on(create_interface(username, uid))?;

    let first_pid = get_first_process_by_uid(uid)?;

    if let Some(first_pid) = first_pid {
        log::info!("Attaching to namespace of pid {first_pid}");
        let mntns_fd = open(
            &["/", "proc", &first_pid.to_string(), "ns", "mnt"]
                .iter()
                .collect::<PathBuf>(),
            OFlag::O_RDONLY,
            Mode::empty(),
        )?;
        setns(mntns_fd, CloneFlags::CLONE_NEWNS)?;
        close(mntns_fd)?;
    } else {
        unshare(CloneFlags::CLONE_NEWNS)?;
        log::debug!("[pam_isolate] unshare(CLONE_NEWNS) successful.");

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
    let run_path: PathBuf = ["/", "var", "run", "user", &uid.to_string(), "pam_isolate"]
        .iter()
        .collect();
    std::fs::create_dir_all(&run_path).expect("mkdir {run_path}");

    let mut lock_path = run_path;
    lock_path.push("lockfile");

    log::debug!("[pam_isolate] lock file path: {lock_path:?}");

    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)?;
    lock_file.lock_exclusive()?;

    // We have to make sure to unlock the file afterwards, even in the case of an error!
    let result = create_namespaces_exclusive(rt, username, uid, gid, mount_config);
    let result2 = lock_file.unlock();

    if result.is_err() {
        drop(lock_file);
        result
    } else {
        result2.map_err(|err| err.into())
    }
}
