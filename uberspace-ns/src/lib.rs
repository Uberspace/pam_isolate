use std::{fs::File, path::PathBuf};

use fs4::FileExt;
use rtnetlink::{new_connection, NetworkNamespace};
use serde::Deserialize;
use tokio::runtime::Runtime;

#[derive(Debug, Default, Deserialize)]
pub struct Mount {
    pub tmp: String,
    pub size: String,
}

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

pub fn create_namespaces(
    rt: &Runtime,
    username: &str,
    uid: u32,
    _mount: &Mount,
) -> anyhow::Result<()> {
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
    rt.block_on(create_interface(username))?;

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

    Ok(())
}
