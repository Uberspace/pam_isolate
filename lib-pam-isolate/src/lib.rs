#![allow(clippy::too_many_arguments)]
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{read_dir, OpenOptions},
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
};

use fs4::FileExt;
use futures::{stream::TryStreamExt, StreamExt};
use nix::{
    fcntl::{open, OFlag},
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::stat::Mode,
    unistd::{close, getpid, Gid, Pid, Uid},
};
use rtnetlink::{new_connection, NetworkNamespace};
use sysctl::{Ctl, CtlValue, Sysctl};
use tokio::runtime::Runtime;

mod config;
pub use config::*;

struct AddressPair {
    v4: Ipv4Addr,
    v4_prefix_len: u8,
    v6: Ipv6Addr,
    v6_prefix_len: u8,
}

// TODO: pass UID as parameter here (ignored for now)
fn generate_veth_addresses(_uid: Uid) -> (AddressPair, AddressPair) {
    (
        AddressPair {
            v4: Ipv4Addr::new(100, 64, 255, 1),
            v4_prefix_len: 24,
            v6: Ipv6Addr::new(0xfd75, 0x6272, 0x7370, 0xffff, 0, 0, 0, 0x0001),
            v6_prefix_len: 64,
        },
        AddressPair {
            v4: Ipv4Addr::new(100, 64, 255, 2),
            v4_prefix_len: 24,
            v6: Ipv6Addr::new(0xfd75, 0x6272, 0x7370, 0xffff, 0, 0, 0, 0x0002),
            v6_prefix_len: 64,
        },
    )
}

async fn get_link_index(handle: &rtnetlink::Handle, name: &str) -> anyhow::Result<Option<u32>> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();

    if let Some(link) = links.try_next().await? {
        links.collect::<Vec<_>>().await; // drain stream
        Ok(Some(link.header.index))
    } else {
        Ok(None)
    }
}

async fn create_interface(username: &str, uid: Uid, loopback: &str) -> anyhow::Result<()> {
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
        log::info!("[pam_isolate] Created net namespace {netns_path:?}");

        let out_name = format!("veth_{uid}_out");
        let in_name = format!("veth_{uid}_in");

        let netns_fd = open(Path::new(&netns_path), OFlag::O_RDONLY, Mode::empty())?;
        let mut links = handle.link().add().veth(out_name.clone(), in_name.clone());
        links
            .message_mut()
            .nlas
            .push(netlink_packet_route::link::nlas::Nla::NetNsFd(netns_fd));
        let result = links.execute().await;
        close(netns_fd)?;
        result?;
        log::info!("[pam_isolate] Link created");

        let (out_addr, in_addr) = generate_veth_addresses(uid);
        if let Some(out_index) = get_link_index(&handle, &out_name).await? {
            handle
                .address()
                .add(out_index, IpAddr::V4(out_addr.v4), out_addr.v4_prefix_len)
                .execute()
                .await?;
            handle
                .address()
                .add(out_index, IpAddr::V6(out_addr.v6), out_addr.v6_prefix_len)
                .execute()
                .await?;
            handle.link().set(out_index).up().execute().await?;
        }

        // We need to set up a new connection here in order to move to the new namespace for this operation.
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        if let Some(lo_index) = get_link_index(&handle, loopback).await? {
            handle.link().set(lo_index).up().execute().await?;
            log::info!("[pam_isolate] Found loopback at index {lo_index}, set up");
        }

        if let Some(in_index) = get_link_index(&handle, &in_name).await? {
            handle
                .address()
                .add(in_index, IpAddr::V4(in_addr.v4), in_addr.v4_prefix_len)
                .execute()
                .await?;
            handle
                .address()
                .add(in_index, IpAddr::V6(in_addr.v6), in_addr.v6_prefix_len)
                .execute()
                .await?;
        }

        Ok(())
    }
}

fn get_first_process_by_uid_or_env(uid: Uid, user_env: &str) -> anyhow::Result<Option<Pid>> {
    // Read the '/proc' directory
    let proc_dir = read_dir("/proc")?;
    let user_env = user_env.as_bytes();
    let uid_string = uid.to_string();
    let uid_bytes = uid_string.as_bytes();

    // Find the PID of a process belonging to the specified user
    for entry in proc_dir.flatten() {
        let entry_path = entry.path();
        if let Some(pid_str) = entry_path.file_name().and_then(|s| s.to_str()) {
            if let Ok(pid) = pid_str.parse() {
                // Check if the process belongs to the specified user
                if let Ok(status) = nix::sys::stat::stat(entry_path.join("status").as_path()) {
                    if Uid::from_raw(status.st_uid) == uid {
                        let exe = nix::fcntl::readlink(&entry_path.join("exe"))?;
                        if exe != OsStr::from_bytes(b"/usr/lib/systemd/systemd") {
                            // systemd creates some processes for a logged in user to manage the PAM session.
                            // Since those don't operate under the namespace, we have to ignore them.
                            return Ok(Some(Pid::from_raw(pid)));
                        }
                    } else if status.st_uid == 0 {
                        // Alternatively, this process could also be in the process of becoming the specified user.
                        // This is here to avoid a race condition, because in a PAM module we can't unlock our
                        // lockfile after the call to `setuid()`, it has to happen before that.
                        let mut environ_path = entry_path.clone();
                        environ_path.push("environ");
                        let mut environ = BufReader::new(std::fs::File::open(environ_path)?);
                        let mut buffer = Vec::new();
                        while environ.read_until(0, &mut buffer)? > 0 {
                            let mut iter = buffer.splitn(2, |c| *c == b'=');
                            if iter.next().unwrap() == user_env
                                && iter
                                    .next()
                                    .filter(|&content| {
                                        !content.is_empty()
                                            && &content[..content.len() - 1] == uid_bytes
                                        // skip \0 at the end of the content
                                    })
                                    .is_some()
                            {
                                log::info!("[pam_isolate] Found process to be used for the user {uid} with pid {pid}");
                                return Ok(Some(Pid::from_raw(pid)));
                            }
                            buffer.clear();
                        }
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
    user_env: &str,
    loopback: &str,
) -> anyhow::Result<()> {
    rt.block_on(create_interface(username, uid, loopback))?;

    let first_pid = get_first_process_by_uid_or_env(uid, user_env)?;

    if let Some(first_pid) = first_pid {
        log::info!("[pam_isolate] Attaching to namespace of pid {first_pid}");
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
    user_env: &str,
    loopback: &str,
    set_env: impl Fn(&str, &str),
) -> anyhow::Result<()> {
    if user_env.contains('=') {
        return Err(anyhow::anyhow!(
            "Don't use `=` within the user environment variable name!"
        ));
    }
    let run_path: PathBuf = ["/", "var", "run", "pam_isolate"].iter().collect();
    std::fs::create_dir_all(&run_path).expect("mkdir {run_path}");

    let mut lock_path = run_path;
    lock_path.push(format!("lock_{uid}"));

    log::debug!(
        "[pam_isolate] lock file path: {lock_path:?} pid {}",
        getpid()
    );

    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)?;
    lock_file.lock_exclusive()?;
    set_env(user_env, &uid.to_string());
    log::debug!("[pam_isolate] set {user_env}={}", uid.to_string());
    for (var, content) in std::env::vars() {
        log::debug!("[pam_isolate] var {var} = {content}");
    }

    // We have to make sure to unlock the file afterwards, even in the case of an error!
    let result =
        create_namespaces_exclusive(rt, username, uid, gid, mount_config, user_env, loopback);
    let result2 = fs4::FileExt::unlock(&lock_file);

    if result.is_err() {
        drop(lock_file);
        result
    } else {
        result2.map_err(|err| err.into())
    }
}

pub fn try_setup_sysctl(table: &HashMap<String, toml::Value>) {
    for (key, value) in table {
        let value = match value {
            toml::Value::String(value) => CtlValue::String(value.clone()),
            toml::Value::Integer(value) => CtlValue::S64(*value),
            toml::Value::Table(value) => {
                if let Some(ty) = value.get("type").and_then(|ty| ty.as_str()) {
                    match ty {
                        "uint" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::Uint(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "ulong" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::Ulong(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "u8" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::U8(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "u16" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::U16(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "u32" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::U32(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "u64" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::U64(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "int" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::Int(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "long" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::Long(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "s8" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::S8(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "s16" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::S16(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "s32" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::S32(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        "s64" if matches!(value.get("value"), Some(toml::Value::Integer(_))) => {
                            CtlValue::S64(value.get("value").unwrap().as_integer().unwrap() as _)
                        }
                        _ => {
                            log::error!(
                                "[pam_isolate] Unknown type {ty:?} for typed sysctl entry \"{key}\""
                            );
                            continue;
                        }
                    }
                } else {
                    log::error!("[pam_isolate] Invalid format for typed sysctl entry \"{key}\"");
                    continue;
                }
            }
            _ => {
                log::error!(
                    "[pam_isolate] Unhandled sysctl value type {value:?} for entry \"{key}\""
                );
                continue;
            }
        };
        if let Err(err) = Ctl::new(key).and_then(|ctl| ctl.set_value(value)) {
            log::error!("[pam_isolate] Failed setting sysctl \"{key}\": {err}");
        }
    }
}
