use std::path::{Path, PathBuf};

use log::LevelFilter;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct Users {
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Mount {
    pub tmp: String,
    pub size: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub users: Users,
    #[serde(default = "default_log_level")]
    pub log_level: LevelFilter,
    pub mount: Mount,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            users: Default::default(),
            log_level: default_log_level(),
            mount: Default::default(),
        }
    }
}

fn default_log_level() -> LevelFilter {
    LevelFilter::Warn
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn default_path() -> PathBuf {
        ["/", "etc", "pam_isolate.toml"].iter().collect()
    }
}
