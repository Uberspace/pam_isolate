use std::path::Path;

use serde::Deserialize;
use uberspace_ns::Mount;

#[derive(Debug, Default, Deserialize)]
pub struct Users {
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub users: Users,
    pub mount: Mount,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
