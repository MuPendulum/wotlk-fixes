// SPDX-License-Identifier: Unlicense

use configparser::ini::Ini;

const CONFIG_PATH: &str = "config.ini";

pub struct Config(Ini);

impl Config {
    pub fn load() -> Self {
        let mut ini = Ini::new();
        let _ = ini.load(CONFIG_PATH);
        Self(ini)
    }

    pub fn is_enabled(&self, key: &str) -> bool {
        self.0.getbool("Patches", key).ok().flatten().unwrap_or(false)
    }
}
