// SPDX-License-Identifier: Unlicense

mod checksum;
mod config;
mod patches;

use std::{env, fs};

fn main() {
    let path = env::args().nth(1).expect("missing input file");
    let mut wow = fs::read(&path).expect("failed to read input file");
    let config = config::Config::load();

    patches::patch_wow(&mut wow, &config);

    fs::write(&path, &wow).expect("failed to write output file");
}
