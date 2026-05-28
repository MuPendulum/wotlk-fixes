// SPDX-License-Identifier: Unlicense

mod checksum;
mod patches;

use std::{env, fs};

fn main() {
    let path = env::args().nth(1).expect("missing input file");
    let mut wow = fs::read(&path).expect("failed to read input file");

    patches::patch_wow(&mut wow);

    fs::write(&path, &wow).expect("failed to write output file");
}
