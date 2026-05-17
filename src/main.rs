// SPDX-License-Identifier: Unlicense

use std::{env, fs};

const PE_CHECKSUM_OFFSET: usize = 0x168;

fn patch(data: &mut [u8], off: usize, bytes: &[u8]) {
    data[off..][..bytes.len()].copy_from_slice(bytes);
}

fn nop(data: &mut [u8], off: usize, len: usize) {
    data[off..][..len].fill(0x90);
}

fn pe_checksum(data: &[u8]) -> u32 {
    let checksum_idx = PE_CHECKSUM_OFFSET / 4;
    let mut sum = 0u64;

    let dword_count = data.len() / 4;
    let trailing_bytes = data.len() % 4;

    // Sum complete DWORDs, skipping the checksum field
    for i in 0..dword_count {
        if i != checksum_idx {
            let start = i * 4;
            let dword = u32::from_le_bytes(data[start..start + 4].try_into().unwrap());
            sum += dword as u64;
        }
    }

    // Sum trailing bytes as a zero-padded DWORD
    if trailing_bytes != 0 {
        let start = dword_count * 4;
        let mut trailing_dword = 0u32;

        for j in 0..trailing_bytes {
            trailing_dword |= (data[start + j] as u32) << (8 * j);
        }

        sum += trailing_dword as u64;
    }

    // Fold sum down to 32 bits
    sum = (sum & 0xFFFFFFFF) + (sum >> 32);
    // Fold sum down to 16 bits
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += sum >> 16;
    sum &= 0xFFFF;

    sum as u32 + data.len() as u32
}

fn update_pe_checksum(data: &mut [u8]) {
    let checksum = pe_checksum(data);
    data[PE_CHECKSUM_OFFSET..PE_CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
}

fn main() {
    let path = env::args().nth(1).expect("missing input file");
    let mut wow = fs::read(&path).expect("failed to read input file");

    // large address aware
    patch(&mut wow, 0x126, &[0x23]);

    // remote code execution exploit
    patch(&mut wow, 0x2A7, &[0xC0]);

    // remote code execution exploit (2)
    nop(&mut wow, 0x3D9D7C, 2);

    // windowed mode to full screen
    patch(&mut wow, 0xE94, &[0xEB]);

    // melee swing on right-click
    nop(&mut wow, 0x2E1C67, 11);

    // NPC attack animation when turning
    patch(&mut wow, 0x33D7C9, &[0xEB]);

    // "ghost" attack when NPC evades from combat
    patch(&mut wow, 0x355BF, &[0xEB]);

    // missing pre cast animation when canceling channeled spells
    nop(&mut wow, 0x33E0D6, 22);

    // mouse flickering and camera snapping issue when mouse has high report rate
    // credits to bonbigz
    patch(&mut wow, 0x469A2C, &[0xE9, 0x71, 0xF0, 0x0B, 0x00, 0xF8, 0x13, 0xD4, 0x00, 0x8B, 0x1D, 0xFC]);
    patch(&mut wow, 0x528AA2, &[0x8D, 0x4D, 0xF0, 0x51, 0x57, 0xFF, 0x15, 0xDC, 0xF5, 0x9D, 0x00, 0x8B, 0x45, 0xF0, 0x8B, 0x15, 0xF8, 0x13, 0xD4, 0x00, 0xE9, 0x7A, 0x0F, 0xF4, 0xFF]);
    patch(&mut wow, 0x4691B1, &[0x89, 0xE5, 0x8B, 0x05, 0xFC, 0x13, 0xD4, 0x00, 0x8B, 0x0D, 0xF8, 0x13, 0xD4, 0x00, 0xEB, 0xC2, 0x7D, 0x03, 0x83, 0xC1, 0x01, 0x83, 0xC0, 0x32, 0x83, 0xC1, 0x32, 0x3B, 0x0D, 0xEC, 0xBC, 0xCA, 0x00, 0x7E, 0x03, 0x83, 0xE9, 0x01, 0x3B, 0x05, 0xF0, 0xBC, 0xCA, 0x00, 0x7E, 0x03, 0x83, 0xE8, 0x01, 0x83, 0xE9, 0x32, 0x83, 0xE8, 0x32, 0x89, 0x0D, 0xF8, 0x13, 0xD4, 0x00, 0x89, 0x05, 0xFC, 0x13, 0xD4, 0x00, 0x89, 0xEC, 0x5D, 0xE9, 0xB4, 0xF7, 0xFF, 0xFF, 0xEC, 0x5D, 0xC3, 0xC3]);
    patch(&mut wow, 0x469183, &[0x83, 0xF8, 0x32, 0x7D, 0x03, 0x83, 0xC0, 0x01, 0x83, 0xF9, 0x32, 0xEB, 0x31]);

    // naked character issue (disables SPELL_AURA_X_RAY)
    patch(&mut wow, 0x1DDC5D, &[0xEB]);

    // patch mail request timeout
    // you no longer need to wait 60 seconds or relog to receive new mail
    patch(&mut wow, 0x16D899, &[0x05, 0x01, 0x00, 0x00, 0x00]);

    // patch area trigger timer to be more precise (250ms -> 50ms)
    patch(&mut wow, 0x2DB241, &[0x32]);

    // Return of "The Blue Moon"
    patch(&mut wow, 0x5CFBC0, &[0xC7, 0x05, 0x74, 0x8E, 0xD3, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]);

    // Allow chat commands while dead
    patch(&mut wow, 0x10CA41, &[0xEB]);

    // Recompute and write PE checksum
    update_pe_checksum(&mut wow);

    fs::write(&path, &wow).expect("failed to write output file");
}
