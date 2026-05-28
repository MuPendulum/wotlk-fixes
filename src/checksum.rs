// SPDX-License-Identifier: Unlicense

const PE_CHECKSUM_OFFSET: usize = 0x168;

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

pub fn update_pe_checksum(data: &mut [u8]) {
    let checksum = pe_checksum(data);
    data[PE_CHECKSUM_OFFSET..PE_CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
}
