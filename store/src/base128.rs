extern crate alloc;

use alloc::vec::Vec;

// Returns the number of bytes required to store a base128 encoded version of an
// input of 'num_bits' in length.
pub fn encoded_len(num_bits: usize) -> usize {
    let len = num_bits / 7;
    // extra +1 for terminator
    if num_bits % 7 != 0 {
        len + 1 + 1
    } else {
        len + 1
    }
}

// Encodes 'num_bits' number of bits from src into dest. Every 7 bits of input is
// written into an output byte. The output bytes have their Msb always set to 0.
// A terminator is written at the end that has its Msb set, and the number of bits
// used in the last byte in the lower 4 bits.
pub fn encode(src: &[u8], num_bits: usize, dest: &mut Vec<u8>) {
    dest.reserve(encoded_len(num_bits));
    let mut bits_togo = num_bits;
    let mut src = src;
    let chunk_size_bits = 8 * 7; // we can efficiently convert a chunk of 7 full bytes into 8 bytes.
    while bits_togo >= chunk_size_bits {
        encode_chunk(&src[..7], dest);
        bits_togo -= chunk_size_bits;
        src = &src[7..];
    }
    if bits_togo == 0 && num_bits > 0 {
        // if encode_chunk exactly handled the input, we need to deal with an edge
        // case where the terminator should say 7 bits were used, but encode_tail
        // would say zero.
        dest.push(128 | 7);
        return;
    }
    encode_tail(src, bits_togo, dest)
}

// Encodes exactly 7 input bytes into 8 output bytes. src must contain 7 bytes.
// Each 7 bits of input are in the lower 7 bits of each output byte. the MSB is
// always 0.
fn encode_chunk(src: &[u8], dest: &mut Vec<u8>) {
    assert!(src.len() == 7);
    dest.push(src[0] >> 1);
    dest.push(((src[0] & 1) << 6) | (src[1] >> 2));
    dest.push(((src[1] & 3) << 5) | (src[2] >> 3));
    dest.push(((src[2] & 7) << 4) | (src[3] >> 4));
    dest.push(((src[3] & 15) << 3) | (src[4] >> 5));
    dest.push(((src[4] & 31) << 2) | (src[5] >> 6));
    dest.push(((src[5] & 63) << 1) | (src[6] >> 7));
    dest.push(src[6] & 127);
}

// Encode 'num_bits' bits from src into dest. Adds the terminator byte with Msb set
// and the num bits used in last byte in the lower 4 bits.
fn encode_tail(src: &[u8], num_bits: usize, dest: &mut Vec<u8>) {
    let src_bit_mask = [128u8, 64, 32, 16, 8, 4, 2, 1];
    let dst_bit_mask = [64u8, 32, 16, 8, 4, 2, 1];
    let mut out = 0u8;
    let mut dst_bit_idx = 0;
    for si in 0..num_bits {
        if dst_bit_idx == 7 {
            dst_bit_idx = 0;
            dest.push(out);
            out = 0;
        }
        let src_byte = src[si / 8];
        let src_bit = si % 8; // 0 ==Msb to 7 == Lsb
        let is_set = src_byte & src_bit_mask[src_bit] != 0;
        if is_set {
            out |= dst_bit_mask[dst_bit_idx];
        }
        dst_bit_idx += 1;
    }
    if dst_bit_idx != 0 {
        dest.push(out);
    }
    let term = 128 | (dst_bit_idx as u8);
    dest.push(term);
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::{encode, encode_chunk, encode_tail, encoded_len};

    #[test]
    fn chunk_encoder() {
        let mut d = Vec::new();
        let src = [0; 7];
        encode_chunk(&src, &mut d);
        assert_eq!(vec![0, 0, 0, 0, 0, 0, 0, 0], d);

        let src = [255; 7];
        d.clear();
        encode_chunk(&src, &mut d);
        assert_eq!(vec![127, 127, 127, 127, 127, 127, 127, 127], d);

        let src = [0b01010101; 7];
        d.clear();
        encode_chunk(&src, &mut d);
        let exp = vec![
            0b00101010, 0b01010101, 0b00101010, 0b01010101, 0b00101010, 0b01010101, 0b00101010,
            0b01010101,
        ];
        assert_eq!(exp, d);
    }

    #[test]
    fn encoder() {
        let tests: Vec<(&[u8], usize, &[u8])> = vec![
            // input, num_bits, expected output
            (&[255], 0, &[128]),
            (&[255], 1, &[64, 128 | 1]),
            (&[255], 7, &[127, 128 | 7]),
            (&[255, 255], 8, &[127, 64, 128 | 1]),
            (&[255, 255], 9, &[127, 0b01100000, 128 | 2]),
            (&[255, 255], 11, &[127, 0b01111000, 128 | 4]),
            (&[255, 255], 16, &[127, 127, 96, 128 | 2]),
            (&[255, 255, 255], 17, &[127, 127, 0b01110000, 128 | 3]),
            (&[0, 0, 0], 17, &[0, 0, 0, 128 | 3]),
            (&[0b11000011], 1, &[0b01000000, 128 | 1]),
            (&[0b11000011], 4, &[0b01100000, 128 | 4]),
            (&[0b11000011], 7, &[0b01100001, 128 | 7]),
            (&[0b11000011], 8, &[0b01100001, 0b01000000, 128 | 1]),
            (&[0x55, 0xAA], 12, &[0b00101010, 0b01101000, 128 | 5]),
            (
                &[255, 255, 255, 255, 255, 255, 255],
                56,
                &[127, 127, 127, 127, 127, 127, 127, 127, 128 | 7],
            ),
        ];
        let mut d = Vec::new();
        for test in tests {
            d.clear();
            encode(test.0, test.1, &mut d);
            assert_eq!(test.2, &d, "for input {:?}", test.0);
        }
    }

    #[test]
    fn with_chunk_vs_tail_only() {
        let seed = [42u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut input = Vec::with_capacity(64);
        let mut enc = Vec::with_capacity(64);
        let mut enc_tail = Vec::with_capacity(64);

        for _ in 0..100 {
            let bit_len = ((rng.next_u32() >> 24) + (8 * 7)) as usize;
            input.resize(bit_len / 8 + 1, 0);
            rng.fill_bytes(&mut input);

            enc.clear();
            enc_tail.clear();
            encode(&input, bit_len, &mut enc);
            encode_tail(&input, bit_len, &mut enc_tail);
            assert_eq!(enc, enc_tail);
            assert_eq!(encoded_len(bit_len), enc.len(), "with bit_len {bit_len}");
            assert!(!enc.iter().rev().skip(1).any(|b| *b & 128 != 0));
        }
    }
}
