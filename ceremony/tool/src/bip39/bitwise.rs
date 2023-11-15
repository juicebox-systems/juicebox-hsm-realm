//! Helpers for iterating over bits and interpreting bits as integers.

/// An iterator over the N lower bits of an unsigned integer, in order from
/// largest to smallest.
///
/// This is specialized to 32-bit integers to avoid generics.
#[derive(Debug)]
pub struct BitIter {
    data: u32,
    last: u8, // 1 greater than the bit to output next
}

impl BitIter {
    pub fn new(data: u32, bits: u8) -> Self {
        assert!(u32::BITS >= u32::from(bits));
        Self { data, last: bits }
    }
}

impl Iterator for BitIter {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.last == 0 {
            None
        } else {
            self.last -= 1;
            Some(((self.data >> self.last) & 1) == 1)
        }
    }
}

/// Interpret the given sequence of bits as an integer, where the most
/// significant bit is first.
///
/// This is specialized to 32-bit integers to avoid generics.
pub fn from_bits(bits: &[bool]) -> u32 {
    assert!(bits.len() <= u32::BITS as usize);
    bits.iter().fold(0, |acc, bit| (acc << 1) | u32::from(*bit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_iter() {
        assert_eq!(
            BitIter::new(0b1101_0011_1011u32, 10).collect::<Vec<bool>>(),
            vec![
                false, true, //
                false, false, true, true, //
                true, false, true, true
            ]
        );
        assert_eq!(
            BitIter::new(0b1110_1100_0100u32, 10).collect::<Vec<bool>>(),
            vec![
                true, false, //
                true, true, false, false, //
                false, true, false, false
            ]
        );
        assert_eq!(
            BitIter::new(0b1001_1111_0100u32, 8).collect::<Vec<bool>>(),
            vec![
                true, true, true, true, //
                false, true, false, false
            ]
        );
        assert_eq!(
            BitIter::new(0b1111_0100u32, 0).collect::<Vec<bool>>(),
            vec![]
        );
    }

    #[test]
    fn test_from_bits() {
        assert_eq!(
            0b101_0011_1010u32,
            from_bits(&[
                true, false, true, //
                false, false, true, true, //
                true, false, true, false
            ])
        );
        assert_eq!(
            0b011_1111_1011u32,
            from_bits(&[
                false, true, true, //
                true, true, true, true, //
                true, false, true, true
            ])
        );

        assert_eq!(0u32, from_bits(&[]));
    }
}
