extern crate alloc;

use core::{
    cmp::Ordering,
    fmt::{Debug, Display, Write},
    iter::zip,
    ops::{Index, Range},
};
use serde::{Deserialize, Serialize};

use super::{hsm::types::RecordId, merkle::KeyVec};

#[macro_export]
macro_rules! bitvec {
    // borrowed from https://doc.rust-lang.org/book/ch19-06-macros.html
    ( $( $x:expr ),* ) => {
        {
            #[allow(unused_mut)]
            let mut temp_vec = $crate::bitvec::BitVec::new();
            $(
                temp_vec.push($x!=0);
            )*
            temp_vec
        }
    };
}

pub trait Bits<'a>: Sized {
    fn len(&self) -> usize; // length in bits
    fn at(&self, index: usize) -> bool;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn iter(&'a self) -> BitIter<'a, Self> {
        BitIter { src: self, pos: 0 }
    }
    fn starts_with<'o, O: Bits<'o>>(&'a self, other: &'o O) -> bool {
        if other.len() > self.len() {
            return false;
        }
        !zip(self.iter(), other.iter()).any(|(x, y)| x != y)
    }
    fn to_bitvec(&'a self) -> BitVec {
        let mut v = BitVec::new();
        for b in self.iter() {
            v.push(b);
        }
        v
    }
}
#[derive(Clone, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BitVec {
    len: usize,
    bits: [u8; 32],
}
impl BitVec {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_record_id(rec_id: &RecordId) -> Self {
        BitVec {
            len: RecordId::num_bits(),
            bits: rec_id.0,
        }
    }
    pub fn to_record_id(&self) -> RecordId {
        assert_eq!(self.len(), RecordId::num_bits());
        RecordId(self.bits)
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut r = Self::new();
        assert!(bytes.len() <= r.bits.len());
        r.bits[..bytes.len()].copy_from_slice(bytes);
        r.len = bytes.len() * 8;
        r
    }
    pub fn as_ref(&self) -> BitSlice {
        BitSlice {
            vec: self,
            offset: 0,
            len: self.len,
        }
    }
    pub fn slice(&self, r: Range<usize>) -> BitSlice {
        assert!(r.end <= self.len);
        BitSlice {
            vec: self,
            offset: r.start,
            len: r.end - r.start,
        }
    }
    pub fn slice_from(&self, index: usize) -> BitSlice {
        assert!(index <= self.len);
        BitSlice {
            vec: self,
            offset: index,
            len: self.len - index,
        }
    }
    pub fn slice_to(&self, index: usize) -> BitSlice {
        assert!(index <= self.len);
        BitSlice {
            vec: self,
            offset: 0,
            len: index,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        let last = if self.len % 8 == 0 {
            self.len / 8
        } else {
            self.len / 8 + 1
        };
        &self.bits[..last]
    }
    pub fn push(&mut self, bit: bool) {
        assert!(self.len < self.bits.len() * 8);
        let (byte_index, bit_mask) = self.bit_pos(self.len);
        if bit {
            self.bits[byte_index] |= bit_mask;
        } else {
            self.bits[byte_index] &= !bit_mask;
        }
        self.len += 1;
    }
    #[inline]
    fn bit_pos(&self, bit_num: usize) -> (usize, u8) {
        let byte_index = bit_num / 8;
        let bit_index = 7 - (bit_num % 8);
        let bit_mask: u8 = 1 << bit_index;
        (byte_index, bit_mask)
    }
    pub fn extend<'b, B: Bits<'b>>(&mut self, other: &'b B) {
        for b in other.iter() {
            self.push(b)
        }
    }
    pub fn pop(&mut self) -> Option<bool> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            let (byte_index, bit_mask) = self.bit_pos(self.len);
            let val = self.bits[byte_index] & bit_mask != 0;
            self.bits[byte_index] &= !bit_mask;
            Some(val)
        }
    }
}

impl<'a> Bits<'a> for BitVec {
    fn len(&self) -> usize {
        self.len
    }
    fn at(&self, bit_num: usize) -> bool {
        assert!(bit_num < self.len);
        let (byte_index, bit_mask) = self.bit_pos(bit_num);
        self.bits[byte_index] & bit_mask != 0
    }
    fn to_bitvec(&self) -> BitVec {
        self.clone()
    }
}

pub struct BitSlice<'a> {
    vec: &'a BitVec,
    offset: usize,
    len: usize,
}
impl<'a> BitSlice<'a> {
    pub fn slice(&self, r: Range<usize>) -> BitSlice<'a> {
        assert!(r.end <= self.len);
        BitSlice {
            vec: self.vec,
            offset: r.start + self.offset,
            len: r.end - r.start,
        }
    }
    pub fn slice_to(&self, index: usize) -> BitSlice<'a> {
        assert!(index <= self.len);
        BitSlice {
            vec: self.vec,
            offset: self.offset,
            len: index,
        }
    }
    pub fn slice_from(&self, index: usize) -> BitSlice<'a> {
        assert!(index <= self.len);
        BitSlice {
            vec: self.vec,
            offset: self.offset + index,
            len: self.len - index,
        }
    }
}
impl<'a> Bits<'a> for BitSlice<'a> {
    fn len(&self) -> usize {
        self.len
    }
    fn at(&self, bit: usize) -> bool {
        assert!(bit < self.len);
        self.vec.at(bit + self.offset)
    }
}

pub struct BitIter<'a, B: Bits<'a>> {
    src: &'a B,
    pos: usize,
}
impl<'a, B: Bits<'a>> Iterator for BitIter<'a, B> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.src.len() {
            let r = self.src.at(self.pos);
            self.pos += 1;
            Some(r)
        } else {
            None
        }
    }
}

// Eq & PartialEq for BitVec are derived.
impl<'a> Eq for BitSlice<'a> {}
impl<'a> PartialEq for BitSlice<'a> {
    fn eq(&self, other: &Self) -> bool {
        cmp_impl(self.iter(), other.iter()).is_eq()
    }
}
impl<'a> PartialEq<BitSlice<'a>> for BitVec {
    fn eq(&self, other: &BitSlice) -> bool {
        cmp_impl(self.iter(), other.iter()).is_eq()
    }
}
impl<'a> PartialEq<BitVec> for BitSlice<'a> {
    fn eq(&self, other: &BitVec) -> bool {
        cmp_impl(self.iter(), other.iter()).is_eq()
    }
}
impl<'a> PartialEq<BitVec> for &BitSlice<'a> {
    fn eq(&self, other: &BitVec) -> bool {
        cmp_impl(self.iter(), other.iter()).is_eq()
    }
}
impl Ord for BitVec {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_impl(self.iter(), other.iter())
    }
}
impl<'a> Ord for BitSlice<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_impl(self.iter(), other.iter())
    }
}
impl PartialOrd for BitVec {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(cmp_impl(self.iter(), other.iter()))
    }
}
impl<'a> PartialOrd for BitSlice<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(cmp_impl(self.iter(), other.iter()))
    }
}
impl<'a> PartialOrd<BitSlice<'a>> for BitVec {
    fn partial_cmp(&self, other: &BitSlice<'a>) -> Option<Ordering> {
        Some(cmp_impl(self.iter(), other.iter()))
    }
}
impl<'a> PartialOrd<BitVec> for BitSlice<'a> {
    fn partial_cmp(&self, other: &BitVec) -> Option<Ordering> {
        Some(cmp_impl(self.iter(), other.iter()))
    }
}
fn cmp_impl(mut a: impl Iterator<Item = bool>, mut b: impl Iterator<Item = bool>) -> Ordering {
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(true), Some(true)) => {}
            (Some(false), Some(false)) => {}
            (Some(false), Some(true)) => return Ordering::Less,
            (Some(true), Some(false)) => return Ordering::Greater,
        }
    }
}

impl Display for BitVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_bits(self.iter(), " ", f)
    }
}
impl Debug for BitVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_bits(self.iter(), " ", f)
    }
}
impl<'a> Display for BitSlice<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_bits(self.iter(), " ", f)
    }
}
impl<'a> Debug for BitSlice<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_bits(self.iter(), " ", f)
    }
}
fn fmt_bits(
    bits: impl Iterator<Item = bool>,
    s: &str,
    f: &mut core::fmt::Formatter<'_>,
) -> core::fmt::Result {
    f.write_char('[')?;
    for (i, b) in bits.enumerate() {
        if i > 0 && i % 8 == 0 {
            f.write_str(s)?;
        }
        f.write_char(if b { '1' } else { '0' })?;
    }
    f.write_char(']')
}

impl Index<usize> for KeyVec {
    type Output = bool;
    fn index(&self, index: usize) -> &Self::Output {
        if self.at(index) {
            &true
        } else {
            &false
        }
    }
}
impl<'a> Index<usize> for BitSlice<'a> {
    type Output = bool;
    fn index(&self, index: usize) -> &Self::Output {
        if self.at(index) {
            &true
        } else {
            &false
        }
    }
}

impl<'a> From<&'a BitVec> for BitSlice<'a> {
    fn from(value: &'a BitVec) -> Self {
        value.as_ref()
    }
}
impl<'a> From<&'a BitSlice<'a>> for BitVec {
    fn from(value: &'a BitSlice<'a>) -> Self {
        value.to_bitvec()
    }
}
impl<'a> From<BitSlice<'a>> for BitVec {
    fn from(value: BitSlice<'a>) -> Self {
        value.to_bitvec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::cmp::Ordering;

    #[test]
    fn vec_push() {
        let mut v = BitVec::new();
        assert!(v.is_empty());
        assert_eq!(0, v.len());
        v.push(true);
        assert!(v.at(0));
        assert_eq!(1, v.len());
        assert!(!v.is_empty());
    }

    #[test]
    #[should_panic]
    fn at_empty() {
        let v = bitvec![];
        v.at(0);
    }
    #[test]
    #[should_panic]
    fn at_oob() {
        let v = bitvec![1, 1, 1];
        assert!(v.at(0));
        assert!(v.at(1));
        assert!(v.at(2));
        v.at(3);
    }

    #[test]
    fn vec_macro() {
        let v = bitvec![0, 1, 1, 0];
        assert_eq!(4, v.len());
        assert!(!v.at(0));
        assert!(v.at(1));
        assert!(v.at(2));
        assert!(!v.at(3));
    }

    #[test]
    fn vec_pop() {
        let mut v = bitvec![1, 1, 0];
        assert_eq!(Some(false), v.pop());
        assert_eq!(128 | 64, v.bits[0]);
        assert_eq!(Some(true), v.pop());
        assert_eq!(128, v.bits[0]);
        assert_eq!(Some(true), v.pop());
        assert_eq!(0, v.bits[0]);
        assert_eq!(None, v.pop());
    }

    #[test]
    fn test_index() {
        let v = bitvec![1, 1, 0, 0];
        assert!(v[0]);
        assert!(v[1]);
        assert!(!v[2]);
        assert!(!v[3]);
        let s = v.slice(1..3);
        assert!(s[0]);
        assert!(!s[1]);
        let s = s.slice(0..1);
        assert!(s[0]);
    }

    #[test]
    fn vec_iter() {
        let v = bitvec![1, 1, 1, 1, 0, 0, 0, 0, 1];
        let bits: Vec<bool> = v.iter().collect();
        assert_eq!(
            vec![true, true, true, true, false, false, false, false, true],
            bits
        );
    }

    #[test]
    fn vec_extend() {
        let mut v = bitvec![1, 0, 1];
        let v2 = bitvec![0, 0, 1];
        v.extend(&v2);
        assert_eq!(bitvec![1, 0, 1, 0, 0, 1], v);
    }

    #[test]
    fn vec_bytes() {
        let v = BitVec::new();
        let empty: &[u8] = &[];
        assert_eq!(empty, v.as_bytes());
        let v = bitvec![1];
        assert_eq!(&[128u8], v.as_bytes());

        let mut v = BitVec::from_bytes(&[0b11000011, 0b01010101]);
        assert_eq!(16, v.len());
        assert_eq!(&[0b11000011, 0b01010101], v.as_bytes());
        v.push(true);
        assert_eq!(&[0b11000011, 0b01010101, 0b10000000], v.as_bytes());

        let rec = RecordId([42u8; 32]);
        let v = BitVec::from_record_id(&rec);
        assert_eq!(256, v.len());
        assert_eq!(&rec.0, v.as_bytes());
    }

    #[test]
    fn vec_slice() {
        let v = BitVec::from_bytes(&[0b11001010, 0b01111000]);
        let s = v.slice(1..3);
        assert!(s.at(0));
        assert!(!s.at(1));
        assert_eq!(2, s.len());
        let mut s = v.slice(6..10);
        assert_eq!(4, s.len());
        assert!(s.at(0));
        assert!(!s.at(1));
        assert!(!s.at(2));
        assert!(s.at(3));
        let bits: Vec<bool> = s.iter().collect();
        assert_eq!(vec![true, false, false, true], bits);
        s = s.slice(2..4);
        assert_eq!(2, s.len());
        assert!(!s.at(0));
        assert!(s.at(1));
        assert_eq!(vec![false, true], s.iter().collect::<Vec<_>>());
    }

    #[test]
    fn vec_slice_to_from() {
        let v = bitvec![1, 1, 1, 1, 0, 0, 0, 0];
        assert_eq!(bitvec![1, 1, 1, 1], v.slice_to(4).to_bitvec());
        assert_eq!(bitvec![0, 0, 0, 0], v.slice_from(4).to_bitvec());
        assert_eq!(bitvec![1, 1, 1, 1], v.slice(0..4));
        assert_eq!(bitvec![0, 0, 0, 0], v.slice(4..8));
        assert_eq!(v, v.as_ref().to_bitvec());
        assert_eq!(v, v.slice(0..8).to_bitvec());
        assert_eq!(v, v.slice_from(0).to_bitvec());
        assert_eq!(v, v.slice_to(8).to_bitvec());
    }
    #[test]
    fn slice_slice_to_from() {
        let v = bitvec![1, 1, 1, 1, 0, 0, 0, 0];
        let s = v.slice(1..7);
        assert_eq!(bitvec![1, 1, 1, 0, 0, 0], s.to_bitvec());
        assert_eq!(bitvec![1, 1, 1], s.slice_to(3).to_bitvec());
        assert_eq!(bitvec![0, 0, 0], s.slice_from(3).to_bitvec());
        assert_eq!(bitvec![1, 1, 1], s.slice(0..3));
        assert_eq!(bitvec![0, 0, 0], s.slice(3..6));
    }

    #[test]
    fn empty_slice() {
        let v = bitvec![0, 1, 0];
        let s = v.slice(0..0);
        assert!(s.is_empty());
        let s = v.slice(2..2);
        assert!(s.is_empty());
        let s = v.slice(2..3);
        assert!(!s.at(0));
        assert_eq!(1, s.len());
    }

    #[test]
    fn slice_to_from() {
        let v = bitvec![1, 1, 1, 0, 0, 0, 1, 1];
        let s = v.slice_to(2);
        assert_eq!(vec![true, true], s.iter().collect::<Vec<_>>());
        let s = v.slice_to(4);
        assert_eq!(vec![true, true, true, false], s.iter().collect::<Vec<_>>());
        let s = v.slice_to(v.len());
        assert_eq!(s, v.as_ref());
        let s = v.slice_from(4);
        assert_eq!(4, s.len());
        assert_eq!(bitvec![0, 0, 1, 1], s.to_bitvec());
        let s = s.slice_to(2);
        assert_eq!(bitvec![0, 0], s.to_bitvec());
    }

    #[test]
    fn eq() {
        let a = bitvec![1, 0, 0, 1, 0];
        let mut b = bitvec![1, 0, 0, 1, 0, 1];
        assert!(a != b);
        b.pop();
        assert_eq!(a, b);
        assert_eq!(a.bits, b.bits);
        assert_eq!(a, b.as_ref());
        assert_eq!(a.as_ref(), b);
        assert_eq!(a.as_ref(), b.as_ref());
        assert_eq!(a.slice(1..3), b.slice(1..3));
        assert_eq!(a.slice(0..2), a.slice(3..5));
    }

    #[test]
    fn order() {
        let k = bitvec![0, 1, 0, 1];
        let r = bitvec![1, 0, 0, 0];
        let k_slice = &k.as_ref();
        let r_slice = &r.as_ref();
        // > & < use PartialOrd
        assert!(r > k);
        assert!(k < r);
        assert!(r_slice > k_slice);
        assert!(k_slice < r_slice);
        assert!(r_slice > &k);
        assert!(&k < r_slice);
        assert!(k_slice < &r);
        assert!(&r > k_slice);
        // check Ord as well. (only between same types)
        assert_eq!(r.cmp(&k), Ordering::Greater);
        assert_eq!(k.cmp(&r), Ordering::Less);
        assert_eq!(r_slice.cmp(&k_slice), Ordering::Greater);
        assert_eq!(k_slice.cmp(&r_slice), Ordering::Less);
    }
}
