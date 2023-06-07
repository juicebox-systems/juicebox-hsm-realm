//! [`BitVec`] and [`BitSlice`] are types that have `Vec<bool>` and
//! `&[bool]`-like operations but have a more efficient representation.

extern crate alloc;

use core::{
    cmp::{min, Ordering},
    fmt::{Debug, Display, Write},
    iter::zip,
    ops::{Bound, Index, RangeBounds},
};
use juicebox_sdk_marshalling::bytes;
use serde::{Deserialize, Serialize};

/// The bitvec! macro is used to easily create new bitvecs. Its very similar to vec!
/// let bits = bitvec![0,0,1]
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

/// the Bits trait exposes some common operations that work with both BitVecs and BitSlices.
pub trait Bits<'a>: Sized {
    /// The length in bits
    fn len(&self) -> usize;
    /// The bit at 'index' into the list of bits. panics if index is out of bounds.
    fn at(&self, index: usize) -> bool;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns an Iterator<Item=bool> that iterates over all the bits.
    fn iter(&'a self) -> BitIter<'a, Self> {
        BitIter { src: self, pos: 0 }
    }
    /// Returns true if self starts with the full sequence of bits in other.
    fn starts_with<'o, O: Bits<'o>>(&'a self, other: &'o O) -> bool {
        if other.len() > self.len() {
            return false;
        }
        zip(self.iter(), other.iter()).all(|(x, y)| x == y)
    }
    /// Create a new bitvec from the current sequence of bits.
    fn to_bitvec(&'a self) -> BitVec {
        let mut v = BitVec::new();
        v.extend(self);
        v
    }
    /// Returns a new KeyVec consisting of our sequence followed by the bit sequence
    /// from other.
    fn concat<'o, O: Bits<'o>>(&'a self, other: &'o O) -> BitVec {
        let mut r = self.to_bitvec();
        r.extend(other);
        r
    }
}

/// BitVec owns a sequence of bits with a maximum size of 256 bits. It is fixed
/// sized, and unlike Vec does not use a heap allocation to store the bits.
///
/// TODO: Serialize writes out the full 256 bits even if only 3 are used. That
/// can be made more efficient
#[derive(Clone, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BitVec {
    len: usize,
    // The bits are stored 8 per byte in Msb order. i.e. the first bit
    // is 0b1.......
    // Invariants:
    // * Unused bits are set to 0.
    // * 0 <= len <= 256
    #[serde(with = "bytes")]
    bits: [u8; 32],
}

impl BitVec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new Bitvec with a copy of the supplied bytes. The bytes
    /// should represent bits the same way as BitVec does. (Msb is first)
    /// Will panic if more then 256 bits (32 bytes) are provided. All the
    /// bits from bytes are used, so len will be bytes.len() * 8
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut r = Self::new();
        assert!(bytes.len() <= r.bits.len());
        r.bits[..bytes.len()].copy_from_slice(bytes);
        r.len = bytes.len() * 8;
        r
    }

    /// Returns a slice that covers that full sequence.
    pub fn as_ref(&self) -> BitSlice {
        BitSlice {
            vec: self,
            offset: 0,
            len: self.len,
        }
    }

    /// Returns a slice of some subset of the sequence.
    pub fn slice(&self, r: impl RangeBounds<usize>) -> BitSlice {
        let (start, len) = bounds_to_start_len(r, self.len);
        BitSlice {
            vec: self,
            offset: start,
            len,
        }
    }

    /// Returns the current sequence as a slice of bytes. Bits are in Msb0 order
    /// in the bytes, and any unused bits are always set to 0. The returned
    /// slice is sized based on the number of bits, i.e. as_bytes() on a BitVec
    /// with len 10 would return a 2 byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        let last = if self.len % 8 == 0 {
            self.len / 8
        } else {
            self.len / 8 + 1
        };
        &self.bits[..last]
    }

    /// Adds a new bit to the end of the current sequence. Will panic if there
    /// is no space left
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

    /// Add the sequence of bits from other to the end of this sequence.
    pub fn extend<'b, B: Bits<'b>>(&mut self, other: &'b B) {
        for b in other.iter() {
            self.push(b)
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

/// BitSlice is a readonly reference to a sequence of bits in a BitVec.
pub struct BitSlice<'a> {
    vec: &'a BitVec,
    offset: usize,
    len: usize,
}

impl<'a> BitSlice<'a> {
    /// Returns a new slice that is a subset of the current slice.
    pub fn slice(&self, r: impl RangeBounds<usize>) -> BitSlice<'a> {
        let (start, len) = bounds_to_start_len(r, self.len);
        BitSlice {
            vec: self.vec,
            offset: start + self.offset,
            len,
        }
    }

    /// Returns a slice that contains the sequence of bits that is at the start
    /// of self & other that is the same.
    pub fn common_prefix<'o, O: Bits<'o>>(&'a self, other: &'o O) -> BitSlice<'a> {
        match zip(self.iter(), other.iter()).position(|(x, y)| x != y) {
            None => self.slice(..min(self.len(), other.len())),
            Some(p) => self.slice(..p),
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
        // TODO: This could be optimized to track the byte index and mask here
        // and increment them. With this impl they get recalculated every time.
        if self.pos < self.src.len() {
            let r = self.src.at(self.pos);
            self.pos += 1;
            Some(r)
        } else {
            None
        }
    }
}

/// Normalizes RangeBounds to an inclusive start and length.
fn bounds_to_start_len(r: impl RangeBounds<usize>, len: usize) -> (usize, usize) {
    let start = match r.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(p) => *p,
        Bound::Excluded(p) => *p + 1,
    };
    assert!(start <= len, "start={start:} len={len:}");
    // 200..100 is a perfectly valid RangeBounds instance. We need to protect
    // against that.
    let bound_len = match r.end_bound() {
        Bound::Unbounded => len - start,
        Bound::Included(p) => {
            assert!(*p >= start);
            *p - start + 1
        }
        Bound::Excluded(p) => {
            assert!(*p >= start);
            *p - start
        }
    };
    assert!(start + bound_len <= len);
    (start, bound_len)
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
        // TODO: Display should compress the tail that's all 0 or 1
        format_bits(self, " ", f)
    }
}

impl Debug for BitVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        format_bits(self, " ", f)
    }
}

impl<'a> Display for BitSlice<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        format_bits(self, " ", f)
    }
}

impl<'a> Debug for BitSlice<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        format_bits(self, " ", f)
    }
}

fn format_bits<'a>(
    bits: &'a impl Bits<'a>,
    s: &str,
    f: &mut core::fmt::Formatter<'_>,
) -> core::fmt::Result {
    f.write_char('[')?;
    for (i, b) in bits.iter().enumerate() {
        if i > 0 && i % 8 == 0 {
            f.write_str(s)?;
        }
        f.write_char(if b { '1' } else { '0' })?;
    }
    f.write_char(']')
}

/// DisplayBits is a wrapper that allows for control of the separator string in
/// the formatting of a sequence of bits.
pub struct DisplayBits<'a, 'b, B: Bits<'b>>(pub &'a str, pub &'b B);
impl<'a, 'b, B: Bits<'b>> Display for DisplayBits<'a, 'b, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        format_bits(self.1, self.0, f)
    }
}

impl Index<usize> for BitVec {
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
    #[should_panic]
    fn range_oob_end() {
        let v = BitVec::from_bytes(&[0; 32]);
        v.slice(100..=260);
    }

    #[test]
    #[should_panic]
    fn range_oob_start() {
        let v = BitVec::from_bytes(&[0; 32]);
        v.slice(256..257);
    }

    #[test]
    #[should_panic]
    fn range_oob_small() {
        let v = bitvec![1, 1, 1, 1];
        v.slice(4..5);
    }

    #[test]
    #[should_panic]
    fn range_backwards() {
        let v = BitVec::from_bytes(&[0; 32]);
        #[allow(clippy::reversed_empty_ranges)]
        v.slice(200..100);
    }

    #[test]
    fn slice_ends() {
        let v = bitvec![1, 1, 1, 1];
        assert!(v.slice(4..4).is_empty());
        assert!(v.slice(0..0).is_empty());
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
    fn vec_slice_range_types() {
        let v = bitvec![1, 1, 1, 1, 0, 0, 0, 0];
        assert_eq!(bitvec![1, 1, 1, 1], v.slice(..4));
        assert_eq!(bitvec![1, 1, 1, 1], v.slice(..=3));
        assert_eq!(bitvec![1, 1, 1, 1], v.slice(0..=3));
        assert_eq!(bitvec![1, 1, 0], v.slice(2..=4));
        assert_eq!(bitvec![1, 1, 0], v.slice(2..5));
        assert_eq!(bitvec![0, 0, 0, 0], v.slice(4..));
        assert_eq!(bitvec![1, 1, 1, 1], v.slice(0..4));
        assert_eq!(bitvec![0, 0, 0, 0], v.slice(4..8));
        assert_eq!(v, v.as_ref());
        assert_eq!(v, v.slice(..));
        assert_eq!(v, v.slice(0..8));
        assert_eq!(v, v.slice(0..));
        assert_eq!(v, v.slice(..8));
    }
    #[test]
    fn slice_slice_range_types() {
        let v = bitvec![1, 1, 1, 1, 0, 0, 0, 0];
        let s = v.slice(1..7);
        assert_eq!(bitvec![1, 1, 1, 0, 0, 0], s);
        assert_eq!(bitvec![1, 1, 1, 0], s.slice(..4));
        assert_eq!(bitvec![1, 1, 1, 0], s.slice(..=3));
        assert_eq!(bitvec![1, 0], s.slice(2..4));
        assert_eq!(bitvec![1, 0], s.slice(2..=3));
        assert_eq!(bitvec![0, 0, 0], s.slice(3..));
        assert_eq!(bitvec![1, 1, 1], s.slice(0..3));
        assert_eq!(bitvec![0, 0, 0], s.slice(3..6));
        assert_eq!(s, s.slice(..));
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
    fn eq() {
        let a = bitvec![1, 0, 0, 1, 0];
        let b = bitvec![1, 0, 0, 1, 0, 1];
        assert!(a != b);
        let b = bitvec![1, 0, 0, 1, 0];
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
        assert_eq!(r_slice.cmp(k_slice), Ordering::Greater);
        assert_eq!(k_slice.cmp(r_slice), Ordering::Less);
    }

    #[test]
    fn concat() {
        let k = bitvec![0, 1, 1, 0, 1];
        let r = bitvec![0, 0, 0, 1];
        assert_eq!(bitvec![0, 1, 1, 0, 1, 0, 0, 0, 1], k.concat(&r));
        assert_eq!(bitvec![0, 0, 0, 1, 0, 1, 1, 0, 1], r.concat(&k));
        let sk = k.slice(..2);
        assert_eq!(bitvec![0, 1, 0, 0], sk.concat(&r.slice(..2)));
        assert_eq!(bitvec![0, 1, 0, 0, 0, 1], sk.concat(&r));
    }

    #[test]
    fn common_prefix_with_prefix() {
        let a = bitvec![1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1];
        let b = bitvec![1, 1, 1, 1, 0, 0, 0, 0, 1, 0];
        assert_eq!(a.slice(..9), a.as_ref().common_prefix(&b));
        assert_eq!(a.slice(..9), b.as_ref().common_prefix(&a));
    }

    #[test]
    fn common_prefix_entire_len() {
        let a = bitvec![1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1];
        let b = bitvec![1, 1, 1, 1, 0, 0, 0];
        assert_eq!(a.slice(..7), a.as_ref().common_prefix(&b));
        assert_eq!(a.slice(..7), b.as_ref().common_prefix(&a));
    }

    #[test]
    fn common_prefix_none() {
        let a = bitvec![1, 1, 1, 1];
        let b = bitvec![0, 1, 1, 1];
        assert!(a.as_ref().common_prefix(&b).is_empty());
        assert!(b.as_ref().common_prefix(&a).is_empty());
    }

    #[test]
    fn common_prefix_same() {
        let a = BitVec::from_bytes(&[1]);
        let b = BitVec::from_bytes(&[1]);
        assert_eq!(a.as_ref(), a.as_ref().common_prefix(&b));
        assert_eq!(b.as_ref(), b.as_ref().common_prefix(&a));
    }
}
