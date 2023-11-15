//! Iterate over chunks of an iterator.

/// Extends all [`Iterator`]s.
pub trait IteratorExt: Iterator + Sized {
    /// Returns an iterator over non-overlapping sequences of length `size`
    /// from the given iterator, followed by any remaining items at the end.
    ///
    /// This returns an iterator over vectors.
    fn chunked(self, size: usize) -> Chunked<Self> {
        assert!(size > 0);
        Chunked { inner: self, size }
    }
}

impl<I: Iterator> IteratorExt for I {}

/// See [`IteratorExt::chunked`].
#[derive(Debug)]
pub struct Chunked<I: Iterator> {
    inner: I,
    size: usize,
}

impl<I: Iterator> Iterator for Chunked<I> {
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        let chunk: Vec<I::Item> = self.inner.by_ref().take(self.size).collect();
        if chunk.is_empty() {
            None
        } else {
            Some(chunk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunked() {
        assert_eq!(
            (0..9).chunked(1).collect::<Vec<_>>(),
            vec![
                vec![0],
                vec![1],
                vec![2],
                vec![3],
                vec![4],
                vec![5],
                vec![6],
                vec![7],
                vec![8]
            ]
        );
        assert_eq!(
            (0..9).chunked(2).collect::<Vec<_>>(),
            vec![vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8]]
        );
        assert_eq!(
            (0..9).chunked(3).collect::<Vec<_>>(),
            vec![vec![0, 1, 2], vec![3, 4, 5], vec![6, 7, 8]]
        );
        assert_eq!((0..2).chunked(3).collect::<Vec<_>>(), vec![vec![0, 1]]);
        assert_eq!(
            std::iter::empty::<u8>().chunked(3).collect::<Vec<_>>(),
            Vec::<Vec<u8>>::new()
        );
    }
}
