//! Trivial secret sharing without thresholding.
//!
//! This algorithm is described briefly here:
//! <https://en.wikipedia.org/wiki/Secret_sharing#t_=_n>.

use rand::{CryptoRng, Rng};

pub fn split<R, S>(secret: &[u8], n: usize, rng: &mut R) -> Vec<S>
where
    S: From<Vec<u8>>,
    R: Rng + CryptoRng,
{
    assert!(n >= 1);
    let mut last_share = secret.to_vec();
    let mut shares = Vec::with_capacity(n);
    for _ in 0..(n - 1) {
        let mut share = vec![0; secret.len()];
        rng.fill(share.as_mut_slice());
        for i in 0..secret.len() {
            last_share[i] ^= share[i];
        }
        shares.push(S::from(share));
    }
    shares.push(S::from(last_share));
    shares
}

#[derive(Debug, Eq, PartialEq)]
pub enum RecombineError {
    NoShares,
    ShareLengthsDiffer,
}

pub fn recombine<I>(shares: I) -> Result<Vec<u8>, RecombineError>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut shares_iter = shares.into_iter();
    let mut secret = match shares_iter.next() {
        Some(first) => first.as_ref().to_owned(),
        None => return Err(RecombineError::NoShares),
    };
    for share in shares_iter {
        let share = share.as_ref();
        if secret.len() != share.len() {
            return Err(RecombineError::ShareLengthsDiffer);
        }
        for i in 0..secret.len() {
            secret[i] ^= share[i];
        }
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_split_recombine_single() {
        let secret = b"bananas";
        assert_eq!(split::<_, Vec<u8>>(secret, 1, &mut OsRng), vec![secret]);
        assert_eq!(recombine([secret.as_slice()]).unwrap(), secret.to_vec());
    }

    #[test]
    fn test_split_recombine() {
        let secret = b"bananas";
        let mut rng = ChaCha12Rng::seed_from_u64(7);
        let shares = split::<_, Vec<u8>>(secret, 6, &mut rng);
        assert_eq!(
            shares,
            vec![
                vec![190, 251, 168, 106, 233, 224, 194],
                vec![134, 95, 126, 36, 232, 52, 157],
                vec![205, 188, 139, 15, 70, 50, 132],
                vec![153, 160, 223, 166, 5, 104, 226],
                vec![182, 33, 98, 158, 173, 97, 194],
                vec![184, 248, 142, 24, 129, 142, 136]
            ]
        );
        assert_eq!(recombine(shares), Ok(secret.to_vec()));
    }

    #[test]
    #[should_panic]
    fn test_split_0() {
        split::<_, Vec<u8>>(b"x", 0, &mut OsRng);
    }

    #[test]
    fn test_recombine_invalid() {
        let empty: &[&[u8]] = &[];
        assert_eq!(recombine(empty), Err(RecombineError::NoShares));
        assert_eq!(
            recombine(&[b"abc".to_vec(), b"x".to_vec()]),
            Err(RecombineError::ShareLengthsDiffer)
        );
    }
}
