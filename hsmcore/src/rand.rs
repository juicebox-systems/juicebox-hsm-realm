pub trait GetRandom {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

pub struct Rng;

#[cfg(target_arch = "x86_64")]
impl GetRandom for Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dest);
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl GetRandom for Rng {
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        todo!()
    }
}
