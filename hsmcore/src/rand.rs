pub trait GetRandom: Send {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

#[cfg(target_arch = "x86_64")]
pub struct OsRng;

#[cfg(target_arch = "x86_64")]
impl GetRandom for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dest);
    }
}
