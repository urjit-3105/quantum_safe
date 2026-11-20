use zeroize::Zeroize;

/// Secure wrapper for sensitive cryptographic key material
/// Automatically zeroizes memory on drop and pins memory against swapping
pub struct SecureKey<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureKey<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        let key = Self { data: bytes };
        key.lock_memory();
        key
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    #[cfg(windows)]
    fn lock_memory(&self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualLock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
        }
        unsafe {
            let _ = VirtualLock(self.data.as_ptr() as *const std::ffi::c_void, N);
        }
    }

    #[cfg(not(windows))]
    fn lock_memory(&self) {
        #[link(name = "c")]
        extern "C" {
            fn mlock(addr: *const std::ffi::c_void, len: usize) -> i32;
        }
        unsafe {
            let _ = mlock(self.data.as_ptr() as *const std::ffi::c_void, N);
        }
    }

    #[cfg(windows)]
    fn unlock_memory(&self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualUnlock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
        }
        unsafe {
            let _ = VirtualUnlock(self.data.as_ptr() as *const std::ffi::c_void, N);
        }
    }

    #[cfg(not(windows))]
    fn unlock_memory(&self) {
        #[link(name = "c")]
        extern "C" {
            fn munlock(addr: *const std::ffi::c_void, len: usize) -> i32;
        }
        unsafe {
            let _ = munlock(self.data.as_ptr() as *const std::ffi::c_void, N);
        }
    }
}

impl<const N: usize> Drop for SecureKey<N> {
    fn drop(&mut self) {
        self.data.zeroize();
        self.unlock_memory();
    }
}

impl<const N: usize> AsRef<[u8]> for SecureKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
