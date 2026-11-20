use getrandom::SysRng;
use rand_core::UnwrapErr;

pub type SecureRng = UnwrapErr<SysRng>;

pub fn get_secure_rng() -> SecureRng {
    UnwrapErr(SysRng)
}
