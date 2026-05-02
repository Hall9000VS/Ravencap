use ravencap_format::RAVP_MAGIC;

pub fn sample_prelude_magic() -> &'static [u8; 5] {
    RAVP_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_sample_magic() {
        assert_eq!(sample_prelude_magic(), b"RAVP\0");
    }
}
