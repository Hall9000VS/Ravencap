use std::io::Read;

fn fuzz_one(data: &[u8]) {
    if let Ok(value) = std::str::from_utf8(data) {
        let value = value.trim_end_matches(['\r', '\n']);
        let _ = ravencap_core::paths::validate_relative_archive_path(value);

        let mut parts = value.splitn(2, '\0');
        if let (Some(link_path), Some(target)) = (parts.next(), parts.next()) {
            let _ = ravencap_core::paths::validate_relative_symlink_target(link_path, target);
        }
    }
}

fn main() {
    let mut data = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .expect("read fuzz input");
    fuzz_one(&data);
}
