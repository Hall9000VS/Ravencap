use std::io::Read;

fn fuzz_one(data: &[u8]) {
    let _ = ravencap_format::parse_prelude_prefix(data);
}

fn main() {
    let mut data = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .expect("read fuzz input");
    fuzz_one(&data);
}
