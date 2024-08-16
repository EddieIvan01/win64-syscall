use proc_macro::TokenStream;
use zero_xxhash::hash64;

const SEED: u64 = 0x1f2f3f4f;

#[proc_macro]
pub fn compile_time_hash(item: TokenStream) -> TokenStream {
    let s = item.into_iter().take(1).next().unwrap().to_string();

    format!("0x{:x}_u64", hash64::xxhash64(s.as_bytes(), SEED))
        .parse()
        .unwrap()
}
