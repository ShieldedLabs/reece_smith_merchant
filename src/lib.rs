
mod high_latency_lightwalletd_rpc_calls;
use base64::Engine;
use high_latency_lightwalletd_rpc_calls::*;

/// cbindgen:ignore
mod uhh {
    pub const LOG: u32 = 1 << 0;
    pub const CALLSTACK: u32 = 1 << 1;
    pub const PANIC: u32 = 1 << 2;
}
fn uhh<T, E: std::fmt::Display> (result: Result<T, E>, on_fail: u32) -> Result<T, E> {
    match &result {
        Ok(_) => (),

        Err(e) => {
            if on_fail & (uhh::LOG | uhh::PANIC) != 0 {
                eprintln!("{}", e)
            }

            if on_fail & uhh::CALLSTACK != 0 {
                todo!("print backtrace")
            }

            if on_fail & uhh::PANIC != 0 {
                panic!("error marked as unrecoverable")
            }
        }
    }

    result
}


#[repr(C)]
#[derive(Clone)]
pub struct ConnectURIAndCertificateBlob {
    https_uri_string_ptr: *const u8,
    https_uri_string_len: usize,
    certificate_blob_ptr: *const u8,
    certificate_blob_len: usize,
}

#[repr(C)]
#[derive(Clone)]
pub struct LightwalletdEndpointArray {
    ptr: *const ConnectURIAndCertificateBlob,
    len: usize,
}

impl Into<&'static [ConnectURIAndCertificateBlob]> for LightwalletdEndpointArray {
    fn into(self) -> &'static [ConnectURIAndCertificateBlob] {
        unsafe { &*slice_from_raw_parts(self.ptr, self.len) }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Blake3Hash {
    data: [u8; 32],
}

use std::{
    ffi::c_void,
    ptr::copy_nonoverlapping,
    ptr::slice_from_raw_parts,
    slice::from_raw_parts,
};

#[unsafe(no_mangle)]
pub extern "C" fn create_rsid_from_merchant_and_tx(merchant_name_str: *const u8, merchant_name_str_len: usize, tx_data: *const c_void, tx_data_size: usize) -> Blake3Hash {
    let data = unsafe {
        *blake3::Hasher::new_derive_key("RSID")
            .update(from_raw_parts(merchant_name_str, merchant_name_str_len))
            .update(from_raw_parts(tx_data as *const u8, tx_data_size))
            .finalize()
            .as_bytes()
    };
    Blake3Hash { data }
}

pub fn do_all_the_things() {
    use secrecy::ExposeSecret;

    // let mut wdb = zcash_client_sqlite::WalletDb::for_path(temp_dir.path().join("wallet.db"), zcash_protocol::consensus::Network::MainNetwork, zcash_client_sqlite::util::SystemClock, rand_core::OsRng).unwrap();
    let cdb = if false {
        let temp_dir = tempfile::tempdir().unwrap();
        zcash_client_sqlite::BlockDb::for_path(temp_dir.path().join("cache.db")).unwrap()
    } else {
        zcash_client_sqlite::BlockDb::for_path(":memory:").unwrap()
    };

    // First run only: create/upgrade the schemas.
    zcash_client_sqlite::chain::init::init_cache_database(&cdb).unwrap();
    // zcash_client_sqlite::wallet::init::init_wallet_db(&mut wdb, None).unwrap();

    // get seed from seed phrase and passphrase
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let bip39_passphrase = ""; // optional
    let mnemonic = bip39::Mnemonic::parse(phrase).unwrap();
    let seed64 = mnemonic.to_seed(bip39_passphrase);
    // assumes passphrase "TREZOR"
    // assert_eq!(&Vec::<u8>::from_hex("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap(), &seed64);
    let seed = secrecy::SecretVec::new(seed64[..32].to_vec());

    // 2. Derive Unified Spending Key (USK) from seed
    let account_id = zip32::AccountId::try_from(0).unwrap();
    let usk = zcash_client_backend::keys::UnifiedSpendingKey::from_seed(&zcash_protocol::consensus::MAIN_NETWORK, seed.expose_secret(), account_id).unwrap();

    // 3. Derive Unified Full Viewing Key (UFVK)
    let ufvk: zcash_client_backend::keys::UnifiedFullViewingKey = usk.to_unified_full_viewing_key();
    let uivk: zcash_client_backend::keys::UnifiedIncomingViewingKey = ufvk.to_unified_incoming_viewing_key();
    // Derive the account’s UFVK and default Unified Address (UA).
    // TODO: we want to generate these on a dev PC and transfer to the lower-privileged server
    // ALT: we can do specific handling for Sapling/Orchard incoming view keys without going through a full key
    let ua: zcash_client_backend::address::UnifiedAddress = uivk.default_address(zcash_client_backend::keys::UnifiedAddressRequest::SHIELDED).unwrap().0;
    println!("Receive at: {}", ua.encode(&zcash_protocol::consensus::Network::MainNetwork));

    let https_uri = "https://eu.zec.rocks:443";
    let cert: &[u8] = include_bytes!("../eu.zec.rocks-leaf.der");

    let mempool_status = simple_get_mempool_tx(LightwalletdEndpointArray {
        len: 1,
        ptr: &ConnectURIAndCertificateBlob {
            https_uri_string_ptr: https_uri.as_ptr(),
            https_uri_string_len: https_uri.len(),
            certificate_blob_ptr: cert.as_ptr(),
            certificate_blob_len: cert.len(),
        } as *const ConnectURIAndCertificateBlob,
    }, uhh::PANIC);
}


// Define a C-compatible struct with #[repr(C)]
#[repr(C)]
pub struct Vector2 {
    pub x: f32,
    pub y: f32,
}

#[repr(C)]
pub enum MyEnum {
    ThingA,
    ThingB,
}

#[unsafe(no_mangle)]
/// Some documentation here
pub extern "C" fn memo_receipt_generate(buf: &mut [u8; 512], merchant_name_str: *const u8, merchant_name_str_len: usize, product_str: *const u8, product_str_len: usize, rsid: &[u8; 32]) -> bool {
    *buf = [0_u8; 512];
    let prefix1 = "RSID:";

    let mut rsm_id_base64 = [0_u8; 43];
    let got_len = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_slice(rsid, &mut rsm_id_base64).unwrap();
    assert_eq!(got_len, rsm_id_base64.len());

    let prefix2 = "\nMERCHANT NAME: ";

    for i in 0..merchant_name_str_len {
        unsafe {
            let c : u8 = *merchant_name_str.add(i);
            if  (c >= b'0' && c <= b'9') ||
                (c >= b'A' && c <= b'Z') ||
                (c >= b'a' && c <= b'z') ||
                c == b' ' || c == b'.'
            {}
            else { return false; }
        }
    }

    if prefix1.len() + rsm_id_base64.len() + prefix2.len() + merchant_name_str_len + 1 + product_str_len <= 512 {
        unsafe {
            let mut o = 0;
            copy_nonoverlapping(prefix1.as_bytes().as_ptr(), (*buf).as_mut_ptr().add(o), prefix1.len());
            o += prefix1.len();
            copy_nonoverlapping(rsm_id_base64.as_ptr(), (*buf).as_mut_ptr().add(o), rsm_id_base64.len());
            o += rsm_id_base64.len();
            copy_nonoverlapping(prefix2.as_bytes().as_ptr(), (*buf).as_mut_ptr().add(o), prefix2.len());
            o += prefix2.len();
            copy_nonoverlapping(merchant_name_str, (*buf).as_mut_ptr().add(o), merchant_name_str_len);
            o += merchant_name_str_len;
            copy_nonoverlapping("\n".as_bytes().as_ptr(), (*buf).as_mut_ptr().add(o), 1);
            o += 1;
            copy_nonoverlapping(product_str, (*buf).as_mut_ptr().add(o), product_str_len);
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zec_rocks_eu() -> LightwalletdEndpointArray {
        let https_uri = "https://eu.zec.rocks:443";
        let cert: &[u8] = include_bytes!("../eu.zec.rocks-leaf.der");
        LightwalletdEndpointArray {
            len: 1,
            ptr: &ConnectURIAndCertificateBlob {
                https_uri_string_ptr: https_uri.as_ptr(),
                https_uri_string_len: https_uri.len(),
                certificate_blob_ptr: cert.as_ptr(),
                certificate_blob_len: cert.len(),
            } as *const ConnectURIAndCertificateBlob,
        }
    }

    #[test]
    fn it_works() {
        do_all_the_things();
        let mut buf = [0_u8; 512];
        let merchant_str = "Google Inc.";
        let product_str = "Thing1: 12.80 USD\n\
                           Another thing: 4.00 USD\n\
                           Subtotal: 16.80 USD";
        let rsid = [65_u8; 32];
        memo_receipt_generate(&mut buf, merchant_str.as_ptr(), merchant_str.len(), product_str.as_ptr(), product_str.len(), &rsid);
        println!("buf:\n```\n{}\n```", std::str::from_utf8(&buf).expect("valid UTF8"));
    }

    #[test]
    fn fetch_mempool_contents() {
        let mempool_status = simple_get_mempool_tx(zec_rocks_eu(), uhh::PANIC);
        println!("No try: {:?}", mempool_status);
        let mempool_status = simple_get_mempool_tx(zec_rocks_eu(), uhh::LOG);
        println!("Try: {:?}", mempool_status);
    }

    #[test]
    #[should_panic]
    fn fetch_invalid_mempool_contents() {
        let invalid_endpoint = {
            let https_uri = "https://eu.ze.rocks:443";
            let cert: &[u8] = include_bytes!("../eu.zec.rocks-leaf.der");
            LightwalletdEndpointArray {
                len: 1,
                ptr: &ConnectURIAndCertificateBlob {
                    https_uri_string_ptr: https_uri.as_ptr(),
                    https_uri_string_len: https_uri.len(),
                    certificate_blob_ptr: cert.as_ptr(),
                    certificate_blob_len: cert.len(),
                } as *const ConnectURIAndCertificateBlob,
            }
        };
        let mempool_status = simple_get_mempool_tx(invalid_endpoint.clone(), uhh::LOG);
        println!("Try: {:?}", mempool_status);
        let mempool_status = simple_get_mempool_tx(invalid_endpoint.clone(), uhh::PANIC);
        println!("No try: {:?}", mempool_status);
    }

    #[test]
    fn blake3_utility() {
        let merchant_str = "Google Inc.";
        let tx_c: u32 = 1234;
        let tx_data: *const c_void = &tx_c as *const u32 as *const c_void;
        let rsid: Blake3Hash = create_rsid_from_merchant_and_tx(merchant_str.as_ptr(), merchant_str.len(), tx_data, std::mem::size_of_val(&tx_c));
        println!("RSID: {:?}", rsid);
    }
}
