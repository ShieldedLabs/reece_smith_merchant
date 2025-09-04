
mod high_latency_lightwalletd_rpc_calls;
use base64::Engine;
use high_latency_lightwalletd_rpc_calls::*;

/// cbindgen:ignore
mod uhh {
    pub const LOG: u32 = 1 << 0;
    pub const CALLSTACK: u32 = 1 << 1;
    pub const PANIC: u32 = 1 << 2;
}
fn uhh<T, E: std::fmt::Debug> (result: Result<T, E>, on_fail: u32) -> Result<T, E> {
    match &result {
        Ok(_) => (),

        Err(e) => {
            if on_fail & (uhh::LOG | uhh::PANIC) != 0 {
                eprintln!("{:?}", e)
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

// NOTE: if you use u64::MAX, it will get treated as negative and then GetBlockRange will reverse &
// go to the start of the chain!
const MAX_POSSIBLE_HEIGHT: u64 = i64::MAX as u64;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ConnectURIAndCertificateBlob {
    https_uri_string_ptr: *const u8,
    https_uri_string_len: usize,
    certificate_blob_ptr: *const u8,
    certificate_blob_len: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
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

use zcash_address::{
    ToAddress,
    ZcashAddress,
};
use zcash_client_backend::{
    address::UnifiedAddress,
    keys::{
        UnifiedAddressRequest,
        UnifiedFullViewingKey,
        UnifiedIncomingViewingKey,
        UnifiedSpendingKey,
    },
    proto::compact_formats::{
        CompactBlock,
        CompactTx,
    },
};
use zcash_note_encryption::try_compact_note_decryption;
use zcash_protocol::consensus::{
    MAIN_NETWORK,
    Parameters,
};
use sapling_crypto::note_encryption::{
    CompactOutputDescription,
    SaplingDomain,
    Zip212Enforcement,
};
use orchard::note_encryption::{
    CompactAction,
    OrchardDomain,
};

pub fn filter_compact_txs_by_uivk(txs: &Option<Vec<CompactTx>>, uivk: &UnifiedIncomingViewingKey) -> Vec<CompactTx> {
    let mut filtered_txs = Vec::new();

    if let Some(txs) = txs {
        let maybe_sapling_ivk = if let Some(ivk) = uivk.sapling() { Some(ivk.prepare()) } else { None };
        let maybe_orchard_ivk = if let Some(ivk) = uivk.orchard() { Some(ivk.prepare()) } else { None };
        let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);

        for tx in txs {
            let tx_hash: &[u8] = &tx.hash;
            let tx_hash: Result<&[u8; 32],_> = tx_hash.try_into();
            match tx_hash {
                Ok(tx_hash) => println!("tx {:?}", tx_hash),
                Err(err) => println!("tx not parsing (len {}): {:?}, {:?}", tx.hash.len(), tx.hash, err),
            }

            let mut is_found = false;


            if let Some(sapling_ivk) = &maybe_sapling_ivk {
                for sapling_output in &tx.outputs {
                    // TODO: see if we can get memo
                    let Ok(output) = uhh(CompactOutputDescription::try_from(sapling_output), uhh::LOG) else { continue; };
                    if let Some((_note, recipient)) = try_compact_note_decryption(&sapling_domain, sapling_ivk, &output) {
                        match UnifiedAddress::from_receivers(None, Some(recipient), None) {
                            Some(ua) => println!("  unified sapling recipient for tx: {}", ua.encode(&MAIN_NETWORK)),
                            None     => println!("  unified sapling recipient for tx not parsed: {:?}", recipient),
                        }

                        let za = ZcashAddress::from_sapling(MAIN_NETWORK.network_type(), recipient.to_bytes());
                        println!("  zcash   sapling recipient for tx: {}", za);

                        // filtered_txs.push(());
                        is_found = true;
                        // break;
                    }
                }
            }

            if let Some(orchard_ivk) = &maybe_orchard_ivk {
                for orchard_action in &tx.actions {
                    let Ok(action) = uhh(CompactAction::try_from(orchard_action), uhh::LOG) else { continue; };
                    let orchard_domain = OrchardDomain::for_compact_action(&action);
                    // TODO: see if we can get memo
                    if let Some((_note, recipient)) = try_compact_note_decryption(&orchard_domain, orchard_ivk, &action) {
                        if let Some(ua) = UnifiedAddress::from_receivers(Some(recipient), None, None) {
                            println!("  unified orchard recipient for tx: {}", ua.encode(&MAIN_NETWORK));
                        } else {
                            println!("  unified orchard recipient for tx not parsed: {:?}", recipient);
                        }

                        // filtered_txs.push(());
                        is_found = true;
                        // break;
                    }
                }
            }


            // if !is_found
            // Option<(D::Note, D::Recipient, D::Memo)>
            // if is_found {
                // filtered_txs.push();
            // }
        }
    }

    filtered_txs
}

pub fn do_all_the_things() {
    use secrecy::ExposeSecret;

    // let mut wdb = zcash_client_sqlite::WalletDb::for_path(temp_dir.path().join("wallet.db"), MAIN_NETWORK, zcash_client_sqlite::util::SystemClock, rand_core::OsRng).unwrap();
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
    let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, seed.expose_secret(), account_id).unwrap();

    // 3. Derive Unified Full Viewing Key (UFVK)
    let ufvk: UnifiedFullViewingKey = usk.to_unified_full_viewing_key();
    let uivk: UnifiedIncomingViewingKey = ufvk.to_unified_incoming_viewing_key();
    let ufvk_encode = ufvk.encode(&MAIN_NETWORK);
    let ufvk_decode = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &ufvk_encode).unwrap();
    println!("Full Viewing Key:     {}", ufvk.encode(&MAIN_NETWORK));
    println!("Full Viewing Key 2:   {}", ufvk_decode.encode(&MAIN_NETWORK));
    println!("Incoming Viewing Key: {}", uivk.encode(&MAIN_NETWORK));
    assert_eq!(ufvk_encode, ufvk_decode.encode(&MAIN_NETWORK), "roundtrip failed");

    let uivk = UnifiedIncomingViewingKey::decode(&MAIN_NETWORK, "uivk1u7ty6ntudngulxlxedkad44w7g6nydknyrdsaw0jkacy0z8k8qk37t4v39jpz2qe3y98q4vs0s05f4u2vfj5e9t6tk9w5r0a3p4smfendjhhm5au324yvd84vsqe664snjfzv9st8z4s8faza5ytzvte5s9zruwy8vf0ze0mhq7ldfl2js8u58k5l9rjlz89w987a9akhgvug3zaz55d5h0d6ndyt4udl2ncwnm30pl456frnkj").unwrap();

    // Derive the account’s UFVK and default Unified Address (UA).
    // TODO: we want to generate these on a dev PC and transfer to the lower-privileged server
    // ALT: we can do specific handling for Sapling/Orchard incoming view keys without going through a full key
    let ua: UnifiedAddress = uivk.default_address(UnifiedAddressRequest::SHIELDED).unwrap().0;
    println!("Receive at: {}", ua.encode(&MAIN_NETWORK));

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

    const ZEC_ROCKS_EU: LightwalletdEndpointArray = {
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
    };

    fn test_uivk() -> UnifiedIncomingViewingKey {
        UnifiedIncomingViewingKey::decode(&MAIN_NETWORK, "uivk1u7ty6ntudngulxlxedkad44w7g6nydknyrdsaw0jkacy0z8k8qk37t4v39jpz2qe3y98q4vs0s05f4u2vfj5e9t6tk9w5r0a3p4smfendjhhm5au324yvd84vsqe664snjfzv9st8z4s8faza5ytzvte5s9zruwy8vf0ze0mhq7ldfl2js8u58k5l9rjlz89w987a9akhgvug3zaz55d5h0d6ndyt4udl2ncwnm30pl456frnkj").unwrap()
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
        let mempool_status = simple_get_mempool_tx(ZEC_ROCKS_EU, uhh::PANIC);
        println!("No try: {:?}", mempool_status);
        let mempool_status = simple_get_mempool_tx(ZEC_ROCKS_EU, uhh::LOG);
        println!("Try: {:?}", mempool_status);
        let uivk = test_uivk();
        filter_compact_txs_by_uivk(&mempool_status, &uivk);
        // found:           u1k9jlaxnrlsy3ppd3ep9rwrxq597j4g2v0mmj9x4x593hghr09y5stp4wsqzaxchzwecjmjtx22tquuth87vnywfu8mgk9n8mkcgxcr4f
        // orchard address: u1k9jlaxnrlsy3ppd3ep9rwrxq597j4g2v0mmj9x4x593hghr09y5stp4wsqzaxchzwecjmjtx22tquuth87vnywfu8mgk9n8mkcgxcr4f
        // given sapling:   zs1zkym0uldnxamm7c8n2tlalps0y08cll3q2ptgmslgzfpvtwh0zqt8ttlyv4p9gsysv2v75xmx5x
        // found sapling:   zs1zkym0uldnxamm7c8n2tlalps0y08cll3q2ptgmslgzfpvtwh0zqt8ttlyv4p9gsysv2v75xmx5x
    }

    #[ignore]
    #[test]
    fn fetch_mempool_contents_indefinitely() {
        loop {
            fetch_mempool_contents();
        }
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
    fn find_known_transactions_using_uivk() {
        let uivk = test_uivk();

        let maybe_block = simple_get_compact_block(ZEC_ROCKS_EU, 3051998, uhh::LOG);
        if let Some(block) = maybe_block {
            filter_compact_txs_by_uivk(&Some(block.vtx), &uivk);
        }

        let maybe_block = simple_get_compact_block(ZEC_ROCKS_EU, 3052062, uhh::LOG);
        if let Some(block) = maybe_block {
            filter_compact_txs_by_uivk(&Some(block.vtx), &uivk);
        }
    }

    #[ignore]
    #[test]
    fn dump_uivk() {
        // TODO: make small binary
        let ufvk_str = "";
        let ufvk = UnifiedFullViewingKey::decode(&MAIN_NETWORK, ufvk_str).unwrap();
        let uivk: UnifiedIncomingViewingKey = ufvk.to_unified_incoming_viewing_key();
        println!("Started with UFVK {}\n\
                  check:            {}\n\
                  generated UIVK    {}",
                  ufvk_str,
                  ufvk.encode(&MAIN_NETWORK),
                  uivk.encode(&MAIN_NETWORK));
    }

    #[test]
    fn blake3_utility() {
        let merchant_str = "Google Inc.";
        let tx_c: u32 = 1234;
        let tx_data: *const c_void = &tx_c as *const u32 as *const c_void;
        let rsid: Blake3Hash = create_rsid_from_merchant_and_tx(merchant_str.as_ptr(), merchant_str.len(), tx_data, std::mem::size_of_val(&tx_c));
        println!("RSID: {:?}", rsid);
    }

    #[test]
    fn fetch_height_range() {
        let uivk = test_uivk();

        let on_fail = uhh::PANIC;
        let maybe_blocks = simple_get_compact_block_range(ZEC_ROCKS_EU, 3051998, 3052065, on_fail);
        if let Some(blocks) = maybe_blocks {
            for block in blocks {
                println!("block at {}: {:?}", block.height, block.hash);
                filter_compact_txs_by_uivk(&Some(block.vtx), &uivk);
            }
        }
    }
}
