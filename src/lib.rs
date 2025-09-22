
mod high_latency_lightwalletd_rpc_calls;
use base64::Engine;
use high_latency_lightwalletd_rpc_calls::*;
use zip32::DiversifierIndex;

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
fn uhh_option<T> (result: Option<T>, on_fail: u32) -> Option<T> {
    if result.is_none() {
        if on_fail & (uhh::LOG | uhh::PANIC) != 0 {
            eprintln!("Option of '{}' was None.", type_name::<T>())
        }

        if on_fail & uhh::CALLSTACK != 0 {
            todo!("print backtrace")
        }

        if on_fail & uhh::PANIC != 0 {
            panic!("error marked as unrecoverable")
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
#[derive(Clone, Copy, Debug)]
pub struct LightwalletdEndpointArray {
    ptr: *const ConnectURIAndCertificateBlob,
    len: usize,
}

impl Into<&'static [ConnectURIAndCertificateBlob]> for LightwalletdEndpointArray {
    fn into(self) -> &'static [ConnectURIAndCertificateBlob] {
        unsafe { &*slice_from_raw_parts(self.ptr, self.len) }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rsm_get_transactions_for_block_range(memory_buf: *mut u8, memory_buf_len: usize, uris: LightwalletdEndpointArray, viewing_key: RSMIncomingViewingKey, lo_height: u64, hi_height: u64, on_fail: u32) -> usize {
    if memory_buf_len < 2 {
        uhh_option::<[u8; 2]>(None, on_fail);
        return 0;
    }
    let v: Option<Vec<CompactBlock>> = simple_get_compact_block_range(uris, lo_height, hi_height, on_fail);
    if v.is_none() { return 0; }
    let v = v.unwrap();

    let uivk = viewing_key.to_uivk();

    let mut out_strings = Vec::new();

    for block in v {
        let compact_txs = filter_compact_txs_by_uivk(&Some(block.vtx), &uivk);
        for compact_tx in &compact_txs {
            let tx = uhh_option(simple_get_raw_transaction(uris, block.height, compact_tx.hash.clone(), on_fail), on_fail);
            if tx.is_none() { return 0; }
            let tx = tx.unwrap();
            if &<[u8;32]>::from(tx.txid()) != compact_tx.hash.as_slice() {
                uhh_option::<TxId>(None, on_fail);
                return 0;
            }
            let v = uhh_option(read_tx_with_uivk(tx.into_data(), &uivk), on_fail);
            if v.is_none() { return 0; }
            let (value, memo) = v.unwrap();

            let mut memo_len = 0; while memo_len < 512 && memo[memo_len] != 0 { memo_len += 1; }
            let addr = viewing_key.unified_address();
            let size = url_from_memo_receipt_amount_addr(null_mut(), memo.as_ptr(), memo_len, value, addr.as_ptr(), addr.len());
            let mut buf = vec![0_u8; size as usize];
            assert_eq!(size, url_from_memo_receipt_amount_addr(buf.as_mut_ptr(), memo.as_ptr(), memo_len, value, addr.as_ptr(), addr.len()));
            out_strings.push(buf);
        }
    }
    if out_strings.len() == 0 {
        // We want to return a single NOP string in order to allow the 0 return to indicate failure and rescan.
        unsafe {
            *memory_buf.byte_add(0) = 0;
            *memory_buf.byte_add(1) = 0;
            return 2;
        }
    }
    let mut total_bytes = 0;
    for os in &out_strings {
        total_bytes += 2 + os.len();
    }
    if memory_buf_len < total_bytes {
        uhh_option::<[u8; 3]>(None, on_fail);
        return 0;
    }
    unsafe {
        let mut put = memory_buf;
        for os in &out_strings {
            *(put as *mut u16) = os.len() as u16;
            put = put.byte_add(2);
            for b in os.as_slice() {
                *put = *b;
                put = put.byte_add(1);
            }
        }
        return total_bytes;
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Blake3Hash {
    data: [u8; 32],
}

use std::{
    any::type_name, ffi::c_void, ptr::{copy_nonoverlapping, null, null_mut, slice_from_raw_parts}, slice::from_raw_parts
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
    proto::{
        compact_formats::{
            CompactBlock,
            CompactTx,
        },
        service::{
            RawTransaction,
            TxFilter,
        },
    },
};
use zcash_note_encryption::{
    try_compact_note_decryption,
    try_note_decryption,
};
use zcash_primitives::transaction::{
    Transaction,
    TransactionData,
};
use zcash_protocol::{
    consensus::{
        BlockHeight, BranchId, Parameters, MAIN_NETWORK
    },
    value::COIN, TxId,
};
use sapling_crypto::note_encryption::{
    CompactOutputDescription,
    SaplingDomain,
    Zip212Enforcement,
};
use orchard::{
    note_encryption::{
        CompactAction,
        OrchardDomain,
    }
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
            /*match tx_hash {
                Ok(tx_hash) => println!("tx {:?}", tx_hash),
                Err(err) => println!("tx not parsing (len {}): {:?}, {:?}", tx.hash.len(), tx.hash, err),
            }*/

            let mut is_found = false;

            { // DUP
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
                            /*if let Some(ua) = UnifiedAddress::from_receivers(Some(recipient), None, None) {
                                println!("  unified orchard recipient for tx: {}", ua.encode(&MAIN_NETWORK));
                            } else {
                                println!("  unified orchard recipient for tx not parsed: {:?}", recipient);
                            }*/

                            // filtered_txs.push(());
                            is_found = true;
                            // break;
                        }
                    }
                }
            }

            if is_found {
                filtered_txs.push(tx.clone());
            }
        }
    }

    filtered_txs
}

pub fn read_tx_with_uivk(tx: TransactionData<zcash_primitives::transaction::Authorized>, uivk: &UnifiedIncomingViewingKey) -> Option<(u64, [u8; 512])> {
    let maybe_sapling_ivk = if let Some(ivk) = uivk.sapling() { Some(ivk.prepare()) } else { None };
    let maybe_orchard_ivk = if let Some(ivk) = uivk.orchard() { Some(ivk.prepare()) } else { None };
    let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);

    let mut res = None;

    if let (Some(ivk), Some(bundle)) = (&maybe_orchard_ivk, tx.orchard_bundle()) {
        for action in bundle.actions() {
            let domain = OrchardDomain::for_action(action);
            if let Some((note, recipient, memo)) = try_note_decryption(&domain, ivk, action) {
                /*if let Some(ua) = UnifiedAddress::from_receivers(Some(recipient), None, None) {
                    println!("  unified orchard recipient for tx: {}", ua.encode(&MAIN_NETWORK));
                } else {
                    println!("  unified orchard recipient for tx not parsed: {:?}", recipient);
                }*/

                let value = note.value().inner();
                //println!("Value: {} zats, Memo:\n---\n{}\n---\n", value, String::from_utf8_lossy(&memo));
                if res.is_none() {
                    res = Some((value, memo));
                }
                // TODO: account for multiple notes in the same transaction
            }
        }
    }

    if let (Some(ivk), Some(bundle)) = (&maybe_sapling_ivk, tx.sapling_bundle()) {
        for output in bundle.shielded_outputs() {
            if let Some((note, recipient, memo)) = try_note_decryption(&sapling_domain, ivk, output) {
                match UnifiedAddress::from_receivers(None, Some(recipient), None) {
                    Some(ua) => println!("  unified sapling recipient for tx: {}", ua.encode(&MAIN_NETWORK)),
                    None     => println!("  unified sapling recipient for tx not parsed: {:?}", recipient),
                }

                let za = ZcashAddress::from_sapling(MAIN_NETWORK.network_type(), recipient.to_bytes());
                println!("  zcash   sapling recipient for tx: {}", za);

                let value = note.value().inner();
                println!("Value: {} zats, Memo:\n---\n{}\n---\n", value, String::from_utf8_lossy(&memo));
                if res.is_none() {
                    res = Some((value, memo));
                }
            }
        }
    }

    res
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

#[derive(PartialEq, Eq, Debug)]
#[repr(C)]
pub struct RSMIncomingViewingKey {
    internal_orchard: orchard::keys::IncomingViewingKey,
}
impl RSMIncomingViewingKey {
    fn to_uivk(&self) -> UnifiedIncomingViewingKey {
        UnifiedIncomingViewingKey::new(None, Some(self.internal_orchard.clone()))
    }
    fn unified_address(&self) -> String {
        self.to_uivk().address(DiversifierIndex::new(), UnifiedAddressRequest::AllAvailableKeys).unwrap().encode(&MAIN_NETWORK)
    }
}

#[unsafe(no_mangle)]
/// Some documentation here
pub extern "C" fn rsm_parse_incoming_viewing_key_from_string(unified_incoming_viewing_key_str: *const u8, unified_incoming_viewing_key_str_len: usize, key_out: *mut RSMIncomingViewingKey) -> bool {
    unsafe {
        let v = UnifiedIncomingViewingKey::decode(&MAIN_NETWORK, &String::from_utf8_lossy(
            &*slice_from_raw_parts(unified_incoming_viewing_key_str, unified_incoming_viewing_key_str_len)));
        if v.is_err() { return false; }
        let v = v.unwrap();
        let v = v.orchard().clone();
        if v.is_none() { return false; }
        let v = v.unwrap();
        *key_out = RSMIncomingViewingKey { internal_orchard: v };

        true
    }
}

#[unsafe(no_mangle)]
/// Some documentation here
pub extern "C" fn rsm_convert_unified_full_viewing_key_string_to_unified_incoming_viewing_key_string(unified_full_viewing_key_str: *const u8, unified_full_viewing_key_str_len: usize, out_buf: *mut u8, out_buf_len: usize) -> usize {
    unsafe {
        let v = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &String::from_utf8_lossy(
            &*slice_from_raw_parts(unified_full_viewing_key_str, unified_full_viewing_key_str_len)));
        if v.is_err() { return 0; }
        let v = v.unwrap();
        let string = v.to_unified_incoming_viewing_key().encode(&MAIN_NETWORK);
        let bytes = string.as_bytes();
        let mut i = 0;
        while i < bytes.len() && i < out_buf_len {
            *out_buf.add(i) = bytes[i];
            i += 1;
        }
        i
    }
}

#[unsafe(no_mangle)]
/// Some documentation here
pub extern "C" fn memo_receipt_generate(buf: &mut [u8; 512], merchant_name_str: *const u8, merchant_name_str_len: usize, product_str: *const u8, product_str_len: usize, rsid: &[u8; 32]) -> i32 {
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
            else { return -1; }
        }
    }

    // println!("memo sizes:");
    // println!("pre1: {}", prefix1.len());
    // println!("bs64: {}", rsm_id_base64.len());
    // println!("pre2: {}", prefix2.len());
    // println!("nl:   1");
    // println!("-------");
    // println!("fixed used: {}", prefix1.len() + rsm_id_base64.len() + prefix2.len() + 1);

    if prefix1.len() + rsm_id_base64.len() + prefix2.len() + merchant_name_str_len + 1 + product_str_len <= 512 {
        let mut o = 0;
        unsafe {
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
            o += product_str_len;
        }
        o as i32
    } else {
        -1
    }
}

fn write_val_to_buf_o(buf: *mut u8, o: usize, amount: u64) -> usize {
    let mut val_buf = [0u8; 17];
    let mut at_i = 17;
    let zecs = amount / COIN;
    let zats = amount % COIN;

    if zats > 0 {
        let mut rem_zats = zats;
        let mut has_started = 0;

        at_i -= 1; // we'll continually overwrite the first item in the buffer to avoid trailing 0s
        for _ in 0..8 {
            let digit_val = (rem_zats % 10) as u8;
            rem_zats /= 10;
            val_buf[at_i] = b'0' + digit_val;
            has_started |= (digit_val != 0) as usize;
            at_i -= has_started; // NOTE: this is unusual but allows branchless & we know there
                                 // will be a subsequent '.' char
        }

        val_buf[at_i] = b'.';
    }

    let mut rem_zecs = zecs;
    loop {
        let digit_val = (rem_zecs % 10) as u8;
        rem_zecs /= 10;
        at_i -= 1;
        val_buf[at_i] = b'0' + digit_val;

        if rem_zecs == 0 {
            break;
        }
    }

    unsafe {
        return copy_to_buf_o(&val_buf[at_i..], buf, o);
    }
}


/// does no copy for null buf
unsafe fn copy_to_buf_o(src: &[u8], buf: *mut u8, o: usize) -> usize {
    if !buf.is_null() {
        unsafe {
            copy_nonoverlapping(src.as_ptr(), buf.add(o), src.len());
        }
    }
    return src.len();
}

/// NOTE: assuming orchard addresses are a constant size & we don't want to include arbitrary
/// unified addresses, we can give a fixed upper buf size that allows for a full memo & max
/// possible zec
///
/// Returns negative number on failure
/// Returns size. If buf is null, returns required size.
///
/// TODO(?): label + message options
#[unsafe(no_mangle)]
pub extern "C" fn url_from_memo_receipt_amount_addr(buf: *mut u8, memo: *const u8, memo_len: usize, amount: u64, addr: *const u8, addr_len: usize) -> i32 {
    // "zcash:": 6 bytes
    // orchard address: 106 bytes
    // "?amount=": 8 bytes
    // ("There MUST NOT be more than 8 digits in the decimal fraction" -- ZIP 321)
    // max representable value: "21000000.00000000": 17 bytes
    // "?memo=": 6 bytes
    // max base64 memo: 683(?)
    if memo_len > 512 {
        return -1;
    }

    let mut o = 0;

    let zcash_url = "zcash:";
    let amount_arg = "?amount=";
    let message_arg = "&message=";
    let memo_arg = "&memo=";

    // println!("max len: {}; {}", base64::encoded_len(512, false).unwrap(), (512 * 4 + 2) / 3);
    // TODO: turn into mutable slice & edit that way?
    unsafe {
        o += copy_to_buf_o(zcash_url.as_bytes(), buf, o);
        o += copy_to_buf_o(from_raw_parts(addr, addr_len), buf, o);

        o += copy_to_buf_o(amount_arg.as_bytes(), buf, o);
        o += write_val_to_buf_o(buf, o, amount);

        o += copy_to_buf_o(memo_arg.as_bytes(), buf, o);
        let mut b64_memo_buf = [0; 683];
        let b64_memo_len = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_slice(from_raw_parts(memo, memo_len), &mut b64_memo_buf).unwrap();
        // println!("b64 memo len: {}", b64_memo_len);
        o += copy_to_buf_o(&b64_memo_buf[..b64_memo_len], buf, o);

        if false {
            let vec = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&b64_memo_buf[..b64_memo_len]).unwrap();
            let decoded = String::from_utf8_lossy(&vec);
            println!("decoded:\n```\n{}\n```", decoded);
            assert_eq!(vec, from_raw_parts(memo, memo_len));
        }

        if false {
            o += copy_to_buf_o(message_arg.as_bytes(), buf, o);
            o += copy_to_buf_o("hello".as_bytes(), buf, o);
        }
    }

    return o as i32;
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
    #[allow(invalid_value)]
    fn test_viewing_key() -> RSMIncomingViewingKey {
        unsafe {
            let string = "uivk1u7ty6ntudngulxlxedkad44w7g6nydknyrdsaw0jkacy0z8k8qk37t4v39jpz2qe3y98q4vs0s05f4u2vfj5e9t6tk9w5r0a3p4smfendjhhm5au324yvd84vsqe664snjfzv9st8z4s8faza5ytzvte5s9zruwy8vf0ze0mhq7ldfl2js8u58k5l9rjlz89w987a9akhgvug3zaz55d5h0d6ndyt4udl2ncwnm30pl456frnkj".as_bytes();
            let mut key: RSMIncomingViewingKey = std::mem::MaybeUninit::uninit().assume_init();
            assert!(rsm_parse_incoming_viewing_key_from_string(string.as_ptr(), string.len(), &mut key as *mut RSMIncomingViewingKey));
            key
        }
    }
    #[test]
    fn print_unified_address_for_orchard_only_receiver_and_check_same() {
        let key = test_viewing_key();
        println!("Test key UA: '{}'", key.unified_address())
    }
    #[allow(invalid_value)]
    #[test]
    fn check_test_key_same_as_ufvk_derivation() {
        unsafe {
            let src_string = "uview1x2s5ketm90fzfgka67szt6xdg0gdvm6wjce7h7hvypvcvj63fqp0t6ldyk9wsunpngg32uaek69nlmj3jhxllsn749l5tjjmt3g52ulgka3yyrrxfh7lyq9ffennyuqydnclw39d9rjtklvljdfvpuq0wpmuf8x4lmzaxeqeucpu7euky3spqu7kp839c7remlgc92lz9am8y8etdzstszdx2yhtjkh0ke3umr5ycr5rfmhcz4w26aj4d7cscpumc3xdzerdnfsf44kg67t6hv08m2uqyfzfy75p6rvp8kz8yv368f2q3qpfd27hkwxy96pu8g635zcpc3lezecq9tl2jcdf9maez3wj5nhn05r8hxeycvnkj9246aj5nfe2twkh77syat9dd".as_bytes();
            let mut buf: Vec<u8> = Vec::new();
            for _ in 0..1024 { buf.push(0); }
            buf.truncate(rsm_convert_unified_full_viewing_key_string_to_unified_incoming_viewing_key_string(src_string.as_ptr(), src_string.len(), buf.as_ptr() as *mut u8, buf.len()));
            let mut key: RSMIncomingViewingKey = std::mem::MaybeUninit::uninit().assume_init();
            assert!(rsm_parse_incoming_viewing_key_from_string(buf.as_ptr(), buf.len(), &mut key as *mut RSMIncomingViewingKey));
            assert_eq!(key, test_viewing_key());
        }
    }

    #[test]
    fn it_works() {
        do_all_the_things();
        let mut memo_buf = [0_u8; 512];
        let merchant_str = "Google Inc.";
        let product_str = "Thing1: 12.80 USD\n\
                           Another thing: 4.00 USD\n\
                           Subtotal: 16.80 USD";
        let rsid = [65_u8; 32];
        let memo_len = memo_receipt_generate(&mut memo_buf, merchant_str.as_ptr(), merchant_str.len(), product_str.as_ptr(), product_str.len(), &rsid);
        println!("memo_buf:\n```\n{}\n```", std::str::from_utf8(&memo_buf).expect("valid UTF8"));

        let mut url_buf = [0u8; 2056];
        let addr = "u1k9jlaxnrlsy3ppd3ep9rwrxq597j4g2v0mmj9x4x593hghr09y5stp4wsqzaxchzwecjmjtx22tquuth87vnywfu8mgk9n8mkcgxcr4f";
        let url_size = url_from_memo_receipt_amount_addr(url_buf.as_mut_ptr(), memo_buf.as_ptr(), memo_len as usize, 3*COIN/2, addr.as_bytes().as_ptr(), addr.len());
        println!("url_buf:\n```\n{}\n```", std::str::from_utf8(&url_buf).expect("valid UTF8"));

        let err_correct_lvls = [
            qrcode::EcLevel::L, // allows up to  7% wrong blocks
            qrcode::EcLevel::M, // allows up to 15%
            qrcode::EcLevel::Q, // allows up to 25%
            qrcode::EcLevel::H, // allows up to 30%
        ];
        for ec_lvl in err_correct_lvls {
            let qr = qrcode::QrCode::with_error_correction_level(&url_buf[..url_size as usize], ec_lvl).unwrap();
            let qr_uni = qr.render::<qrcode::render::unicode::Dense1x2>().build();
            println!("{:?}:\n{}", ec_lvl, qr_uni);
            // let qr_str = qr.render().dark_color('#').build();
            // println!("{:?}:\n{}", ec_lvl, qr_str);
        }
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
    fn fetch_mempool_contents_indefinitely_demo() {
        loop {
            let mempool_status = simple_get_mempool_tx(ZEC_ROCKS_EU, uhh::LOG);
            println!("Try: {:?}", mempool_status);
            let uivk = test_uivk();
            filter_compact_txs_by_uivk(&mempool_status, &uivk);
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

    fn memo_from_str(str: &str) -> [u8; 512] {
        let mut memo = [0_u8; 512];
        memo[0..str.len()].copy_from_slice(str.as_bytes());
        memo
    }

    #[test]
    fn value_encoding() {
        struct Test {
            amount: u64,
            string: &'static str,
        };
        let tests = [
            Test { amount: 1 * COIN, string: "1" },
            Test { amount: 1234 * COIN, string: "1234" },
            Test { amount: COIN / 2, string: "0.5" },
            Test { amount: 3 * COIN / 2, string: "1.5" },
            Test { amount: 1,  string: "0.00000001" },
            Test { amount: 10, string: "0.0000001" },
        ];

        for test in tests {
            let mut buf = [0u8; 32];
            let len = write_val_to_buf_o(buf.as_mut_ptr(), 0, test.amount);
            assert!(len > 0);
            assert_eq!(test.string, std::str::from_utf8(&buf[..len]).unwrap());
        }
    }

    #[test]
    fn c_api_fetch_height_range() {
        let mut arena = vec![0_u8; 4096];
        arena.truncate(rsm_get_transactions_for_block_range(arena.as_ptr() as *mut u8, arena.len(), ZEC_ROCKS_EU, test_viewing_key(), 3051998, 3052065, uhh::PANIC));
        let mut out_strings = Vec::new();
        unsafe {
            let mut cursor = 0;
            while cursor < arena.len() {
                let len = *(arena.as_ptr().byte_add(cursor) as *const u16);
                cursor += 2;
                let slice = slice_from_raw_parts(arena.as_ptr().byte_add(cursor), len as usize);
                out_strings.push(String::from_utf8_lossy(&*slice));
                cursor += len as usize;
            }
        }
        for os in &out_strings {
            println!("{}", os);
        }
    }

    #[test]
    fn c_api_fetch_height_range_returns_success_nothing_for_range_in_the_past() {
        let mut arena = vec![0_u8; 4096];
        assert_eq!(2, rsm_get_transactions_for_block_range(arena.as_ptr() as *mut u8, arena.len(), ZEC_ROCKS_EU, test_viewing_key(), 3021998, 3022065, uhh::PANIC));
    }

    #[test]
    fn fetch_height_range() {
        let uivk = test_uivk();
        #[derive(Eq, PartialEq, Debug)]
        struct MemoValueAtHeight {
            height: u64,
            value: u64,
            memo: [u8; 512],
        }
        let vals = &[
            MemoValueAtHeight {
                height: 3051998,
                value: 50000,
                memo: memo_from_str("Test memo contents.\n\nRSMID:0123456789ABCDEFabcdef"),
            },
            MemoValueAtHeight {
                height: 3052062,
                value: 30000,
                memo: memo_from_str(
                    "🛡MSG\n\
                    u16jd565hta2s78r4hrjkn5jxzyjyzt98jkaffv2jvwy098scxdvhfx69rrynw3y0whk7uatz3586axjk6tgxsqw8z3mw025ld5lq649tkgcjuu4v3t5m9amhp6pc6rcxh207fjvtdnuu5tq2tdwqzkaac2ad055pdea5k99eypv70s6le8884j5au56p2yp6ztr6fdd7qtqn42hk8hde\n\
                    Ywallet Subject\n\
                    Memo: Sent from YWallet"
                ),
            },
        ];

        let mut found_i = 0;
        let on_fail = uhh::PANIC;
        let maybe_blocks = simple_get_compact_block_range(ZEC_ROCKS_EU, 3051998, 3052065, on_fail);
        if let Some(blocks) = maybe_blocks {
            for block in blocks {
                println!("block at {}: {:?}", block.height, block.hash);
                let compact_txs = filter_compact_txs_by_uivk(&Some(block.vtx), &uivk);
                for compact_tx in &compact_txs {
                    if let Some(tx) = simple_get_raw_transaction(ZEC_ROCKS_EU, block.height, compact_tx.hash.clone(), on_fail) {
                        println!("  Retrieved full tx with txid: {:?}", tx.txid());
                        assert_eq!(&<[u8;32]>::from(tx.txid()), compact_tx.hash.as_slice());
                        if let Some((value, memo)) = read_tx_with_uivk(tx.into_data(), &uivk) {
                            assert_eq!(vals[found_i], MemoValueAtHeight{ height: block.height, value, memo });
                            found_i += 1;
                        }
                    } else {
                        println!("  Couldn't retrieve full tx");
                    }
                }
            }
        }
    }
}
