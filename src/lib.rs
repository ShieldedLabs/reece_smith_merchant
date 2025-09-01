
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

// Define a C-compatible function with extern "C" and #[no_mangle]
#[unsafe(no_mangle)]
pub extern "C" fn vector2_magnitude(vector: *const Vector2, kind: MyEnum) -> f32 {
    // Safety: Ensure the pointer is valid in real code
    unsafe {
        if vector.is_null() {
            return 0.0;
        }
        let v = &*vector;
        (v.x * v.x + v.y * v.y).sqrt()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        do_all_the_things();
    }
}
