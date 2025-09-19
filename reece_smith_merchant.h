typedef struct Blake3Hash {
    uint8_t data[32];
} Blake3Hash;

typedef struct RSMIncomingViewingKey {
    IncomingViewingKey internal_orchard;
} RSMIncomingViewingKey;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct Blake3Hash create_rsid_from_merchant_and_tx(const uint8_t *merchant_name_str,
                                                   size_t merchant_name_str_len,
                                                   const void *tx_data,
                                                   size_t tx_data_size);

/**
 * Some documentation here
 */
bool rsm_parse_incoming_viewing_key_from_string(const uint8_t *unified_incoming_viewing_key_str,
                                                size_t unified_incoming_viewing_key_str_len,
                                                struct RSMIncomingViewingKey *key_out);

/**
 * Some documentation here
 */
bool memo_receipt_generate(uint8_t (*buf)[512],
                           const uint8_t *merchant_name_str,
                           size_t merchant_name_str_len,
                           const uint8_t *product_str,
                           size_t product_str_len,
                           const uint8_t (*rsid)[32]);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
