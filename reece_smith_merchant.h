typedef struct ConnectURIAndCertificateBlob {
    const uint8_t *https_uri_string_ptr;
    size_t https_uri_string_len;
    const uint8_t *certificate_blob_ptr;
    size_t certificate_blob_len;
} ConnectURIAndCertificateBlob;

typedef struct LightwalletdEndpointArray {
    const struct ConnectURIAndCertificateBlob *ptr;
    size_t len;
} LightwalletdEndpointArray;

typedef struct RSMIncomingViewingKey {
    uint8_t internal_orchard[64];
} RSMIncomingViewingKey;

typedef struct Blake3Hash {
    uint8_t data[32];
} Blake3Hash;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

size_t rsm_get_transactions_for_block_range(uint8_t *memory_buf,
                                            size_t memory_buf_len,
                                            struct LightwalletdEndpointArray uris,
                                            struct RSMIncomingViewingKey viewing_key,
                                            uint64_t lo_height,
                                            uint64_t hi_height,
                                            uint32_t on_fail);

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
size_t rsm_convert_unified_full_viewing_key_string_to_unified_incoming_viewing_key_string(const uint8_t *unified_full_viewing_key_str,
                                                                                          size_t unified_full_viewing_key_str_len,
                                                                                          uint8_t *out_buf,
                                                                                          size_t out_buf_len);

/**
 * Some documentation here
 */
int32_t memo_receipt_generate(uint8_t (*buf)[512],
                              const uint8_t *merchant_name_str,
                              size_t merchant_name_str_len,
                              const uint8_t *product_str,
                              size_t product_str_len,
                              const uint8_t (*rsid)[32]);

/**
 * NOTE: assuming orchard addresses are a constant size & we don't want to include arbitrary
 * unified addresses, we can give a fixed upper buf size that allows for a full memo & max
 * possible zec
 *
 * Returns negative number on failure
 * Returns size. If buf is null, returns required size.
 *
 * TODO(?): label + message options
 */
int32_t url_from_memo_receipt_amount_addr(uint8_t *buf,
                                          const uint8_t *memo,
                                          size_t memo_len,
                                          uint64_t amount,
                                          const uint8_t *addr,
                                          size_t addr_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
