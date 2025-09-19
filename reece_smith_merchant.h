typedef struct Blake3Hash {
    uint8_t data[32];
} Blake3Hash;

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
