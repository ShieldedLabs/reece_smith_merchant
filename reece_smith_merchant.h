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
bool memo_receipt_generate(uint8_t (*buf)[512],
                           const uint8_t *merchant_name_str,
                           size_t merchant_name_str_len,
                           const uint8_t *product_str,
                           size_t product_str_len,
                           const uint8_t (*rsid)[32]);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
