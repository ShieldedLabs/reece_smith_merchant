#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Some documentation here
 */
bool memo_receipt_generate(uint8_t (*buf)[512],
                           const uint8_t *merchant_id_str,
                           size_t merchant_id_str_len,
                           const uint8_t *product_str,
                           size_t product_str_len,
                           const uint8_t (*id_hash)[64]);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
