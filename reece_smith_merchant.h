typedef enum MyEnum {
  MyEnum_ThingA,
  MyEnum_ThingB,
} MyEnum;

typedef struct Vector2 {
  float x;
  float y;
} Vector2;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

size_t add(size_t left, size_t right);

float vector2_magnitude(const struct Vector2 *vector, enum MyEnum kind);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
