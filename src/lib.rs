#[unsafe(no_mangle)]
pub extern "C" fn add(left: usize, right: usize) -> usize {
    left + right
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
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
