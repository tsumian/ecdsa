use core::fmt::Debug;
use core::ops::{Add, AddAssign, BitAnd, Div, Mul, Rem, ShrAssign, Sub, SubAssign};
use rand::Rng;
use sha2::{Digest, Sha256};

// Inspired by toru3/modulo-n-tools
// https://gitlab.com/Toru3/modulo-n-tools/-/tree/master?ref_type=heads

// Define the elliptic curve parameters
const N: [u64; 4] = [
    0xffffffff00000000,
    0xffffffff,
    0xbce6faada7179e84,
    0xf3b9cac2fc632551,
];

const P: [u64; 4] = [
    0xffffffff00000001,
    0x00000000,
    0x00000000,
    0xfffffffffffffffe,
];

const GX: [u64; 4] = [
    0x6b17d1f2e12c4247,
    0xf8bce6e563a440f2,
    0x77037d812deb33a0,
    0xf4a13945d898c296,
];

const GY: [u64; 4] = [
    0x4fe342e2fe1a7f9b,
    0x8ee7eb4a7c0f9e16,
    0x2bce33576b315ece,
    0xcbb6406837bf51f5,
];

const A: [u64; 4] = [
    0xffffffff00000001,
    0x00000000,
    0x00000000,
    0xfffffffffffffffc,
];

const B: [u64; 4] = [
    0x5ac635d8aa3a93e7,
    0xb3ebbd55769886bc,
    0x651d06b0cc53b0f6,
    0x3bce3c3e27d2604b,
];

/// Generates a new private key.
///
/// # Returns
///
/// A private key represented as an array of 4 64-bit unsigned integers.
///
/// # Examples
///
/// ```
/// let priv_key = generate_private_key();
/// assert_eq!(priv_key.len(), 4);
/// ```
fn generate_private_key() -> [u64; 4] {
    let mut rng = rand::thread_rng();
    let mut priv_key = [0u64; 4];
    for i in 0..4 {
        priv_key[i] = rng.gen::<u64>() % N[i];
    }
    priv_key
}

/// Reduces a given value modulo a specified modulus.
///
/// # Parameters
///
/// * `a`: The value to be reduced. This value is modified in place.
/// * `modulo`: A reference to the modulus value. The result will be in the range `[0, modulo)`.
///
/// # Returns
///
/// The reduced value, which is within the range `[0, modulo)`.
///
/// # Examples
///
/// ```
/// let mut value = 20u64;
/// let modulus = 15u64;
/// let result = reduce(value, &modulus);
/// assert_eq!(result, 5);
/// ```
pub fn reduce<T>(mut a: T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T> + Copy,
{
    if &a >= modulo {
        a -= modulo;
    }
    // We do not need to handle the negative case since `u64` cannot be negative.
    a
}

/// Adds two values and reduces the result modulo a specified modulus.
///
/// # Parameters
///
/// * `a`: A reference to the first value to be added.
/// * `b`: A reference to the second value to be added.
/// * `modulo`: A reference to the modulus value. The result will be in the range `[0, modulo)`.
///
/// # Returns
///
/// The result of `(a + b) % modulo`, which is within the range `[0, modulo)`.
///
/// # Examples
///
/// ```
/// let a = 10u64;
/// let b = 15u64;
/// let modulus = 12u64;
/// let result = add_mod(&a, &b, &modulus);
/// assert_eq!(result, 1);
/// ```
pub fn add_mod<T>(a: &T, b: &T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T> + Copy,
    for<'x> &'x T: Add<Output = T>,
{
    let c = a + b; // Perform the addition
    reduce(c, modulo)
}

/// Subtracts two values and reduces the result modulo a specified modulus.
///
/// # Parameters
///
/// * `a`: A reference to the value to be subtracted from.
/// * `b`: A reference to the value to subtract.
/// * `modulo`: A reference to the modulus value. The result will be in the range `[0, modulo)`.
///
/// # Returns
///
/// The result of `(a - b) % modulo`, which is within the range `[0, modulo)`. If the result of the
/// subtraction is negative, it wraps around by adding the modulus.
///
/// # Examples
///
/// ```
/// let a = 10u64;
/// let b = 15u64;
/// let modulus = 12u64;
/// let result = sub_mod(&a, &b, &modulus);
/// assert_eq!(result, 7); // 10 - 15 + 12 = 7 (mod 12)
/// ```
pub fn sub_mod<T>(a: &T, b: &T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T> + Copy,
    for<'x> &'x T: Add<Output = T> + Sub<Output = T>,
{
    if a >= b {
        let c = a - b;
        reduce(c, modulo)
    } else {
        let temp = a + modulo;
        let c = &temp - b;
        reduce(c, modulo)
    }
}

/// Multiplies two values and reduces the result modulo a specified modulus.
///
/// # Parameters
///
/// * `a`: A reference to the first value to be multiplied.
/// * `b`: A reference to the second value to be multiplied.
/// * `modulo`: A reference to the modulus value. The result will be in the range `[0, modulo)`.
///
/// # Returns
///
/// The result of `(a * b) % modulo`, which is within the range `[0, modulo)`.
///
/// # Examples
///
/// ```
/// let a = 7u64;
/// let b = 8u64;
/// let modulus = 10u64;
/// let result = mul_mod(&a, &b, &modulus);
/// assert_eq!(result, 6); // (7 * 8) % 10 = 56 % 10 = 6
/// ```
pub fn mul_mod<T>(a: &T, b: &T, modulo: &T) -> T
where
    for<'x> &'x T: Mul<Output = T> + Rem<Output = T>,
{
    &(a * b) % modulo
}

/// Computes the modular exponentiation of a value raised to a power, modulo a specified modulus.
///
/// # Parameters
///
/// * `a`: The base value.
/// * `b`: The exponent value.
/// * `modulo`: A reference to the modulus value. The result will be in the range `[0, modulo)`.
///
/// # Returns
///
/// The result of \( a^b \mod \text{modulo} \), which is within the range `[0, modulo)`.
///
/// # Examples
///
/// ```
/// let a = 2u64;
/// let b = 10u64;
/// let modulo = 1000u64;
/// let result = pow_mod(a, b, &modulo);
/// assert_eq!(result, 24); // 2^10 % 1000 = 1024 % 1000 = 24
/// ```
pub fn pow_mod<T, U>(a: T, mut b: U, modulo: &T) -> T
where
    T: From<u8>,
    for<'x> &'x T: Mul<Output = T> + Rem<Output = T>,
    U: Ord + ShrAssign<u8> + From<u8>,
    for<'x> &'x U: BitAnd<Output = U>,
{
    let c0 = U::from(0);
    let c1 = U::from(1);
    let mut x = a;
    let mut y = T::from(1);
    while b > c0 {
        if &b & &c1 != c0 {
            y = mul_mod(&x, &y, modulo);
        }
        x = mul_mod(&x, &x, modulo);
        b >>= 1;
    }
    y
}

/// Computes the modular multiplication of a value with the result of a base raised to a power, modulo a specified modulus. Inspired by
///
/// # Parameters
///
/// * `a`: The multiplier value.
/// * `base`: The base value to be exponentiated.
/// * `power`: The exponent value.
/// * `modulo`: A reference to the modulus value. The result will be in the range `[0, modulo)`.
///
/// # Returns
///
/// The result of \( a \times \text{base}^\text{power} \mod \text{modulo} \), which is within the range `[0, modulo)`.
///
/// # Examples
///
/// ```
/// let a = 3u64;
/// let base = 2u64;
/// let power = 10u64;
/// let modulo = 1000u64;
/// let result = mul_pow_mod(a, base, power, &modulo);
/// assert_eq!(result, 72); // 3 * 2^10 % 1000 = 3 * 1024 % 1000 = 3072 % 1000 = 72
/// ```
pub fn mul_pow_mod<T, U>(a: T, base: T, mut power: U, modulo: &T) -> T
where
    for<'x> &'x T: Mul<Output = T> + Rem<Output = T>,
    U: Ord + ShrAssign<u8> + From<u8>,
    for<'x> &'x U: BitAnd<Output = U>,
{
    let c0 = U::from(0);
    let c1 = U::from(1);
    let mut x = base;
    let mut y = a;
    while power > c0 {
        if &power & &c1 != c0 {
            y = mul_mod(&x, &y, modulo);
        }
        x = mul_mod(&x, &x, modulo);
        power >>= 1;
    }
    y
}

/// Computes the Extended Euclidean Algorithm (EEA).
///
/// Given two integers `a` and `b`, where `a >= b`, this function returns a tuple `(g, x, y)`
/// such that `g` is the greatest common divisor of `a` and `b`, and `g = a * x + b * y`.
///
/// # Parameters
///
/// * `a` - The first integer.
/// * `b` - The second integer.
///
/// # Returns
///
/// A tuple `(g, x, y)` representing the greatest common divisor `g` and the coefficients `x` and `y`.
///
/// # Examples
///
/// ```
/// use ecdsa::egcd;
///
/// let result = egcd(10, 6);
/// assert_eq!(result, (2, 1, -1));
/// ```
pub fn egcd<T: Debug>(a: T, b: T) -> (T, T, T)
where
    T: Copy
        + PartialEq
        + PartialOrd
        + Sub<Output = T>
        + Mul<Output = T>
        + Div<Output = T>
        + Rem<Output = T>
        + From<u8>
        + Ord
        + for<'x> AddAssign<&'x T>
        + for<'x> SubAssign<&'x T>,
    for<'x> &'x T: Mul<Output = T> + Rem<Output = T>,
    for<'x> &'x T: Add<Output = T> + Sub<Output = T>,
{
    if a == T::from(0u8) {
        (b, T::from(0u8), T::from(1u8))
    } else {
        let (g, x, y) = egcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// Calculates the modular inverse of a number using the Euclidean algorithm.
///
/// Given an integer `x` and a modulus `p`, this function computes the modular inverse `q`
/// such that `x * q ≡ 1 (mod p)`.
///
/// # Arguments
///
/// * `x` - The integer for which to find the modular inverse.
/// * `p` - The modulus.
///
/// # Returns
///
/// The modular inverse `q` if it exists, wrapped in `Some(q)`. If the modular inverse does not exist,
/// this function panics.
///
/// # Examples
///
/// ```
/// use ecdsa::{inv_mod, add_mod};
///
/// let result = inv_mod(3, 11);
/// assert_eq!(result, Some(4));
/// ```
pub fn inv_mod<T: Debug>(x: T, p: T) -> Option<T>
where
    T: Copy
        + PartialEq
        + PartialOrd
        + Sub<Output = T>
        + Mul<Output = T>
        + Div<Output = T>
        + Rem<Output = T>
        + From<u8>
        + Ord
        + for<'x> AddAssign<&'x T>
        + for<'x> SubAssign<&'x T>,
    for<'x> &'x T: Mul<Output = T> + Rem<Output = T>,
    for<'x> &'x T: Add<Output = T> + Sub<Output = T>,
{
    let (g, x, _) = egcd(x, p);
    if g != T::from(1u8) {
        panic!("Multiplicative inverse Does not exist!")
    } else {
        let zero = T::from(0u8);
        let temp = add_mod(&x, &zero, &p);
        let q = add_mod(&temp, &p, &p);
        println!("q: {:?}", q);
        Some(q)
    }
}

// // This is a placeholder function for scalar multiplication
// // You should replace this with an actual implementation
// fn mul(scalar: [u64; 4], point: ([u64; 4], [u64; 4]), p: [u64; 4]) -> ([u64; 4], [u64; 4]) {
//     // Implement point multiplication here
//     (point.0, point.1)
// }

// // Placeholder function for point addition
// fn add(
//     point1: ([u64; 4], [u64; 4]),
//     point2: ([u64; 4], [u64; 4]),
//     p: [u64; 4],
// ) -> ([u64; 4], [u64; 4]) {
//     // Implement point addition here
//     (point1.0, point1.1)
// }

// // Placeholder function for modular inverse
// fn mod_inv(value: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
//     // Implement modular inverse here
//     value
// }

// fn generate_public_key(priv_key: [u64; 4]) -> ([u64; 4], [u64; 4]) {
//     // Generator point of the curve
//     let g = (GX, GY);
//     mul(priv_key, g, P)
// }

// // Signature generation
// fn sign_message(priv_key: [u64; 4], message: &[u8]) -> ([u64; 4], [u64; 4]) {
//     let hash = Sha256::digest(message);
//     let z = [
//         hash[0] as u64,
//         hash[1] as u64,
//         hash[2] as u64,
//         hash[3] as u64,
//     ]; // Simplified for illustration
//     let k = generate_private_key(); // Temporary random value
//     let (x1, y1) = mul(k, (GX, GY), P);
//     let r = x1; // Simplified, typically reduce mod N
//     let k_inv = mod_inv(k, N);
//     let s = mul_add(k_inv, add(z, mul(r, priv_key, N)), N); // Simplified
//     (r, s)
// }

// // Signature verification
// fn verify_signature(
//     pub_key: ([u64; 4], [u64; 4]),
//     message: &[u8],
//     signature: ([u64; 4], [u64; 4]),
// ) -> bool {
//     let (r, s) = signature;
//     let w = mod_inv(s, N);
//     let hash = Sha256::digest(message);
//     let z = [
//         hash[0] as u64,
//         hash[1] as u64,
//         hash[2] as u64,
//         hash[3] as u64,
//     ]; // Simplified for illustration
//     let u1 = mul(z, w, N); // Simplified
//     let u2 = mul(r, w, N); // Simplified
//     let (x1, y1) = add(mul(u1, (GX, GY), P), mul(u2, pub_key, P), P);
//     x1 == r // Simplified comparison
// }

fn main() {
    // Key generation
    let priv_key = generate_private_key();
    println!("Private key: {:x?}", priv_key);
    let example = inv_mod(7, 31);
    println!("example: {:?}", example);

    // let pub_key = generate_public_key(priv_key);

    // // Message to be signed
    // let message = b"Hello, world!";

    // // Sign the message
    // let signature = sign_message(priv_key, message);

    // // Verify the signature
    // let is_valid = verify_signature(pub_key, message, signature);
    // println!("Signature valid: {}", is_valid);
}
