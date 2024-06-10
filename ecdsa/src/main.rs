use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, Rem, Sub, SubAssign};
use hmac_sha256::Hash;
use num::{BigInt, Num};
use num_bigint::RandBigInt;
use std::ops::Shr;

// Inspired by toru3/modulo-n-tools
// https://gitlab.com/Toru3/modulo-n-tools/-/tree/master?ref_type=heads

// Define the elliptic curve parameters
const N_STRING: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P_STRING: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const GX_STRING: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY_STRING: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const A_STRING: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const B_STRING: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";

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
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T>,
{
    while &a >= modulo {
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
pub fn add_mod<T: Debug>(a: &T, b: &T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T>,
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
pub fn sub_mod<T: Debug>(a: &T, b: &T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T> + From<u8>,
    for<'x> &'x T: Add<Output = T> + Sub<Output = T>,
{
    if a >= b {
        let c = a - b;
        reduce(c, modulo)
    } else {
        let zero = T::from(0u8);
        let temp = add_mod(&a, &zero, &modulo);
        let c = sub_mod(&b, &temp, &modulo);
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
pub fn mul_mod<T: Debug>(a: &T, b: &T, modulo: &T) -> T
where
    for<'x> &'x T: Mul<Output = T> + Rem<Output = T>,
{
    &(a * b) % modulo
}

/// Computes the modular inverse of a given number modulo a specified modulus.
///
/// # Parameters
///
/// * `x`: A reference to the number for which the modular inverse is to be calculated.
/// * `p`: A reference to the modulus.
///
/// # Returns
///
/// An `Option<BigInt>` which is:
/// - `Some(BigInt)` if the inverse exists.
/// - `None` if the inverse does not exist.
///
/// # Panics
///
/// The function panics if either `x` or `p` is zero, as the modular inverse does not exist in these cases.
///
/// # Examples
///
/// ```
/// let x = BigInt::from(3u32);
/// let p = BigInt::from(11u32);
/// match inv_mod(&x, &p) {
///     Some(inv) => println!("The modular inverse is: {}", inv),
///     None => println!("No modular inverse exists."),
/// }
/// ```
fn inv_mod(x: &BigInt, p: &BigInt) -> Option<BigInt> {
    if *x == BigInt::ZERO || *p == BigInt::ZERO {
        panic!("Multiplicative inverse does not exist!"); // No inverse if x or p is zero
    }

    match x.modinv(p) {
        Some(inv) => Some(inv),
        None => None, // No inverse if modinv returns None
    }
}

/// Adds two points on an elliptic curve.
///
/// # Parameters
///
/// * `p`: The first point (x1, y1) represented as a tuple of BigInt.
/// * `q`: The second point (x2, y2) represented as a tuple of BigInt.
/// * `modulo`: The prime modulus of the field.
/// * `a`: The constant `a` that defines the elliptic curve.
///
/// # Returns
///
/// The resulting point (x3, y3) after addition.
fn point_add(
    p: (BigInt, BigInt),
    q: (BigInt, BigInt),
    modulo: BigInt,
    a: BigInt,
) -> (BigInt, BigInt) {
    // Unpack the coordinates
    let (ref xp, ref yp) = p;
    let (ref xq, ref yq) = q;

    // Check if either point is the point at infinity
    if *xp == BigInt::ZERO && *yp == BigInt::ZERO {
        return q;
    }
    if *xq == BigInt::ZERO && *yq == BigInt::ZERO {
        return p;
    }

    let lambda;
    // Check if both points are the same
    if *xp == *xq && *yp == *yq {
        // Point doubling case
        lambda = lambda_point_doubling(xp, yp, &modulo, &a);
    } else {
        // General case
        lambda = lambda_point_adding(xp, yp, xq, yq, &modulo);
    }
    // Compute the slope lambda = (yq - yp) / (xq - xp) mod p
    let lambda_square = lambda.modpow(&BigInt::from(2u32), &modulo);

    // Get (xr, yr)
    let mut temp = sub_mod(&lambda_square, &xp, &modulo);
    let xr = sub_mod(&temp, &xq, &modulo);
    temp = sub_mod(&xp, &xr, &modulo);
    temp = mul_mod(&lambda, &temp, &modulo);
    let yr = sub_mod(&temp, &yp, &modulo);

    return (xr, yr);
}

/// Computes the slope (lambda) for adding two distinct points on an elliptic curve. It is used when adding two distinct points `P` and `Q` on the curve.
///
/// # Parameters
///
/// * `xp`: A reference to the x-coordinate of point `P`.
/// * `yp`: A reference to the y-coordinate of point `P`.
/// * `xq`: A reference to the x-coordinate of point `Q`.
/// * `yq`: A reference to the y-coordinate of point `Q`.
/// * `modulo`: A reference to the modulus value `p`.
///
/// # Returns
///
/// A `BigInt` representing the slope `lambda`.
///
/// # Examples
///
/// ```
/// let xp = BigInt::from(2u32);
/// let yp = BigInt::from(3u32);
/// let xq = BigInt::from(5u32);
/// let yq = BigInt::from(7u32);
/// let modulo = BigInt::from(11u32);
///
/// let lambda = lambda_point_adding(&xp, &yp, &xq, &yq, &modulo);
/// ```
fn lambda_point_adding(
    xp: &BigInt,
    yp: &BigInt,
    xq: &BigInt,
    yq: &BigInt,
    modulo: &BigInt,
) -> BigInt {
    // Compute the slope lambda = (yq - yp) / (xq - xp) mod p
    let numerator = sub_mod(yq, yp, modulo);
    let denominator = sub_mod(xq, xp, modulo);

    // Get the inverse of denominator
    let denominator_inv =
        inv_mod(&denominator, modulo).expect("Multiplicative inverse does not exist!");

    let lambda = mul_mod(&numerator, &denominator_inv, modulo);
    lambda
}

/// Computes the slope (lambda) for doubling a point on an elliptic curve.
/// It is used when doubling a point `P` on the curve.
///
/// # Parameters
///
/// * `xp`: A reference to the x-coordinate of point `P`.
/// * `yp`: A reference to the y-coordinate of point `P`.
/// * `modulo`: A reference to the modulus value `p`.
/// * `a`: A reference to the curve parameter `a`.
///
/// # Returns
///
/// A `BigInt` representing the slope `lambda`.
///
/// # Examples
///
/// ```
/// let xp = BigInt::from(2u32);
/// let yp = BigInt::from(3u32);
/// let modulo = BigInt::from(11u32);
/// let a = BigInt::from(1u32);
///
/// let lambda = lambda_point_doubling(&xp, &yp, &modulo, &a);
/// ```
fn lambda_point_doubling(xp: &BigInt, yp: &BigInt, modulo: &BigInt, a: &BigInt) -> BigInt {
    let xp_square = xp.modpow(&BigInt::from(2u32), modulo);
    let temp = mul_mod(&BigInt::from(3u32), &xp_square, modulo);
    let numerator = add_mod(&temp, a, modulo);
    let denominator = mul_mod(&BigInt::from(2u32), yp, modulo);
    let denominator_inv =
        inv_mod(&denominator, modulo).expect("Multiplicative inverse does not exist!");
    let lambda = mul_mod(&numerator, &denominator_inv, modulo);
    lambda
}

/// Performs scalar multiplication on an elliptic curve.
/// It uses the double-and-add algorithm to efficiently compute the result.
///
/// # Parameters
///
/// * `k`: A reference to the scalar value.
/// * `p`: A reference to the point `P` represented as a tuple `(x, y)`.
/// * `modulo`: A reference to the modulus value `p`.
/// * `a`: A reference to the curve parameter `a`.
///
/// # Returns
///
/// A tuple `(x, y)` representing the resulting point on the elliptic curve.
///
/// # Examples
///
/// ```
/// let k = BigInt::from(3u32);
/// let p = (BigInt::from(2u32), BigInt::from(3u32));
/// let modulo = BigInt::from(11u32);
/// let a = BigInt::from(1u32);
///
/// let result = scalar_mult(&k, &p, &modulo, &a);
/// ```
fn scalar_mult(k: &BigInt, p: &(BigInt, BigInt), modulo: &BigInt, a: &BigInt) -> (BigInt, BigInt) {
    let mut n = k.clone();
    let mut q = (BigInt::ZERO, BigInt::ZERO); // Point at infinity
    let mut r = p.clone(); // Current point

    while n > BigInt::ZERO {
        if &n & BigInt::from(1u32) == BigInt::from(1u32) {
            q = point_add(q, r.clone(), modulo.clone(), a.clone());
        }
        r = point_add(r.clone(), r.clone(), modulo.clone(), a.clone());
        n = n.shr(1);
    }

    q
}

/// Generates a private key for elliptic curve cryptography.
///
/// # Parameters
///
/// * `N`: The upper bound (exclusive) for the private key. This is typically the order of the curve
/// or the field size.
///
/// # Returns
///
/// A `BigInt` representing the private key.
///
/// # Examples
///
/// ```
/// use num_bigint::BigInt;
/// use crate::generate_private_key;
///
/// let n = BigInt::from(0xffffffff00000001u64);
/// let private_key = generate_private_key(&n);
/// println!("Private Key: {}", private_key);
/// ```
fn generate_private_key(n: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let priv_key = rng.gen_bigint_range(&BigInt::ZERO, n);
    priv_key
}

/// Generates a public key for elliptic curve cryptography based on a given private key.
///
/// # Parameters
///
/// * `priv_key`: A reference to the private key, which is a `BigInt`.
/// * `generator_point`: A reference to a tuple representing the generator point (Gx, Gy) on the elliptic curve.
/// * `modulo`: A reference to the modulo `p` defining the finite field for the elliptic curve.
/// * `a`: A reference to the curve parameter `a` in the elliptic curve equation `y^2 = x^3 + ax + b`.
///
/// # Returns
///
/// A tuple `(BigInt, BigInt)` representing the public key, which is the point (Px, Py) on the elliptic curve.
///
/// # Examples
///
/// ```
/// let priv_key = BigInt::from(1234567890u64);
/// let generator_point = (BigInt::from(4u64), BigInt::from(20u64)); // Example generator point
/// let modulo = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
/// let a = BigInt::from(0u64); // For secp256k1 curve
///
/// let public_key = generate_public_key(&priv_key, &generator_point, &modulo, &a);
/// ```
fn generate_public_key(
    priv_key: &BigInt,
    generator_point: &(BigInt, BigInt),
    modulo: &BigInt,
    a: &BigInt,
) -> (BigInt, BigInt) {
    scalar_mult(priv_key, generator_point, modulo, a)
}

fn generate_random_key(n: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let random_key = rng.gen_bigint_range(&BigInt::ZERO, n);
    random_key
}

fn calculate_signature_proof(
    k: &BigInt,
    h: &BigInt,
    r: &BigInt,
    priv_key: &BigInt,
    modulo: &BigInt,
) -> BigInt {
    let k_inv = inv_mod(k, modulo).expect("Multiplicative inverse does not exist!");
    let mut temp = mul_mod(r, priv_key, modulo);
    temp = add_mod(h, &temp, modulo);
    let s = mul_mod(&k_inv, &temp, modulo);
    s
}

// Signature generation
fn sign_message(
    priv_key: &BigInt,
    message: &[u8],
    n: &BigInt,
    generator_point: &(BigInt, BigInt),
    modulo: &BigInt,
    a: &BigInt,
) -> (BigInt, BigInt) {
    let hash = Hash::hash(message);
    let h = BigInt::from_signed_bytes_be(&hash);
    let k = generate_random_key(n);
    let (r, _y) = scalar_mult(&k, generator_point, modulo, a);
    let s = calculate_signature_proof(&k, &h, &r, priv_key, modulo);
    (r, s)
}

// Signature verification
fn verify(
    message: &[u8],
    r: &BigInt,
    s: &BigInt,
    public_key: &(BigInt, BigInt),
    generator_point: &(BigInt, BigInt),
    modulo: &BigInt,
    a: &BigInt,
) -> bool {
    let hash = Hash::hash(message);
    let h = BigInt::from_signed_bytes_be(&hash);
    let s1 = inv_mod(s, modulo).expect("Multiplicative inverse does not exist!");
    let mut temp = mul_mod(&h, &s1, modulo);
    let point_1 = scalar_mult(&temp, generator_point, modulo, a);
    temp = mul_mod(&r, &s1, modulo);
    let point_2 = scalar_mult(&temp, public_key, modulo, a);
    let (r_prime_x, _r_prime_y) = point_add(point_1, point_2, modulo.clone(), a.clone());
    println!("r_prime_x: {:?}", r_prime_x);
    assert_eq!(r_prime_x, r.clone());
    r_prime_x == *r
}

fn main() {
    let n: BigInt = BigInt::from_str_radix(&N_STRING, 16).unwrap();
    let p: BigInt = BigInt::from_str_radix(&P_STRING, 16).unwrap();
    let gx: BigInt = BigInt::from_str_radix(&GX_STRING, 16).unwrap();
    let gy: BigInt = BigInt::from_str_radix(&GY_STRING, 16).unwrap();
    let a: BigInt = BigInt::from_str_radix(&A_STRING, 16).unwrap();
    let _b: BigInt = BigInt::from_str_radix(&B_STRING, 16).unwrap();

    // Key generation
    let priv_key = generate_private_key(&n);
    println!("Private key: {:x?}", priv_key);

    let g = (gx.clone(), gy.clone());
    let public_key = generate_public_key(&priv_key, &g, &p, &a);
    println!("Public key: {:x?}", public_key);

    // Signing of message
    let message = b"Hello World";
    let (r, s) = sign_message(&priv_key, message, &n, &g, &p, &a);
    println!("r: {:?}", r);
    println!("s: {:?}", s);

    // Signature verification
    let is_valid = verify(message, &r, &s, &public_key, &g, &p, &a);
    // Check if verify returns true
    assert!(is_valid)
}
