use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, Rem, Sub, SubAssign};
use hex_literal::hex;
use num::{BigInt, Num};
use num_bigint::RandBigInt;
use sha2::{Digest, Sha256};
use std::ops::Shr;
mod test_vectors;

// Inspired by toru3/modulo-n-tools
// https://gitlab.com/Toru3/modulo-n-tools/-/tree/master?ref_type=heads

// Define the elliptic curve parameters for P256
const N_STRING: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P_STRING: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const GX_STRING: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY_STRING: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const A_STRING: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const B_STRING: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";

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
pub fn add_mod<T: Debug + Clone>(a: &T, b: &T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T> + Rem<Output = T>,
    for<'x> &'x T: Add<Output = T>,
{
    let c = a + b; // Perform the addition
    c % modulo.clone()
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
pub fn sub_mod<T: Debug + Clone>(a: &T, b: &T, modulo: &T) -> T
where
    T: Ord + for<'x> AddAssign<&'x T> + for<'x> SubAssign<&'x T> + Rem<Output = T> + From<u8>,
    for<'x> &'x T: Add<Output = T> + Sub<Output = T>,
{
    if a >= b {
        let c = a - b;
        c % modulo.clone()
    } else {
        let temp = a + modulo;
        let c = sub_mod(&temp, &b, &modulo);
        c % modulo.clone()
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

    if xp.clone() == xq.clone() && yp.clone() == (yq.clone() * -BigInt::from(1u8)) {
        return (BigInt::ZERO, BigInt::ZERO);
    }

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
        if &n % 2 != BigInt::ZERO {
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
fn generate_private_key(order: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let priv_key = rng.gen_bigint_range(&BigInt::from(1u8), order);
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

/// Generates a random key within the specified range [1, n).
///
/// # Parameters
///
/// * `n`: A reference to the upper bound `BigInt`. The generated key will be in the range [1, `n`).
///
/// # Returns
///
/// A `BigInt` representing the generated random key.
///
/// # Examples
///
/// ```
/// use num_bigint::BigInt;
/// use crate::generate_random_key;
///
/// let n = BigInt::from(1000000u64);
/// let random_key = generate_random_key(&n);
/// println!("Generated random key: {:?}", random_key);
/// ```
fn generate_random_key(n: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let random_key = rng.gen_bigint_range(&BigInt::from(1u8), n);
    random_key
}

/// Calculates the proof for a digital signature using ECDSA.
///
/// # Parameters
///
/// * `k`: A reference to the random value `k`.
/// * `h`: A reference to the hashed message value `h`.
/// * `r`: A reference to the `r` value from the generated random point.
/// * `priv_key`: A reference to the private key `priv_key`.
/// * `modulo`: A reference to the modulus value `modulo`.
///
/// # Returns
///
/// A `BigInt` representing the calculated signature proof `s`.
///
/// # Panics
///
/// Panics if the multiplicative inverse of `k` does not exist.
///
/// # Examples
///
/// ```
/// use num_bigint::BigInt;
/// use crate::calculate_signature_proof;
///
/// let k = BigInt::from(123456);
/// let h = BigInt::from(78910);
/// let r = BigInt::from(111213);
/// let priv_key = BigInt::from(141516);
/// let modulo = BigInt::from(171819);
///
/// let s = calculate_signature_proof(&k, &h, &r, &priv_key, &modulo);
/// println!("Signature proof: {:?}", s);
/// ```
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

/// Generates a digital signature for a given message using ECDSA.
///
/// # Parameters
///
/// * `priv_key`: A reference to the private key `priv_key`.
/// * `message`: A reference to the message bytes to be signed.
/// * `n`: A reference to the order of the group `n`.
/// * `generator_point`: A reference to the generator point of the elliptic curve.
/// * `modulo`: A reference to the modulus value `modulo`.
/// * `a`: A reference to the elliptic curve parameter `a`.
///
/// # Returns
///
/// A tuple `(BigInt, BigInt)` representing the generated signature `(r, s)`.
///
/// # Examples
///
/// ```
/// use num_bigint::BigInt;
/// use crate::sign_message;
///
/// let priv_key = BigInt::from(141516);
/// let message = b"Hello, world!";
/// let n = BigInt::from(171819);
/// let generator_point = (BigInt::from(192021), BigInt::from(222324));
/// let modulo = BigInt::from(252627);
/// let a = BigInt::from(282930);
///
/// let (r, s) = sign_message(&priv_key, message, &n, &generator_point, &modulo, &a);
/// ```
fn sign_message(
    priv_key: &BigInt,
    message: &[u8],
    generator_point: &(BigInt, BigInt),
    order: &BigInt,
    modulo: &BigInt,
    a: &BigInt,
    k: Option<&BigInt>, // for testing purposes
) -> (BigInt, BigInt) {
    // Hash the message
    let mut sha256 = Sha256::new();
    sha256.update(message);
    let hash_string: String = format!("{:X}", sha256.finalize());
    let h: BigInt = BigInt::from_str_radix(&hash_string, 16).unwrap();

    loop {
        // Use the provided random key or generate a new one
        let k = match k {
            Some(key) => key.clone(),
            None => generate_random_key(order),
        };

        let (r, y) = scalar_mult(&k, generator_point, modulo, a);
        println!("Expected Point: ({:?}, {:?})", r, y);
        let s = calculate_signature_proof(&k, &h, &r, priv_key, order);

        if s != BigInt::ZERO {
            return (r, s);
        }
    }
}

/// Verifies a digital signature for a given message using ECDSA.
///
/// # Parameters
///
/// * `message`: A reference to the message bytes to be verified.
/// * `r`: A reference to the `r` value from the generated signature.
/// * `s`: A reference to the `s` value from the generated signature.
/// * `public_key`: A reference to the public key `(x, y)` tuple.
/// * `generator_point`: A reference to the generator point of the elliptic curve.
/// * `modulo`: A reference to the modulus value `modulo`.
/// * `a`: A reference to the elliptic curve parameter `a`.
///
/// # Returns
///
/// A `bool` indicating whether the signature is valid (`true`) or not (`false`).
///
/// # Examples
///
/// ```
/// use num_bigint::BigInt;
/// use crate::verify;
///
/// let message = b"Hello, world!";
/// let r = BigInt::from(123456);
/// let s = BigInt::from(78910);
/// let public_key = (BigInt::from(111213), BigInt::from(141516));
/// let generator_point = (BigInt::from(192021), BigInt::from(222324));
/// let modulo = BigInt::from(252627);
/// let a = BigInt::from(282930);
///
/// let is_valid = verify(
///     message,
///     &r,
///     &s,
///     &public_key,
///     &generator_point,
///     &modulo,
///     &a,
/// );
/// println!("Signature valid: {:?}", is_valid);
/// ```
fn verify(
    message: &[u8],
    r: &BigInt,
    s: &BigInt,
    public_key: &(BigInt, BigInt),
    generator_point: &(BigInt, BigInt),
    order: &BigInt,
    modulo: &BigInt,
    a: &BigInt,
) -> bool {
    // Hash the message
    let mut sha256 = Sha256::new();
    sha256.update(message);
    let hash_string: String = format!("{:X}", sha256.finalize());
    let h: BigInt = BigInt::from_str_radix(&hash_string, 16).unwrap();

    // Calculate s1 from s
    let s1 = inv_mod(s, order).expect("Multiplicative inverse does not exist!");

    let c1 = h.clone() * s1.clone();
    let point_1 = scalar_mult(&c1, generator_point, modulo, a); // (h * s1) * G

    let c2 = r.clone() * s1.clone();
    let point_2 = scalar_mult(&c2, public_key, modulo, a); // (r * s1) * pubKey

    let (r_prime_x, r_prime_y) = point_add(point_1, point_2, modulo.clone(), a.clone());

    println!("Verified Point: ({:?}, {:?})", r_prime_x, r_prime_y);
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
    let g = (gx.clone(), gy.clone());
    let public_key = generate_public_key(&priv_key, &g, &p, &a);
    println!("Public key: {:x?}", public_key);

    // Signing of message
    let message = hex!("21188c3edd5de088dacc1076b9e1bcecd79de1003c2414c3866173054dc82dde85169baa77993adb20c269f60a5226111828578bcc7c29e6e8d2dae81806152c8ba0c6ada1986a1983ebeec1473a73a04795b6319d48662d40881c1723a706f516fe75300f92408aa1dc6ae4288d2046f23c1aa2e54b7fb6448a0da922bd7f34");
    let (r, s) = sign_message(&priv_key, &message, &g, &n, &p, &a, None);
    println!("Signature (r, s): ({:?}, {:?})", r, s);

    // Signature verification
    let is_valid = verify(&message, &r, &s, &public_key, &g, &n, &p, &a);
    // Check if verify returns true
    assert!(is_valid);
    println!("Signature is valid!");
}

#[cfg(test)]
mod ecdsa_tests {
    use super::*;
    use crate::test_vectors::{get_test_vectors_k256, get_test_vectors_p256};
    use num::{BigInt, Num};

    // Define the elliptic curve parameters for p256
    const N_STRING: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const P_STRING: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    const GX_STRING: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const GY_STRING: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const A_STRING: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";

    #[test]
    fn public_key_test() {
        let p: BigInt = BigInt::from_str_radix(&P_STRING, 16).unwrap();
        let gx: BigInt = BigInt::from_str_radix(&GX_STRING, 16).unwrap();
        let gy: BigInt = BigInt::from_str_radix(&GY_STRING, 16).unwrap();
        let a: BigInt = BigInt::from_str_radix(&A_STRING, 16).unwrap();

        let g = (gx.clone(), gy.clone());
        for test_vector in get_test_vectors_p256() {
            let priv_key = BigInt::from_str_radix(&test_vector.priv_key, 16).unwrap();
            let (x, y) = generate_public_key(&priv_key, &g, &p, &a);
            let correct_x = BigInt::from_str_radix(&test_vector.qx, 16).unwrap();
            let correct_y = BigInt::from_str_radix(&test_vector.qy, 16).unwrap();

            assert_eq!(correct_x, x);
            assert_eq!(correct_y, y);
        }
    }

    #[test]
    fn signing_test() {
        let n: BigInt = BigInt::from_str_radix(&N_STRING, 16).unwrap();
        let p: BigInt = BigInt::from_str_radix(&P_STRING, 16).unwrap();
        let gx: BigInt = BigInt::from_str_radix(&GX_STRING, 16).unwrap();
        let gy: BigInt = BigInt::from_str_radix(&GY_STRING, 16).unwrap();
        let a: BigInt = BigInt::from_str_radix(&A_STRING, 16).unwrap();

        let g = (gx.clone(), gy.clone());
        for test_vector in get_test_vectors_p256() {
            let priv_key = BigInt::from_str_radix(&test_vector.priv_key, 16).unwrap();
            let k = BigInt::from_str_radix(&test_vector.k, 16).unwrap();
            let correct_r = BigInt::from_str_radix(&test_vector.r, 16).unwrap();
            let correct_s = BigInt::from_str_radix(&test_vector.s, 16).unwrap();
            let (r, s) = sign_message(&priv_key, &test_vector.message, &g, &n, &p, &a, Some(&k));

            assert_eq!(correct_r, r);
            assert_eq!(correct_s, s);
        }
    }

    #[test]
    fn verify_test() {
        let n: BigInt = BigInt::from_str_radix(&N_STRING, 16).unwrap();
        let p: BigInt = BigInt::from_str_radix(&P_STRING, 16).unwrap();
        let gx: BigInt = BigInt::from_str_radix(&GX_STRING, 16).unwrap();
        let gy: BigInt = BigInt::from_str_radix(&GY_STRING, 16).unwrap();
        let a: BigInt = BigInt::from_str_radix(&A_STRING, 16).unwrap();

        let g = (gx.clone(), gy.clone());
        for test_vector in get_test_vectors_p256() {
            let priv_key = BigInt::from_str_radix(&test_vector.priv_key, 16).unwrap();
            let public_key = generate_public_key(&priv_key, &g, &p, &a);
            let k = BigInt::from_str_radix(&test_vector.k, 16).unwrap();
            let (r, s) = sign_message(&priv_key, &test_vector.message, &g, &n, &p, &a, Some(&k));
            let is_valid = verify(&test_vector.message, &r, &s, &public_key, &g, &n, &p, &a);
            assert!(is_valid)
        }
    }
}
