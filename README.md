# ECDSA Verification Library

This repository contains a generic ECDSA (Elliptic Curve Digital Signature Algorithm) verification implementation. The library provides a simple and configurable verification mechanism based on constants defined for various types of elliptic curves. It is designed to be flexible and can be adapted to different elliptic curve parameters.

## Overview

ECDSA is a widely used digital signature algorithm that leverages the mathematical properties of elliptic curves to provide secure and efficient signing and verification of messages. This library focuses on the verification part of the ECDSA process, ensuring that given a message, a signature, and a public key, one can verify whether the signature is valid for the message under the specified elliptic curve parameters.

## Features

- **Generic Implementation**: The library is designed to work with different elliptic curves by configuring the relevant constants.
- **Modular Arithmetic**: Provides basic modular arithmetic operations such as addition, subtraction, multiplication, and exponentiation.
- **Field Operations**: Implements finite field arithmetic required for elliptic curve operations.
- **Curve Parameters**: Allows configuration of elliptic curve parameters to support various standard curves.

## Getting Started

To use this library, you need to configure the elliptic curve parameters specific to the curve you are working with. The library includes functions for modular arithmetic and finite field operations that form the basis of the ECDSA verification process.

### Example Usage

The code can be modified in **2 ways:**

#### Hashed Message

The message that is being signed can be modified to any value by changing the following line:

```rust
let message = hex!("21188c3edd5de088dacc1076b9e1bcecd79de1003c2414c3866173054dc82dde85169baa77993adb20c269f60a5226111828578bcc7c29e6e8d2dae81806152c8ba0c6ada1986a1983ebeec1473a73a04795b6319d48662d40881c1723a706f516fe75300f92408aa1dc6ae4288d2046f23c1aa2e54b7fb6448a0da922bd7f34");
```

#### Curve Parameters

The default curve is [NIST P256](https://neuromancer.sk/std/nist/P-256) but it can be modified to other Elliptic Curves by assigning the right parameters:

```rust
// Define the elliptic curve parameters for P256
const N_STRING: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P_STRING: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const GX_STRING: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY_STRING: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const A_STRING: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const B_STRING: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
```

### Example Usage

Below is a brief example of how you can use the library to verify an ECDSA signature.

```
cargo check
cargo run
```

If it all runs successfully, you should see something like this as the output

```
Public key: (4127457462906340257510389613670959715920692866556694645120227145166430128385, 102451142036970943007269727168535563406230363534717242446700625056386878926290)
Expected Point: (30518050761849371515869127986188711421511647131645324597541674329419534221332, 58978029870435833667630266593063453007282302808185461681444380738554668216981)
Signature (r, s): (30518050761849371515869127986188711421511647131645324597541674329419534221332, 96181282622080437831684686701751688609052917865903780341004326887700100365924)
Verified Point: (30518050761849371515869127986188711421511647131645324597541674329419534221332, 58978029870435833667630266593063453007282302808185461681444380738554668216981)
Signature is valid!
```

To run the loaded test vectors in `test_vectors.rs`

```
cargo test
```

If all tests passed, you should see the output

```
running 3 tests
test ecdsa_tests::public_key_test ... ok
test ecdsa_tests::signing_test ... ok
test ecdsa_tests::verify_test ... ok
```

## References

For more information on ECDSA and elliptic curve cryptography, refer to the following resources:

- [ECDSA](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages)
- [ECC](https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc#elliptic-curves)
- [NIST P256](https://neuromancer.sk/std/nist/P-256)
- [General Elliptic Curve calculator](https://andrea.corbellini.name/ecc/interactive/modk-add.html)
- [Modular Inverse Calculator](https://planetcalc.com/3311/)

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please create an issue or submit a pull request.
