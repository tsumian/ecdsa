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

Below is a brief example of how you can use the library to verify an ECDSA signature.

```rust
// Still in progress
```

## References
For more information on ECDSA and elliptic curve cryptography, refer to the following resources:
- [ECDSA](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages)
- [ECC](https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc#elliptic-curves)

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please create an issue or submit a pull request.