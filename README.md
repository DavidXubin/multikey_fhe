# multi-key fhe bases on ckks

Welcome to our code repository! The code you'll find here is related to our paper, "Share to Gain: Collaborative Learning with Dynamic Membership via Multi-Key Homomorphic Encryption", submitted to Scientific Reports. Our primary focus is on implementing a logistic regression algorithm based on Multi-Key Homomorphic Encryption (MK-HE).

## LR

This repository contains an implementation of our proposed logistic regression algorithm based on MK-HE. We use various functions implemented in MKCKKS for parameter setting and basic operations like addition, multiplication, rotation, etc.

## MKCKKS

MKCKKS (Multi-Key CKKS) repository includes several functionalities such as:

- decryptor: Contains functions for creating decryptors and carrying out decryption processes, including partial decryption and merge.
- elements: Contains details on the scaling factor affecting ciphertext slot numbers and data precision.
- encryptor: Offers functions for creating encryptors, and various methods related to encoding and encryption.
- evaluator: Implements functions for ciphertext operations like addition, multiplication, and rotation.
- keys: Provides the structure and creation functions for secret and public keys used in encryption and evaluation.
- mkckks_bencmark_test / mkckks_test: Contains files for testing and benchmarking various functions supported by mkckks.
- params: Sets parameters required for mkckks initialization.
- utils: Implements basic functions used in implementing functions supported by mkckks.

The mentioned functionalities are transformations of MKRLWE functions made to match the CKKS scheme.

## MKRLWE

Files with the same names as those in MKCKKS have similar functionalities. Due to RLWE (Ring learning with errors) being used in schemes other than CKKS, they provide features in a slightly more generalized form.

- basis_extension: Implements functions required when changing the modulus in the ring structure by transforming the basis that constructs the modulus.
- key_switch: Provides functionality required for the technique 'key switching,' which is necessary in maintaining the canonical form of the ciphertext in the HE when conducting operations like multiplication/rotation, and switches a ciphertext encrypted with s' back to a form encrypted with s.
- key_switch_hoisted: Implements 'hoisted' key switching, a more efficient technique when carrying out key switching multiple times on the same ciphertexts.

Feel free to test and explore our repository.


