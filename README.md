sodium_stream is a rust_sodium/blake2_c-based collection of file encryption,
authentication, and decryption functions. it uses xchacha20 for encryption and
decryption and blake2b to hash files and generate a keyed hmac.

so far, my focus has been on creating a set of fast, resource-scalable functions.
current development focus is on implementing argon2 for key derivation and a
scheme for asymmetric key management, as well as creating a user interface of
some kind.
