use crate::witness::{Instance, Solution};

type PublicKey = Instance;
type SecretKey = Solution;

pub trait SDitH {
    /// Generates public and private key.
    /// Returns true if the keypair was generated successfully.
    ///
    /// ### Arguments
    ///
    /// * `pk` - A mutable reference to a public key.
    /// * `sk` - A mutable reference to a secret key.
    fn crypto_sign_keypair(pk: &mut PublicKey, sk: &mut SecretKey) -> bool;

    /// Check the consistency of public and private keys.
    /// Returns true if the keys are consistent.
    ///
    /// ### Arguments
    ///
    /// * `pk` - A reference to a public key.
    /// * `sk` - A reference to a secret key.
    fn crypto_sign_valid_keys(pk: &PublicKey, sk: &SecretKey) -> bool;

    /// Computes signature.
    /// Returns true if the signature was computed successfully.
    ///
    /// ### Arguments
    /// * `sm` - pointer to output signed message (allocated
    ///                          array with CRYPTO_BYTES + mlen bytes),
    ///                          can be equal to m
    /// * `smlen` - pointer to output length of signed message
    /// * `m` - pointer to message to be signed
    /// * `mlen` - length of message
    /// * `sk` - pointer to bit-packed secret key

    fn crypto_sign_signature(
        sig: &mut [u8],
        siglen: &usize, // TODO is this necessary?
        m: &[u8],
        mlen: usize, // TODO is this necessary?
        sk: &SecretKey,
    ) -> bool;

    /// Compute signed message.
    /// Returns true if the signed message was computed successfully.
    ///
    /// ### Arguments
    /// * `sm` - pointer to output signed message (allocated
    ///                         array with CRYPTO_BYTES + mlen bytes),
    ///                        can be equal to m
    /// * `smlen` - pointer to output length of signed message
    /// * `m` - pointer to message to be signed
    /// * `mlen` - length of message
    /// * `sk` - pointer to bit-packed secret key
    fn crypto_sign(sm: &mut [u8], smlen: &usize, m: &[u8], mlen: usize, sk: &SecretKey) -> bool;

    /// Verifies signature.
    /// Returns true if the signature is valid.
    ///
    /// ### Arguments
    /// * `sig` - pointer to input signature
    /// * `siglen` - length of signature
    /// * `m` - pointer to message
    /// * `mlen` - length of message
    /// * `pk` - pointer to bit-packed public key
    fn crypto_sign_verify(sig: &[u8], siglen: usize, m: &[u8], mlen: usize, pk: &PublicKey)
        -> bool;

    /// Verify signed message.
    /// Returns true if the signed message is valid.
    ///
    /// ### Arguments
    /// * `m` - pointer to output message (allocated array with smlen bytes),
    ///                       can be equal to sm
    /// * `mlen` - pointer to output length of message
    /// * `sm` - pointer to signed message
    /// * `smlen` - length of signed message
    /// * `pk` - pointer to bit-packed public key
    fn crypto_sign_open(
        m: &mut [u8],
        mlen: &usize,
        sm: &[u8],
        smlen: usize,
        pk: &PublicKey,
    ) -> bool;
}
