extern crate crypto;

use crypto::aes::{self, KeySize};
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::Encryptor;

fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = crypto::randombytes::randombytes(16); // Generate a random initialization vector (IV)

    let mut encryptor = aes::cbc_encryptor(
        KeySize::KeySize256,
        key,
        &iv,
        PkcsPadding,
    ); // Create an AES cipher object with a 256-bit key and CBC mode

    let mut ciphertext = vec![0; plaintext.len() + aes::BLOCK_SIZE]; // Allocate a buffer for the ciphertext
    let mut output = RefWriteBuffer::new(&mut ciphertext);

    let mut input = RefReadBuffer::new(plaintext);
    loop {
        let result = encryptor.encrypt(&mut input, &mut output, true);
        match result {
            Ok(BufferResult::BufferUnderflow) => break, // Encryption complete
            Ok(BufferResult::BufferOverflow) => (),
            Err(_) => panic!("Encryption error"),
        }
    }

    ciphertext.truncate(output.position()); // Remove any padding bytes
    let mut result = Vec::new();
    result.extend_from_slice(&iv); // Prepend the IV to the ciphertext
    result.extend_from_slice(&ciphertext);

    result // Return the result as a vector of bytes
}

fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &ciphertext[0..16]; // Extract the IV from the ciphertext
    let ciphertext = &ciphertext[16..]; // Extract the actual ciphertext

    let mut decryptor = aes::cbc_decryptor(
        KeySize::KeySize256,
        key,
        iv,
        PkcsPadding,
    ); // Create an AES cipher object with the key and IV

    let mut plaintext = vec![0; ciphertext.len() + aes::BLOCK_SIZE]; // Allocate a buffer for the plaintext
    let mut output = RefWriteBuffer::new(&mut plaintext);

    let mut input = RefReadBuffer::new(ciphertext);
    loop {
        let result = decryptor.decrypt(&mut input, &mut output, true);
        match result {
            Ok(BufferResult::BufferUnderflow) => break, // Decryption complete
            Ok(BufferResult::BufferOverflow) => (),
            Err(_) => panic!("Decryption error"),
        }
    }

    plaintext.truncate(output.position()); // Remove any padding bytes
    plaintext // Return the plaintext as a vector of bytes
}

fn main() {
    let key = crypto::randombytes::randombytes(32); // Generate a random 256-bit key
    let plaintext = b"Hello, world!";

    let ciphertext = encrypt(plaintext, &key);
    let decrypted_plaintext = decrypt(&ciphertext, &key);

    assert_eq!(plaintext.to_vec(), decrypted_plaintext);
}
