//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be broken
//! up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_ it
//! is not secure and make the point that the most straight-forward approach isn't always the best, and
//! can sometimes be trivially broken.


use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
	// Create a random key of [u8; 16]
	let key: [u8; 16] = rand::thread_rng().gen();


	// Plaintext is "Polkadot Blockchain Academy", converted to Vec<u8
	let plaintext = "Polkadot Blockchain Academy";
	let plaintext = plaintext.as_bytes();

	println!("ECB MODE");

	// Encrypt the plaintext.
  let ciphertext=	ecb_encrypt(plaintext.to_vec(), key);


	println!("Ciphertext: {:?}", ciphertext);
	println!("Key: {:?}", key);

	println!("Plaintext: {:?}", plaintext);


	// Decrypt the ciphertext.
	let decrypted_plaintext = ecb_decrypt(ciphertext, key);
	println!("Decrypted plaintext: {:?}", decrypted_plaintext);

	// Check that the decrypted plaintext matches the original plaintext.
	assert_eq!(decrypted_plaintext, plaintext);


	println!("========================================================");

	println!("CBC MODE");

	// Create a random key of [u8; 16]
	let key: [u8; 16] = rand::thread_rng().gen();
	// generate salt
	let salt: [u8; 16] = rand::thread_rng().gen();


	// Plaintext is "Polkadot Blockchain Academy", converted to Vec<u8>
	let plaintext = "Polkadot Blockchain Academy";
	let plaintext = plaintext.as_bytes();

	// Encrypt the plaintext.
	let ciphertext = cbc_encrypt(plaintext.to_vec(), key, salt);
	println!("Ciphertext: {:?}", ciphertext);
	println!("Key: {:?}", key);

	println!("Plaintext: {:?}", plaintext);

	// Decrypt the ciphertext.
	let decrypted_plaintext = cbc_decrypt(ciphertext, key, salt);
	println!("Decrypted plaintext: {:?}", decrypted_plaintext);

	// Check that the decrypted plaintext matches the original plaintext.
	assert_eq!(decrypted_plaintext, plaintext);
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;
	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
	let mut data = Vec::new();
	for block in blocks {
		data.extend_from_slice(&block);
	}

	data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<[u8; 16]>) -> Vec<u8> {
	let mut data = un_group(data);

	let number_pad_bytes = data.pop().unwrap();
	data.truncate(data.len() - number_pad_bytes as usize + 1);

	data
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
	let mut cipher_text = Vec::new();
	for block in group(pad(plain_text)) {
		cipher_text.extend_from_slice(&aes_encrypt(block, &key));
	}

	cipher_text
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let mut plain_text = Vec::new();
	for block in group(cipher_text) {
		plain_text.extend_from_slice([aes_decrypt(block, &key)].as_slice());
	}

	un_pad(plain_text)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE], salt: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let mut cipher_text = Vec::new();
	let mut previous_block: [u8; BLOCK_SIZE] = Default::default();
	previous_block.copy_from_slice(&salt);
	for block in group(pad(plain_text)) {
		let mut block = block;
		for i in 0..BLOCK_SIZE {
			block[i] ^= previous_block[i];
		}
		cipher_text.extend_from_slice(&aes_encrypt(block, &key));
		previous_block.copy_from_slice(&cipher_text[cipher_text.len() - BLOCK_SIZE..]);
	}

	cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE], salt: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let mut plain_text = Vec::new();
	let mut previous_block: [u8; BLOCK_SIZE] = Default::default();
	previous_block.copy_from_slice(&salt);
	for block in group(cipher_text) {
		let block = block;
		let mut decrypted_block = aes_decrypt(block, &key);
		for i in 0..BLOCK_SIZE {
			decrypted_block[i] ^= previous_block[i];
		}
		plain_text.extend_from_slice([decrypted_block].as_slice());
		previous_block.copy_from_slice(&block);
	}


	un_pad(plain_text)
}
