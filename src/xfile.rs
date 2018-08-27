/*
 * Copyright 2018 Maya MacLean
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use super::*;
use std::fs::File;
use std::io::{prelude::*, SeekFrom};

pub fn _auth_file(input: &str, _hmac: &[u8], max_threads: usize, salt: &[u8], max_mem: usize) -> bool {
    let mut buffer: Vec<u8>   = vec![0u8; max_mem as usize];
    let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

    let mut inp  = File::open(input).expect("no open!");
    inp.seek(SeekFrom::Start(80)).expect("io err");

    let mut b = Builder::new();
    b.digest_length(64);
    b.key(&salt[0..64]);
    b.salt(&salt[64..80]);

    let mut hmac = b.build();
    let mut bytes_read    = 1;

    while bytes_read > 0 {
        bytes_read = inp.read(unsafe {&mut (*buf_ref)}).expect("read err");
        if bytes_read == 0 { break; }

        let buf_digest = buffer::_hash_buffer(buf_ref, max_threads, bytes_read as u64);
        hmac.update(&buf_digest.bytes[..]);
    }
    rust_sodium::utils::memzero(&mut buffer[..]);

    rust_sodium::utils::memcmp(&hmac.finalize().bytes[..], &_hmac[..])
}

pub fn decrypt_file(input: &str, output: &str, key: &xchacha20::Key, nonce: &xchacha20::Nonce,
               max_threads: usize, max_mem: usize, hmac: &[u8], salt: &[u8]) -> bool {

    if !_auth_file(input, hmac, max_threads, salt, max_mem) { print!("\nauth error!\n");return false; }

    let mut buffer: Vec<u8>   = vec![0u8; max_mem as usize];
    let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

    let mut inp  = File::open(input).expect("no open!");
    inp.seek(SeekFrom::Start(80)).expect("io err");
    let mut out  = File::create(output).expect("no write!");

    let mut current_iic = 0;
    let mut bytes_read  = 1;

    while bytes_read > 0 {
        bytes_read = inp.read(unsafe {&mut (*buf_ref)}).expect("read err");
        if bytes_read == 0 { break; }

        buffer::_decrypt(buf_ref, key, nonce, current_iic, max_threads, bytes_read as u64);
        out.write(&buffer[0..bytes_read]).expect("write err");

        current_iic += bytes_read as u64/64;
    }
    rust_sodium::utils::memzero(&mut buffer[..]);

    true
}

// salt should be 80 bytes
pub fn encrypt_file(input: &str, output: &str, key: &xchacha20::Key, nonce: &xchacha20::Nonce,
               max_threads: usize, max_mem: usize, salt: &[u8]) -> Vec<u8> {

    let mut buffer: Vec<u8>   = vec![0u8; max_mem];
    let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

    let mut inp  = File::open(input).expect("no open!");
    let mut out  = File::create(output).expect("no write!");
    out.write(&vec![0;80]).expect("io err");

    let mut current_iic = 0;

    let mut b = Builder::new();
    b.digest_length(64);
    b.key(&salt[0..64]);
    b.salt(&salt[64..80]);

    let mut hmac       = b.build();
    let mut bytes_read = 1;

    while bytes_read > 0 {
        bytes_read = inp.read(unsafe {&mut (*buf_ref)}).expect("read err");
        if bytes_read == 0 { break; }

        let buf_digest = buffer::_encrypt(buf_ref, key, nonce, current_iic, max_threads, bytes_read as u64);
        hmac.update(&buf_digest.bytes[..]);

        out.write(&buffer[0..bytes_read]).expect("write err");
        current_iic += bytes_read as u64/64;
    }
    rust_sodium::utils::memzero(&mut buffer[..]);

    hmac.finalize().bytes[..].to_vec()
}
