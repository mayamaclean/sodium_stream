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
 *
 * TODO: * key management
 *       * write cli and further testing
 */
extern crate rust_sodium;
extern crate blake2_c;

use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::sync::mpsc::{Sender, Receiver, channel};
use blake2_c::{blake2b::{Builder, State}, Digest};
use std::thread;
use rust_sodium::crypto::stream::xchacha20;
use std::io::prelude::*;
use std::fs::File;
use std::time;

pub fn decrypt_file(input: &str, output: &str, key: &xchacha20::Key, nonce: &xchacha20::Nonce,
               max_threads: usize, hmac: Digest, max_mem: usize, salt: &[u8]) -> bool {

    let mut timer = time::Instant::now();
    if !_auth_file(input, hmac, max_threads as u64, salt, max_mem) { return false; }
    println!("atime: {:?}", timer.elapsed());
    timer = time::Instant::now();

    let mut buffer: Vec<u8>   = vec![0u8; max_mem as usize];
    let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

    let mut inp  = File::open(input).expect("no open!");
    let mut out  = File::create(output).expect("no write!");

    let mut current_iic = 0;
    let mut bytes_read  = 1;

    while bytes_read > 0 {
        bytes_read = inp.read(unsafe {&mut (*buf_ref)}).expect("read err");
        if bytes_read == 0 { break; }

        _decrypt(buf_ref, key, nonce, current_iic, max_threads, bytes_read as u64);
        out.write(&buffer[0..bytes_read]).expect("write err");

        current_iic += bytes_read as u64/64;
    }
    println!("dtime: {:?}", timer.elapsed());
    rust_sodium::utils::memzero(&mut buffer[..]);

    true
}

pub fn _auth_file(input: &str, _hmac: Digest, max_threads: u64, salt: &[u8], max_mem: usize) -> bool {
    let mut buffer: Vec<u8>   = vec![0u8; max_mem as usize];
    let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

    let mut inp  = File::open(input).expect("no open!");

    let mut b = Builder::new();
    b.digest_length(64);
    b.key(&salt[0..64]);
    b.salt(&salt[64..80]);
    b.personal(&salt[80..96]);

    let mut hmac = b.build();
    let mut bytes_read    = 1;

    while bytes_read > 0 {
        bytes_read = inp.read(unsafe {&mut (*buf_ref)}).expect("read err");
        if bytes_read == 0 { break; }

        let buf_digest = _hash_buffer(buf_ref, max_threads as usize, bytes_read as u64);
        hmac.update(&buf_digest.bytes[..]);
    }
    rust_sodium::utils::memzero(&mut buffer[..]);

    rust_sodium::utils::memcmp(&hmac.finalize().bytes[..], &_hmac.bytes[..])
}

// salt should be 96 bytes
pub fn encrypt_file(input: &str, output: &str, key: &xchacha20::Key, nonce: &xchacha20::Nonce,
               max_threads: usize, max_mem: u64, salt: &[u8]) -> Digest {

    let mut buffer: Vec<u8>   = vec![0u8; max_mem as usize];
    let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

    let mut inp  = File::open(input).expect("no open!");
    let mut out  = File::create(output).expect("no write!");

    let mut current_iic = 0;

    let mut b = Builder::new();
    b.digest_length(64);
    b.key(&salt[0..64]);
    b.salt(&salt[64..80]);
    b.personal(&salt[80..96]);

    let mut hmac       = b.build();
    let mut bytes_read = 1;

    while bytes_read > 0 {
        bytes_read = inp.read(unsafe {&mut (*buf_ref)}).expect("read err");
        if bytes_read == 0 { break; }

        let buf_digest = _encrypt(buf_ref, key, nonce, current_iic, max_threads, bytes_read as u64);
        hmac.update(&buf_digest.bytes[..]);

        out.write(&buffer[0..bytes_read]).expect("write err");
        current_iic += bytes_read as u64/64;
    }
    rust_sodium::utils::memzero(&mut buffer[..]);

    hmac.finalize()
}

pub fn _decrypt(_buffer: *mut Vec<u8>, key: &xchacha20::Key, nonce: &xchacha20::Nonce,
                initial_ic: u64, max_threads: usize, bytes_read: u64) {

    let mut bytes_to_go    = bytes_read;
    let threads_needed     = if (bytes_read/1024*1024) + 1 <= max_threads as u64 {
                                (bytes_read/1024*1024) + 1
                            } else {
                                max_threads as u64
                            };
    let mut local_ic    = initial_ic;
    let mut chunk_start = 0;

    let (p_tx, p_rx): (Sender<u8>, Receiver<u8>) = channel();

    let local_count       = Arc::new(AtomicUsize::new(0));
    let mut total_threads = 0;

    while bytes_to_go > 0 {
        for _ in 0..threads_needed {
            let mut buffer         = unsafe { &mut *_buffer };
            let mut thread_comm    = p_tx.clone();
            let mut chunk_len      = if bytes_to_go > 1024*1024 {
                                        1024*1024 }
                                     else {
                                        bytes_to_go };
            bytes_to_go -= chunk_len;

            let key_copy  = key.clone();
            let non_copy  = nonce.clone();
            let mut chunk = buffer.get_mut(chunk_start as usize..(chunk_start + chunk_len) as usize).expect("chunking error");

            chunk_start += chunk_len;

            let mut work_tracker = Arc::clone(&local_count);

            loop { if local_count.load(Ordering::Relaxed) < max_threads { break; }
        /*println!("waiting for other threads before spawning thread #{}", total_threads);*/ }

            thread::spawn(move || {
                work_tracker.fetch_add(1, Ordering::Relaxed);

                xchacha20::stream_xor_ic_inplace(chunk, &non_copy, local_ic, &key_copy);
                thread_comm.send(0).expect("thread comm error");

                work_tracker.fetch_sub(1, Ordering::Relaxed);
            });
            local_ic      += chunk_len/64;
            total_threads += 1;

            if bytes_to_go == 0 { break; }
        }
    }
    for _ in 0..total_threads { p_rx.recv().expect("threading error"); }
    loop { if local_count.load(Ordering::Relaxed) == 0 { break; } }
}

pub fn _hash_buffer(_buffer: *mut Vec<u8>, max_threads: usize, bytes_read: u64) -> Digest {
    let mut bytes_to_go    = bytes_read;
    let threads_needed     = if (bytes_read/1024*1024) + 1 <= max_threads as u64 {
                                (bytes_read/1024*1024) + 1
                            } else {
                                max_threads as u64
                            };
    let mut chunk_start = 0;

    let (p_tx, p_rx): (Sender<(u64,Digest)>, Receiver<(u64,Digest)>) = channel();

    let mut hashes: HashMap<u64, Digest> = HashMap::with_capacity(128);

    let local_count       = Arc::new(AtomicUsize::new(0));
    let mut total_threads = 0;

    while bytes_to_go > 0 {
        for _ in 0..threads_needed {
            let mut buffer         = unsafe { &mut *_buffer };
            let mut thread_comm    = p_tx.clone();
            let mut chunk_len      = if bytes_to_go > 1024*1024 {
                                        1024*1024 }
                                     else {
                                        bytes_to_go };
            bytes_to_go -= chunk_len;

            let mut chunk = buffer.get_mut(chunk_start as usize..(chunk_start + chunk_len) as usize).expect("chunking error");

            chunk_start += chunk_len;

            let mut work_tracker = Arc::clone(&local_count);

            loop { if local_count.load(Ordering::Relaxed) < max_threads { break; }
        /*println!("waiting for other threads before spawning thread #{}", total_threads);*/ }

            thread::spawn(move || {
                work_tracker.fetch_add(1, Ordering::Relaxed);

                let chunk_hash = blake2_c::blake2b_512(chunk);
                thread_comm.send((total_threads, chunk_hash)).expect("thread comm error");

                work_tracker.fetch_sub(1, Ordering::Relaxed);
            });
            total_threads += 1;

            if bytes_to_go == 0 { break; }
        }
    }
    for _ in 0..total_threads {
        let message = p_rx.recv().expect("digest error");
        hashes.insert(message.0, message.1);
    }

    let mut buff_hash = State::new(64);
    for h in 0..total_threads {
        buff_hash.update(&hashes.get(&h).expect("hash error").bytes[..]);
    }
    let fhash = buff_hash.finalize();
    loop { if local_count.load(Ordering::Relaxed) == 0 { break; } }

    fhash
}

pub fn _encrypt(_buffer: *mut Vec<u8>, key: &xchacha20::Key,
                nonce: &xchacha20::Nonce, initial_ic: u64,
                max_threads: usize, bytes_read: u64) -> Digest {

    let mut bytes_to_go    = bytes_read;
    let threads_needed     = if (bytes_read/1024*1024) + 1 <= max_threads as u64 {
                                (bytes_read/1024*1024) + 1
                            } else {
                                max_threads as u64
                            };
    let mut local_ic    = initial_ic;
    let mut chunk_start = 0;

    let (p_tx, p_rx): (Sender<(u64,Digest)>, Receiver<(u64,Digest)>) = channel();

    let mut hashes: HashMap<u64, Digest> = HashMap::new();

    let local_count       = Arc::new(AtomicUsize::new(0));
    let mut total_threads = 0;

    while bytes_to_go > 0 {
        for _ in 0..threads_needed {
            let mut buffer         = unsafe { &mut *_buffer };
            let mut thread_comm    = p_tx.clone();
            let mut chunk_len      = if bytes_to_go > 1024*1024 {
                                        1024*1024 }
                                     else {
                                        bytes_to_go };
            bytes_to_go -= chunk_len;

            let key_copy  = key.clone();
            let non_copy  = nonce.clone();
            let mut chunk = buffer.get_mut(chunk_start as usize..(chunk_start + chunk_len) as usize).expect("chunking error");

            chunk_start += chunk_len;

            let mut work_tracker = Arc::clone(&local_count);

            loop { if local_count.load(Ordering::Relaxed) < max_threads { break; }
        /*println!("waiting for other threads before spawning thread #{}", total_threads);*/ }

            thread::spawn(move || {
                work_tracker.fetch_add(1, Ordering::Relaxed);

                xchacha20::stream_xor_ic_inplace(chunk, &non_copy, local_ic, &key_copy);
                let chunk_hash = blake2_c::blake2b_512(chunk);
                thread_comm.send((total_threads, chunk_hash)).expect("thread comm error");

                work_tracker.fetch_sub(1, Ordering::Relaxed);
            });
            local_ic      += chunk_len/64;
            total_threads += 1;

            if bytes_to_go == 0 { break; }
        }
    }
    for _ in 0..total_threads {
        let message = p_rx.recv().expect("digest error");
        hashes.insert(message.0, message.1);
    }

    let mut buff_hash = State::new(64);
    for h in 0..total_threads {
        buff_hash.update(&hashes.get(&h).expect("hash error").bytes[..]);
    }
    let fhash = buff_hash.finalize();
    loop { if local_count.load(Ordering::Relaxed) == 0 { break; } }
    
    fhash
}

#[cfg(test)]
mod tests
{
    use super::*;

    // 1 MB per thread or 4 MB per thread seem to be optimal
    const TMAX: usize  = 4;
    const KB:   usize  = 1024;
    const MB:   usize  = KB*1024;
    const MEM:   usize = 16;
    const MAX:   usize = MB*MEM;

    const MUDD: &str   = "../mudd.avi";
    const MUDC: &str   = "../mudd.bin";
    const DMUD: &str   = "../mudd-d.avi";
    const MSG1: &str   = "./message1.txt";
    const MS1C: &str   = "./message1.bin";
    const MS1D: &str   = "./message1d.txt";
    const MSG2: &str   = "./message2.txt";
    const MS2C: &str   = "./message2.bin";
    const MS2D: &str   = "./message2d.txt";

    #[test]
    fn test_en_auth_de_file() {
        rust_sodium::init().expect("sodium err");

        let test_key:   xchacha20::Key   = xchacha20::Key::from_slice(&[77, 98, 63, 124, 210, 234, 125, 221, 18, 168, 172, 173, 251, 202, 155, 47, 78, 127, 248, 155, 39, 25, 21, 255, 231, 29, 226, 235, 6, 255, 17, 74][..]).unwrap();
        let test_nonce: xchacha20::Nonce = xchacha20::Nonce::from_slice(&[38, 143, 150, 82, 213, 128, 30, 251, 149, 133, 127, 208, 159, 175, 41, 107, 93, 32, 206, 72, 77, 72, 105, 245][..]).unwrap();
        let test_salt: Vec<u8> = vec![0u8; 96];

        let mut timer = time::Instant::now();
        let hash_one  = encrypt_file(MUDD, MUDC, &test_key, &test_nonce, TMAX, MAX as u64, &test_salt[..]);
        println!("\n*****\netime1: {:?}", timer.elapsed());

        let mut decrypted = decrypt_file(MUDC, DMUD, &test_key, &test_nonce, TMAX, hash_one, MAX, &test_salt[..]);
        println!("ttime1: {:?}", timer.elapsed());
        assert_eq!(decrypted, true);

        timer        = time::Instant::now();
        let hash_two = encrypt_file(MSG1, MS1C, &test_key, &test_nonce, TMAX, MAX as u64, &test_salt[..]);
        println!("\netime2: {:?}", timer.elapsed());

        decrypted = decrypt_file(MS1C, MS1D, &test_key, &test_nonce, TMAX, hash_two, MAX, &test_salt[..]);
        println!("ttime2: {:?}", timer.elapsed());
        assert_eq!(decrypted, true);

        timer          = time::Instant::now();
        let hash_three = encrypt_file(MSG2, MS2C, &test_key, &test_nonce, TMAX, MAX as u64, &test_salt[..]);
        println!("\netime3: {:?}", timer.elapsed());

        decrypted  = decrypt_file(MS2C, MS2D, &test_key, &test_nonce, TMAX, hash_three, MAX, &test_salt[..]);
        println!("ttime3: {:?}\n*****\n", timer.elapsed());
        assert_eq!(decrypted, true);
    }
}

/* OLDER TESTS:
    //#[test]
    fn test_auth_file() {
        rust_sodium::init().expect("sodium err");

        let test_key:   xchacha20::Key   = xchacha20::Key::from_slice(&[77, 98, 63, 124, 210, 234, 125, 221, 18, 168, 172, 173, 251, 202, 155, 47, 78, 127, 248, 155, 39, 25, 21, 255, 231, 29, 226, 235, 6, 255, 17, 74][..]).unwrap();
        let test_nonce: xchacha20::Nonce = xchacha20::Nonce::from_slice(&[38, 143, 150, 82, 213, 128, 30, 251, 149, 133, 127, 208, 159, 175, 41, 107, 93, 32, 206, 72, 77, 72, 105, 245][..]).unwrap();

        let test_salt: Vec<u8> = vec![0u8; 96];

        // _auth_file(input: &str, _hmac: Digest, max_threads: u64, salt: &[u8], max_mem: usize) -> bool
        let mut timer = time::Instant::now();
        let hash_one  = encrypt_file(MUDD, "../muddc1.bin", &test_key, &test_nonce, TMAX, MAX as u64, &test_salt[..]);
        println!("etime: {:?}", timer.elapsed());

        timer    = time::Instant::now();
        let auth = _auth_file("../muddc1.bin", hash_one, TMAX as u64, &test_salt[..], MAX);
        println!("atime: {:?}", timer.elapsed());

        assert_eq!(auth, true);
    }

    //#[test]
    fn test_en_file_test() {
        /*
        encrypt(input: &str, output: &str, key: &xchacha20::Key, nonce: &xchacha20::Nonce,
                       max_threads: usize, max_mem: u64, salt: &[u8; 96]) -> Digest */
        rust_sodium::init().expect("sodium err");

        let test_key:   xchacha20::Key   = xchacha20::Key::from_slice(&[77, 98, 63, 124, 210, 234, 125, 221, 18, 168, 172, 173, 251, 202, 155, 47, 78, 127, 248, 155, 39, 25, 21, 255, 231, 29, 226, 235, 6, 255, 17, 74][..]).unwrap();
        let test_nonce: xchacha20::Nonce = xchacha20::Nonce::from_slice(&[38, 143, 150, 82, 213, 128, 30, 251, 149, 133, 127, 208, 159, 175, 41, 107, 93, 32, 206, 72, 77, 72, 105, 245][..]).unwrap();

        let test_salt: Vec<u8> = vec![0u8; 96];

        let hash_one = encrypt_file(MSG2, "./message2c1.bin", &test_key, &test_nonce, TMAX, MAX as u64, &test_salt[..]);
        let hash_two = encrypt_file(MSG2, "./message2c2.bin", &test_key, &test_nonce, TMAX, MAX as u64, &test_salt[..]);

        println!("\none:\n{:?}\n\ntwo:\n{:?}\n\n", hash_one, hash_two);
        assert_eq!(hash_one, hash_two);
    }

    //#[test]
    fn test_standalone_buffer_en_auth_de() {
        rust_sodium::init().expect("sodium err");

        let test_key:   xchacha20::Key   = xchacha20::Key::from_slice(&[77, 98, 63, 124, 210, 234, 125, 221, 18, 168, 172, 173, 251, 202, 155, 47, 78, 127, 248, 155, 39, 25, 21, 255, 231, 29, 226, 235, 6, 255, 17, 74][..]).unwrap();
        let test_nonce: xchacha20::Nonce = xchacha20::Nonce::from_slice(&[38, 143, 150, 82, 213, 128, 30, 251, 149, 133, 127, 208, 159, 175, 41, 107, 93, 32, 206, 72, 77, 72, 105, 245][..]).unwrap();

        let mut buffer: Vec<u8>   = vec![0u8; MAX];
        let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

        let mut inp  = File::open(MSG1).expect("no open!");

        let cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("\n*****\nread {} bytes\n", cnt);

        let mut plaintext = Vec::new();
        unsafe { plaintext.extend_from_slice(&(*buf_ref)[..cnt]) };
        println!("plaintext:\n{:?}\n", String::from_utf8_lossy(&plaintext[..16]));
        let ehash = _encrypt(buf_ref, &test_key, &test_nonce, 0, TMAX, cnt as u64);
        let shash = _hash_buffer(buf_ref, TMAX, cnt as u64);

        println!("hash from _encrypt():\n{:?}\n\nhash from _hash_buffer():\n{:?}\n", ehash, shash);
        assert_eq!(ehash, shash);

        let mut ciphertext = Vec::new();
        unsafe { ciphertext.extend_from_slice(&(*buf_ref)[..cnt]) };
        println!("ciphertext: {:?}\n", String::from_utf8_lossy(&ciphertext[..16]));

        _decrypt(buf_ref, &test_key, &test_nonce, 0, TMAX, cnt as u64);
        let mut decrypted = Vec::new();
        unsafe {decrypted.extend_from_slice(&(*buf_ref)[..cnt]) };
        println!("decrypted:\n{:?}\n\n*****", String::from_utf8_lossy(&decrypted[..16]));

        assert_eq!(plaintext, decrypted);
    }

    //#[test]
    fn test_standalone_buffer_auth() {
        let mut buffer: Vec<u8>   = vec![0u8; MAX];
        let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

        let mut inp  = File::open(MSG1).expect("no open!");

        let mut cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("read {} bytes", cnt);
        inp.seek(io::SeekFrom::Start(0)).expect("seek err");

        let hash_one = _hash_buffer(buf_ref, TMAX, cnt as u64);
        cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("read {} bytes", cnt);
        inp.seek(io::SeekFrom::Start(0)).expect("seek err");

        let hash_two = _hash_buffer(buf_ref, TMAX, cnt as u64);
        cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("read {} bytes", cnt);
        inp.seek(io::SeekFrom::Start(0)).expect("seek err");

        let hash_three = _hash_buffer(buf_ref, TMAX-1, cnt as u64);

        println!("comparison one");
        assert_eq!(hash_one, hash_two);
        println!("comparison two");
        assert_eq!(hash_one, hash_three);
    }

    //#[test]
    fn test_auth_encrypt_hashes() {
        rust_sodium::init().expect("sodium err");
        let test_key:   xchacha20::Key   = xchacha20::Key::from_slice(&[77, 98, 63, 124, 210, 234, 125, 221, 18, 168, 172, 173, 251, 202, 155, 47, 78, 127, 248, 155, 39, 25, 21, 255, 231, 29, 226, 235, 6, 255, 17, 74][..]).unwrap();
        let test_nonce: xchacha20::Nonce = xchacha20::Nonce::from_slice(&[38, 143, 150, 82, 213, 128, 30, 251, 149, 133, 127, 208, 159, 175, 41, 107, 93, 32, 206, 72, 77, 72, 105, 245][..]).unwrap();

        let mut buffer: Vec<u8>   = vec![0u8; MAX];
        let buf_ref: *mut Vec<u8> = &mut buffer as *mut Vec<u8>;

        let mut inp  = File::open(MSG1).expect("no open!");

        let mut cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("read {} bytes", cnt);
        inp.seek(io::SeekFrom::Start(0)).expect("seek err");

        let hash_one = _encrypt(buf_ref, &test_key, &test_nonce, 0, TMAX, cnt as u64);
        println!("\nciphertext[0..64]: {:?}\n", unsafe { String::from_utf8_lossy(&(*buf_ref)[0..64]) });
        let mut ciph_one = vec![];
        unsafe { ciph_one.clone_from(&(*buf_ref)) };

        cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("read {} bytes", cnt);
        inp.seek(io::SeekFrom::Start(0)).expect("seek err");

        let hash_two = _encrypt(buf_ref, &test_key, &test_nonce, 0, TMAX, cnt as u64);
        println!("\nciphertext[0..64]: {:?}\n", unsafe { String::from_utf8_lossy(&(*buf_ref)[0..64]) });
        let mut ciph_two = vec![];
        unsafe { ciph_two.clone_from(&(*buf_ref)) };

        cnt = inp.read(unsafe { &mut *buf_ref }).expect("read err");
        println!("read {} bytes", cnt);
        inp.seek(io::SeekFrom::Start(0)).expect("seek err");

        let hash_three = _encrypt(buf_ref, &test_key, &test_nonce, 0, TMAX-1, cnt as u64);
        println!("\nciphertext[0..64]: {:?}\n", unsafe { String::from_utf8_lossy(&(*buf_ref)[0..64]) });
        let mut ciph_three = vec![];
        unsafe { ciph_three.clone_from(&(*buf_ref)) };

        println!("ciph comp one");
        assert_eq!(ciph_one, ciph_two);

        println!("ciph comp two\nlen 1: {}, len 3: {}", ciph_one.len(), ciph_three.len());
        assert_eq!(ciph_one, ciph_three);

        println!("comparison one");
        assert_eq!(hash_one, hash_two);
        println!("comparison two");
        assert_eq!(hash_one, hash_three);
    }
}*/
