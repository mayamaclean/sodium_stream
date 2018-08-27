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
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;

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
