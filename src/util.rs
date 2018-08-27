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
use argon2::{ThreadMode, Variant, Version};

pub fn secrets_from_argon(password: &[u8], salt: &[u8], key: &[u8], max_threads: usize, max_mem: usize) -> Result<Vec<u8>, argon2::Error> {

    let max = if max_mem/32 > 128*1024*1024 { max_mem/32 }
              else                          { 128*1024 };

    let argon = argon2::Config {
        ad          : &[],
        hash_length : 136,
        lanes       : max_threads as u32,
        mem_cost    : max as u32,
        secret      : key,
        thread_mode : ThreadMode::Parallel,
        time_cost   : 10,
        variant     : Variant::Argon2id,
        version     : Version::Version13,
    };

    argon2::hash_raw(password, salt, &argon)
}
