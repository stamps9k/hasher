use std::num::Wrapping;

/*
  SHA256 Hasher properties
*/
pub struct SHA256 {
  h: [Wrapping<u32>; 8], // The hash
  k: [Wrapping<u32>; 64], // The round constants
}

/*
  SHA256 Hasher methods
*/
impl SHA256 {
  pub fn new() -> SHA256 {
    return SHA256 {
      h:  [
        Wrapping(0x6a09e667),
        Wrapping(0xbb67ae85),
        Wrapping(0x3c6ef372),
        Wrapping(0xa54ff53a),
        Wrapping(0x510e527f),
        Wrapping(0x9b05688c),
        Wrapping(0x1f83d9ab),
        Wrapping(0x5be0cd19)
      ],
      k: [
        Wrapping(0x428a2f98), Wrapping(0x71374491), Wrapping(0xb5c0fbcf), Wrapping(0xe9b5dba5),
        Wrapping(0x3956c25b), Wrapping(0x59f111f1), Wrapping(0x923f82a4), Wrapping(0xab1c5ed5),
        Wrapping(0xd807aa98), Wrapping(0x12835b01), Wrapping(0x243185be), Wrapping(0x550c7dc3),
        Wrapping(0x72be5d74), Wrapping(0x80deb1fe), Wrapping(0x9bdc06a7), Wrapping(0xc19bf174),
        Wrapping(0xe49b69c1), Wrapping(0xefbe4786), Wrapping(0x0fc19dc6), Wrapping(0x240ca1cc),
        Wrapping(0x2de92c6f), Wrapping(0x4a7484aa), Wrapping(0x5cb0a9dc), Wrapping(0x76f988da),
        Wrapping(0x983e5152), Wrapping(0xa831c66d), Wrapping(0xb00327c8), Wrapping(0xbf597fc7),
        Wrapping(0xc6e00bf3), Wrapping(0xd5a79147), Wrapping(0x06ca6351), Wrapping(0x14292967),
        Wrapping(0x27b70a85), Wrapping(0x2e1b2138), Wrapping(0x4d2c6dfc), Wrapping(0x53380d13),
        Wrapping(0x650a7354), Wrapping(0x766a0abb), Wrapping(0x81c2c92e), Wrapping(0x92722c85),
        Wrapping(0xa2bfe8a1), Wrapping(0xa81a664b), Wrapping(0xc24b8b70), Wrapping(0xc76c51a3),
        Wrapping(0xd192e819), Wrapping(0xd6990624), Wrapping(0xf40e3585), Wrapping(0x106aa070),
        Wrapping(0x19a4c116), Wrapping(0x1e376c08), Wrapping(0x2748774c), Wrapping(0x34b0bcb5),
        Wrapping(0x391c0cb3), Wrapping(0x4ed8aa4a), Wrapping(0x5b9cca4f), Wrapping(0x682e6ff3),
        Wrapping(0x748f82ee), Wrapping(0x78a5636f), Wrapping(0x84c87814), Wrapping(0x8cc70208),
        Wrapping(0x90befffa), Wrapping(0xa4506ceb), Wrapping(0xbef9a3f7), Wrapping(0xc67178f2)
      ]
    }
  }

  /*
    Hash a u8 array and output as a hex string 
  */
  pub fn hash_u8_to_string(&mut self, val: &[u8]) -> String {
    let l: Vec<Wrapping<u32>> = self.pre_process(val);
    self.chunk_loop(l);
    return self.to_string();
  }

  /*
    Convert the hash stored as 8 32 bit words to a string for printing to terminal
  */
  fn to_string(&self) -> String {
    let mut h_u32: [u8; 32] = [0; 32];

    for (i, e) in self.h.iter().enumerate() {
      let tmp_0: u8 = (e.0 >> 24 & 0x000000FF) as u8;
      let tmp_1: u8 = (e.0 >> 16 & 0x000000FF) as u8;
      let tmp_2: u8 = (e.0 >> 8 & 0x000000FF) as u8;
      let tmp_3: u8 = (e.0 & 0x000000FF) as u8;
      h_u32[i*4+0] = tmp_0;
      h_u32[i*4+1] = tmp_1;
      h_u32[i*4+2] = tmp_2;
      h_u32[i*4+3] = tmp_3;
    }
    return hex::encode(h_u32);
  }


  /**
    Take 512 bits of message expand, process as defined by SHA256 standard, compress and update the ongoing hash value
  **/
  fn chunk_loop(&mut self, m: Vec<Wrapping<u32>>) {
    
    let no_of_blocks: usize = m.len() * 32 / 512;
    for i in 0..no_of_blocks {
      log::debug!("Starting processing chunk {}...", i);
      // 512 bits is 16 entries in an array of 32 bit ints 
      let start_block: usize = i*16;

      let mut chunk: Vec<Wrapping<u32>> = m[start_block..(start_block+16)].to_vec();

      for _i in 0..(start_block+48) {
        chunk.push(Wrapping(0x0000));
      }

      for i in 16..64 {
        let tmp_1: Wrapping<u32> = (chunk[i-15] << 25) | (chunk[i-15] >> 7);
        let tmp_2: Wrapping<u32> = (chunk[i-15] << 14) | (chunk[i-15] >> 18);
        let tmp_3: Wrapping<u32> = chunk[i-15] >> 3;
        let s0 = tmp_1 ^ tmp_2 ^ tmp_3;

        let tmp_4: Wrapping<u32> = (chunk[i-2] << 15) | (chunk[i-2] >> 17);
        let tmp_5: Wrapping<u32> = (chunk[i-2] << 13) | (chunk[i-2] >> 19);
        let tmp_6: Wrapping<u32> = chunk[i-2] >> 10;
        let s1 = tmp_4 ^ tmp_5 ^ tmp_6;
        
        chunk[i] = chunk[i-16] + s0 + chunk[i-7] + s1;
      }

      log::debug!("Starting compression of chunk {}...", i);
      self.compress(chunk);
      log::debug!("...finished compression of chunk {}", i);
      log::debug!("...finished processing chunk {}", i);
    }
  }

  /*
    Compress a 64 length 32bit word array down and asassign to the ongoing hash as defined by SHA256 standard
  */
  fn compress(&mut self, w: Vec<Wrapping<u32>>) {
    let mut a = self.h[0];
    let mut b = self.h[1];
    let mut c = self.h[2];
    let mut d = self.h[3];
    let mut e = self.h[4];
    let mut f = self.h[5];
    let mut g = self.h[6];
    let mut h = self.h[7];

    for i in 0..64 {
      let tmp_1: Wrapping<u32> = (e << 26) | (e >> 6);
      let tmp_2: Wrapping<u32> = (e << 21) | (e >> 11);
      let tmp_3: Wrapping<u32> = (e << 7) | (e >> 25);
      let s1 = tmp_1 ^ tmp_2 ^ tmp_3;

      let ch = (e & f) ^ (!e & g);

      let tmp1 = h + s1 + ch + self.k[i] +  w[i];

      let tmp_4: Wrapping<u32> = (a << 30) | (a >> 2);
      let tmp_5: Wrapping<u32> = (a << 19) | (a >> 13);
      let tmp_6: Wrapping<u32> = (a << 10) | (a >> 22);
      let s0 = tmp_4 ^ tmp_5 ^ tmp_6;

      let maj = (a & b) ^ (a & c) ^ (b & c);

      let tmp2 = s0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + tmp1;
      d = c;
      c = b;
      b = a;
      a = tmp1 + tmp2
    }

    self.h[0] = self.h[0] + a;
    self.h[1] = self.h[1] + b;
    self.h[2] = self.h[2] + c;
    self.h[3] = self.h[3] + d;
    self.h[4] = self.h[4] + e;
    self.h[5] = self.h[5] + f;
    self.h[6] = self.h[6] + g;
    self.h[7] = self.h[7] + h;
  }

  /*
    Pre process a u8 array. As defined in SHA256 standard
  */
  fn pre_process(&self, chars: &[u8]) -> Vec<Wrapping<u32>> {
    // Calculate size of padded u8 length
    let base_size: usize = chars.len();
    let to_add: usize = 64 - ((chars.len() + 1 + 8) % 64) + 1 + 8;
    let padded_size: usize = base_size + to_add;

    // Create a vector of the corect sizshe to store the fully padded data and populate with initial data
    let mut tmp: Vec<Wrapping<u8>> = vec![Wrapping(0); padded_size];
    for i in 0..chars.len() {
      tmp[i] = Wrapping(chars[i]);
    }
    
    //Append the end of message marker
    tmp[chars.len()] = Wrapping(0x80);
    
    // Calculate message length and append to the end
    let msg_len: [Wrapping<u8>; 8] = self.u64_to_u8(Wrapping((chars.len() * 8) as u64));
    for i in 0..8 {
      let index: usize = tmp.len() - 8 + i;
      tmp[index] = msg_len[i];  
    }

    // Finally convert to 32 bit
    let mut out_arr: Vec<Wrapping<u32>> = vec![Wrapping(0); padded_size / 4];
    for i in (0..padded_size).step_by(4) {
      out_arr[i/4] = self.u8_slice_to_u32(&tmp[i..i + 4]);
    }

    return out_arr; 
  }

  /*
    Convert a 4 long u8 slice to a u32. Hasher therefore everything is inside wrapper 
  */
  fn u8_slice_to_u32(&self, slice: &[Wrapping<u8>]) -> Wrapping<u32> {
    let mut array: [u8; 4] = [0; 4];
    for i in 0..4 {
       array[i] = slice[i].0; 
    }
    return Wrapping(u32::from_be_bytes(array));
  }

  /*
    Convert a u64 to an array of u8's using big endian. Hasher therefore everything is inside wrapper 
  */
  fn u64_to_u8(&self, arr: Wrapping<u64>) -> [Wrapping<u8>; 8]{
    let b0 = (arr.0 >> 56) as u8;
    let b1 = (arr.0 >> 48) as u8;
    let b2 = (arr.0 >> 40) as u8;
    let b3 = (arr.0 >> 32) as u8;
    let b4 = (arr.0 >> 24) as u8;
    let b5 = (arr.0 >> 16) as u8;
    let b6 = (arr.0 >> 8) as u8;
    let b7 = arr.0 as u8;

    return [Wrapping(b0), Wrapping(b1), Wrapping(b2), Wrapping(b3), Wrapping(b4), Wrapping(b5), Wrapping(b6), Wrapping(b7)];
  }
}