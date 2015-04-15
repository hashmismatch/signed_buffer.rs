#![no_std]

#![feature(core, alloc, no_std, macro_reexport, unboxed_closures, collections, convert)]

extern crate core;
extern crate alloc;
extern crate collections;

use core::prelude::*;
use core::hash::Hasher;
use core::hash::SipHasher;

#[derive(Debug)]
pub struct SignedBuffer<'a> {
	pub size_bytes: u16,
	pub header_magic_bytes: &'a[u8],
	pub trailer_magic_bytes: &'a[u8]
}

#[derive(Debug)]
pub enum BufferSignatureError {
	PayloadTooLarge,
	BufferInvalidSize
}

#[derive(Debug)]
pub enum PayloadRetrievalError {
	InvalidBufferSize,
	InvalidHeader,
	InvalidTrailer,
	InvalidHash
}

#[derive(Debug)]
pub struct Payload<'a> {
	pub payload: &'a[u8]
}

impl<'a> SignedBuffer<'a> {
	pub fn sign(&self, payload: &[u8], buffer: &mut [u8]) -> Result<(), BufferSignatureError> {
		if buffer.len() != self.size_bytes as usize {
			return Err(BufferSignatureError::BufferInvalidSize);
		}

		if payload.len() > (self.size_bytes as usize - self.padding_size_bytes() as usize) {
			return Err(BufferSignatureError::PayloadTooLarge);
		}

		// clear
		for i in 0..buffer.len() {
			buffer[i] = 0;
		}

		for i in 0..self.header_magic_bytes.len() {
			buffer[i] = self.header_magic_bytes[i];
		}

		for i in 0..self.trailer_magic_bytes.len() {
			buffer[buffer.len() - self.trailer_magic_bytes.len() + i] = self.trailer_magic_bytes[i];
		}

		let checksum = self.hash(payload);
		let checksum_start_addr = buffer.len() - self.trailer_magic_bytes.len() - self.hash_size_bytes() as usize;
		
		{
			let c = ByteSerializer::serialize_u64(checksum);

			for i in 0..c.len() {
				buffer[checksum_start_addr + i] = c[i];
			}
		}

		/*
		for i in 0..self.hash_size_bytes() as usize {
			let r = checksum.rotate_right((self.hash_size_bytes() as usize - i) as u32);
			buffer[checksum_start_addr + i as usize] = (r & 0xff) as u8;
			//buffer]
		}
		*/

		{
			let l = ByteSerializer::serialize_u16(payload.len() as u16);
			buffer[self.header_magic_bytes.len() + 0] = l[0];
			buffer[self.header_magic_bytes.len() + 1] = l[1];
		}

		for i in 0..payload.len() {
			buffer[self.header_magic_bytes.len() + 2 + i] = payload[i];
		}


		Ok(())
	}

	pub fn retrieve(&'a self, buffer: &'a [u8]) -> Result<Payload, PayloadRetrievalError> {
		if buffer.len() != self.size_bytes as usize {
			return Err(PayloadRetrievalError::InvalidBufferSize);
		}

		for i in 0..self.header_magic_bytes.len() {
			if buffer[i] != self.header_magic_bytes[i] {
				return Err(PayloadRetrievalError::InvalidHeader);
			}
		}

		for i in 0..self.trailer_magic_bytes.len() {
			if buffer[buffer.len() - self.trailer_magic_bytes.len() + i] != self.trailer_magic_bytes[i] {
				return Err(PayloadRetrievalError::InvalidTrailer);	
			}
		}

		let payload_bytes = ByteSerializer::deserialize_u16(&[buffer[self.header_magic_bytes.len() + 0], buffer[self.header_magic_bytes.len() + 1]]);

		let s = self.header_magic_bytes.len() + 2;
		let payload = Payload {
			payload: &buffer[s..(s + payload_bytes as usize)]
		};

		let checksum_in_buffer = {
			let mut s = buffer.len() - self.trailer_magic_bytes.len() - self.hash_size_bytes() as usize;

			let b = [
				buffer[s + 0],
				buffer[s + 1],
				buffer[s + 2],
				buffer[s + 3],
				buffer[s + 4],
				buffer[s + 5],
				buffer[s + 6],
				buffer[s + 7]
			];

			ByteSerializer::deserialize_u64(&b)
		};

		let checksum = self.hash(payload.payload);
		
		if checksum != checksum_in_buffer {
			return Err(PayloadRetrievalError::InvalidHash);
		}

		return Ok(payload);
	}

	fn hash(&self, buffer: &[u8]) -> u64 {
		let mut hash = SipHasher::new();

		for b in buffer {
			hash.write_u8(*b);
		}

		hash.finish()
	}

	fn padding_size_bytes(&self) -> u16 {
		(2 + self.header_magic_bytes.len() + self.trailer_magic_bytes.len() + self.hash_size_bytes() as usize) as u16
	}

	fn hash_size_bytes(&self) -> u16 {
		8
	}
}

pub struct ByteSerializer;
impl ByteSerializer {
	fn serialize_uint(val: u64, output: &mut [u8]) {
		let l = output.len();
		for i in 0..l {
			let r = val >> ((l-i-1) * 8);
			output[i] = (r & 0xff) as u8;
		}
	}

	fn deserialize_uint(bytes: &[u8]) -> u64 {
		let mut ret = 0 as u64;
		
		let l = bytes.len();
		for i in 0..l {
			ret += (bytes[i] as u64) << ((l-i-1) * 8);
		}

		ret
	}

	pub fn serialize_u64(val: u64) -> [u8; 8] {
		let mut b = [0 as u8; 8];
		ByteSerializer::serialize_uint(val, b.as_mut_slice());
		b
	}

	pub fn deserialize_u64(bytes: &[u8; 8]) -> u64 {
		ByteSerializer::deserialize_uint(bytes.as_slice())
	}

	pub fn serialize_u16(val: u16) -> [u8; 2] {
		let mut b = [0 as u8; 2];
		ByteSerializer::serialize_uint(val as u64, b.as_mut_slice());
		b
	}

	pub fn deserialize_u16(bytes: &[u8; 2]) -> u16 {
		ByteSerializer::deserialize_uint(bytes.as_slice()) as u16
	}
}





// for tests
#[cfg(test)]
#[macro_use(println, assert_eq, print, panic)]
extern crate std;

#[cfg(test)]
mod tests {
	use super::*;
	use core::prelude::*;
	use std::prelude::*;

	#[test]
	fn bytes() {
		{
			let num = 2418509812123184;
			let s = ByteSerializer::serialize_u64(num);

			assert_eq!(num, ByteSerializer::deserialize_u64(&s));
		}

		{
			let num = 421894;
			let s = ByteSerializer::serialize_u16(num);

			assert_eq!(num, ByteSerializer::deserialize_u16(&s));
		}

		{
			let b = [26, 124, 142, 98, 167, 23, 116, 11];
			let num = ByteSerializer::deserialize_u64(&b);
			let d = ByteSerializer::serialize_u64(num);

			assert_eq!(b, d);
		}

	}

	#[test]
	fn roundtrip() {
		let header = [100, 200];
		let trailer = [200, 100];


		let signed_buffer = SignedBuffer {
			size_bytes: 128,
			header_magic_bytes: header.as_slice(),
			trailer_magic_bytes: trailer.as_slice()
		};

		let mut buffer = [0; 128];
		let payload = [0, 100, 200, 60, 123, 125, 255, 0, 0, 255];

		let u = signed_buffer.sign(payload.as_slice(), buffer.as_mut_slice());
		println!("{:?}", u);
		println!("buffer: {:?}", buffer.as_slice());
		//println!("buffer:");
		/*
		for i in 0..buffer.len() {
			println!("buffer[{}] = {}", i, buffer[i]);
		}
		*/


		let retrieved = signed_buffer.retrieve(buffer.as_slice());		
		println!("retrieved: {:?}", retrieved);

		assert_eq!(payload.as_slice(), retrieved.unwrap().payload);
	}
}

