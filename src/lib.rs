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

		let checksum = SignedBuffer::hash(buffer);
		let checksum_start_addr = buffer.len() - self.trailer_magic_bytes.len() - self.hash_size_bytes() as usize;
		
		for i in 0..self.hash_size_bytes() as usize {
			let r = checksum.rotate_right((self.hash_size_bytes() as usize - i) as u32);
			buffer[checksum_start_addr + i as usize] = (r & 0xff) as u8;
		}

		for i in 0..2 {
			buffer[i + self.header_magic_bytes.len()] = (payload.len() >> (1 - i as u32) & 0xff) as u8;
		}

		for i in 0..payload.len() {
			buffer[2 + self.header_magic_bytes.len() + i] = payload[i];
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

		let payload_bytes = {
			let mut p: u16 = 0;
			p += (buffer[self.header_magic_bytes.len() + 0] << 1) as u16;
			p += (buffer[self.header_magic_bytes.len() + 1] << 0) as u16;

			p
		};


		let s = self.header_magic_bytes.len() + 2;

		return Ok(Payload {
			payload: &buffer[s..(s + payload_bytes as usize)]
		});
	}

	fn hash(buffer: &[u8]) -> u64 {
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
	fn roundtrip() {
		let header = [100, 200];
		let trailer = [200, 100];


		let signed_buffer = SignedBuffer {
			size_bytes: 128,
			header_magic_bytes: header.as_slice(),
			trailer_magic_bytes: trailer.as_slice()
		};

		let mut buffer = [0; 128];

		let u = signed_buffer.sign([0, 100, 200].as_slice(), buffer.as_mut_slice());
		println!("{:?}", u);
		//println!("buffer: {:?}", buffer);
		println!("buffer:");
		for i in 0..buffer.len() {
			println!("buffer[{}] = {}", i, buffer[i]);
		}


		let retrieved = signed_buffer.retrieve(buffer.as_slice());
		println!("retrieved");
		println!("{:?}", retrieved);
	}
}

