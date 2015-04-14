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

		let checksum = self.hash(buffer);
		let checksum_start_addr = buffer.len() - self.trailer_magic_bytes.len() - self.hash_size_bytes() as usize;
		

		{
			buffer[checksum_start_addr + 0] = ((checksum & (0xff00000000000000)) >> 7) as u8;
			buffer[checksum_start_addr + 1] = ((checksum & (0x00ff000000000000)) >> 6) as u8;
			buffer[checksum_start_addr + 2] = ((checksum & (0x0000ff0000000000)) >> 5) as u8;
			buffer[checksum_start_addr + 3] = ((checksum & (0x000000ff00000000)) >> 4) as u8;
			buffer[checksum_start_addr + 4] = ((checksum & (0x00000000ff000000)) >> 3) as u8;
			buffer[checksum_start_addr + 5] = ((checksum & (0x0000000000ff0000)) >> 2) as u8;
			buffer[checksum_start_addr + 6] = ((checksum & (0x000000000000ff00)) >> 1) as u8;
			buffer[checksum_start_addr + 7] = ((checksum & (0x00000000000000ff)) >> 0) as u8;
		}

		/*
		for i in 0..self.hash_size_bytes() as usize {
			let r = checksum.rotate_right((self.hash_size_bytes() as usize - i) as u32);
			buffer[checksum_start_addr + i as usize] = (r & 0xff) as u8;
			//buffer]
		}
		*/

		buffer[self.header_magic_bytes.len() + 0] = ((payload.len() & 0xff00 << 0) >> 1) as u8;
		buffer[self.header_magic_bytes.len() + 1] = ((payload.len() & 0xff << 0) >> 0) as u8;

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
			p += ((buffer[self.header_magic_bytes.len() + 0] as u16) << 1);
			p += ((buffer[self.header_magic_bytes.len() + 1] as u16) << 0);

			p
		};


		let s = self.header_magic_bytes.len() + 2;
		let payload = Payload {
			payload: &buffer[s..(s + payload_bytes as usize)]
		};

		let checksum_in_payload = {
			let mut c: u64 = 0;
			let mut s = buffer.len() - self.trailer_magic_bytes.len() - self.hash_size_bytes() as usize;
			
			c += (buffer[s + 0] as u64) << 7;
			c += (buffer[s + 1] as u64) << 6;
			c += (buffer[s + 2] as u64) << 5;
			c += (buffer[s + 3] as u64) << 4;
			c += (buffer[s + 4] as u64) << 3;
			c += (buffer[s + 5] as u64) << 2;
			c += (buffer[s + 6] as u64) << 1;
			c += (buffer[s + 7] as u64) << 0;

			c
		};

		let checksum = self.hash(payload.payload);
		
		if checksum_in_payload != checksum {
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

