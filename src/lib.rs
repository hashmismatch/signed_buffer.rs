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
	pub size: BufferSize,
	pub header_magic_bytes: &'a[u8],
	pub trailer_magic_bytes: &'a[u8]
}

#[derive(Debug)]
pub enum BufferSize {
	Fixed { bytes: u32 },
	Dynamic { max_bytes: u32 }
}

#[derive(Debug)]
pub enum BufferSignatureError {
	PayloadTooLarge,
	BufferInvalidSize { expected: u32, actual: u32 }
}

#[derive(Debug)]
pub enum PayloadRetrievalError {
	InvalidBufferSize,
	InvalidHeader,
	InvalidTrailer,
	InvalidHash,
	InvalidPayloadSizeMarker
}

#[derive(Debug)]
pub struct Payload<'a> {
	pub payload: &'a[u8]
}

impl<'a> SignedBuffer<'a> {
	pub fn sign(&self, payload: &[u8], buffer: &mut [u8]) -> Result<(), BufferSignatureError> {
		
		match self.size {
			// exact size match is required
			BufferSize::Fixed { bytes: bytes } => {
				if buffer.len() != bytes as usize {
					return Err(BufferSignatureError::BufferInvalidSize { expected: bytes, actual: buffer.len() as u32 });
				}
			},
			_ => {}
		}
		
		// check if payload fits into our buffer
		{
			let max_size = match self.size {
				BufferSize::Fixed { bytes: bytes } => bytes,
				BufferSize::Dynamic { .. } => buffer.len() as u32
			};

			if payload.len() > (max_size as usize - self.padding_size_bytes() as usize) {
				return Err(BufferSignatureError::PayloadTooLarge);
			}
		}

		

		// clear
		for i in 0..buffer.len() {
			buffer[i] = 0;
		}

		// construct the signed buffer
		let signed_buffer_len = {
			let mut pos = 0;

			// header
			for i in 0..self.header_magic_bytes.len() {
				buffer[pos] = self.header_magic_bytes[i];
				pos += 1;
			}

			// payload length
			{
				let l = ByteSerializer::serialize_u16(payload.len() as u16);
				buffer[pos] = l[0];
				pos += 1;
				buffer[pos] = l[1];
				pos += 1;
			}

			// copy the payload
			for i in 0..payload.len() {
				buffer[pos] = payload[i];
				pos += 1;
			}

			// payload checksum
			{
				let checksum = self.hash(payload);								
				let c = ByteSerializer::serialize_u64(checksum);

				for i in 0..c.len() {
					buffer[pos] = c[i];
					pos += 1;
				}
			}

			// trailer
			for i in 0..self.trailer_magic_bytes.len() {
				buffer[pos] = self.trailer_magic_bytes[i];
				pos += 1;
			}

			pos
		};

		Ok(())
	}

	pub fn retrieve(&'a self, buffer: &'a [u8]) -> Result<Payload, PayloadRetrievalError> {
		/*
		if buffer.len() != self.size_bytes as usize {
			return Err(PayloadRetrievalError::InvalidBufferSize);
		}
		*/
		let mut pos = 0;

		for i in 0..self.header_magic_bytes.len() {
			if buffer[pos] != self.header_magic_bytes[i] {
				return Err(PayloadRetrievalError::InvalidHeader);
			}
			pos += 1;
		}

		let payload_bytes = ByteSerializer::deserialize_u16(&[buffer[pos], buffer[pos + 1]]);
		pos += 2;
		// todo: validate size!

		let payload = Payload {
			payload: &buffer[pos..(payload_bytes as usize + pos)]
		};
		pos += payload_bytes as usize;

		let checksum_in_buffer = {
			let b = [
				buffer[pos + 0],
				buffer[pos + 1],
				buffer[pos + 2],
				buffer[pos + 3],
				buffer[pos + 4],
				buffer[pos + 5],
				buffer[pos + 6],
				buffer[pos + 7]
			];
			pos += 8;

			ByteSerializer::deserialize_u64(&b)
		};

		let checksum = self.hash(payload.payload);		
		if checksum != checksum_in_buffer {
			return Err(PayloadRetrievalError::InvalidHash);
		}

		for i in 0..self.trailer_magic_bytes.len() {
			if buffer[pos] != self.trailer_magic_bytes[i] {
				return Err(PayloadRetrievalError::InvalidTrailer);	
			}
			pos += 1;
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

	pub fn signed_buffer_size(&self, payload: &[u8]) -> u32 {
		match self.size {
			BufferSize::Fixed { bytes: bytes } => bytes,
			BufferSize::Dynamic { .. } => self.padding_size_bytes() + payload.len() as u32
		}
	}

	fn padding_size_bytes(&self) -> u32 {
		(self.header_magic_bytes.len() + 2 + self.hash_size_bytes() as usize + self.trailer_magic_bytes.len()) as u32
	}

	fn hash_size_bytes(&self) -> u32 {
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
			size: BufferSize::Fixed { bytes: 128 },
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

