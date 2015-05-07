#![no_std]

#![feature(core, alloc, no_std, macro_reexport, unboxed_closures, collections, convert, hash)]

extern crate core;
extern crate alloc;
extern crate collections;

use core::prelude::*;
use core::hash::Hasher;
use core::hash::SipHasher;
use core::array::FixedSizeArray;

use collections::vec::*;

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
	pub payload: &'a[u8],
	pub position: DetectedSignedBuffer
}

#[derive(Debug)]
pub struct SignedBufferResult {
	pub buffer_data_length: u32
}

#[derive(Debug, Copy, Clone)]
pub struct DetectedSignedBuffer {
	pub from: usize,
	pub to: usize
}

impl<'a> SignedBuffer<'a> {
	pub fn sign(&self, payload: &[u8], buffer: &mut [u8]) -> Result<SignedBufferResult, BufferSignatureError> {
		
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
		/*
		for i in 0..buffer.len() {
			buffer[i] = 0;
		}
		*/

		// construct the signed buffer
		let signed_buffer_len = {
			let mut bw = PointedSliceWriter::new();

			// header
			bw.write_slice_and_advance(buffer, self.header_magic_bytes);

			// payload length
			bw.write_slice_and_advance(buffer, ByteSerializer::serialize_u16(payload.len() as u16).as_slice());

			// copy the payload
			bw.write_slice_and_advance(buffer, payload);

			// payload checksum
			let checksum = self.hash(payload);
			bw.write_slice_and_advance(buffer, ByteSerializer::serialize_u64(checksum).as_slice());

			// trailer
			bw.write_slice_and_advance(buffer, self.trailer_magic_bytes);

			bw.get_pos()
		};

		Ok(SignedBufferResult { buffer_data_length: signed_buffer_len as u32 })
	}

	pub fn retrieve(&'a self, buffer: &'a [u8]) -> Result<Payload, PayloadRetrievalError> {		

		//let mut b = buffer;
		let mut b = PointedSliceReader::new(buffer);

		// header
		let header = b.get_next_slice(self.header_magic_bytes.len());
		if header.is_none() { return Err(PayloadRetrievalError::InvalidHeader); }
		let header = header.unwrap();
		if header != self.header_magic_bytes {
			return Err(PayloadRetrievalError::InvalidHeader);
		}

		// payload length
		let payload_bytes = ByteSerializer::deserialize_u16_opt(b.get_next_slice(2));
		if payload_bytes.is_none() { return Err(PayloadRetrievalError::InvalidPayloadSizeMarker); }
		let payload_bytes = payload_bytes.unwrap();		
		// todo: validate size, even before going for the payload itself

		// payload itself
		let payload_data = b.get_next_slice(payload_bytes as usize);
		if payload_data.is_none() { return Err(PayloadRetrievalError::InvalidPayloadSizeMarker); }
		let payload_data = payload_data.unwrap();


		// payload checksum
		let checksum_in_buffer = ByteSerializer::deserialize_u64_opt(b.get_next_slice(8));
		if checksum_in_buffer.is_none() { return Err(PayloadRetrievalError::InvalidHash); }
		let checksum_in_buffer = checksum_in_buffer.unwrap();
		let checksum = self.hash(payload_data);		
		if checksum != checksum_in_buffer {
			return Err(PayloadRetrievalError::InvalidHash);
		}

		// buffer trailer
		let trailer = b.get_next_slice(self.trailer_magic_bytes.len());
		if trailer.is_none() { return Err(PayloadRetrievalError::InvalidTrailer); }
		let trailer = trailer.unwrap();
		if trailer != self.trailer_magic_bytes {
			return Err(PayloadRetrievalError::InvalidTrailer);	
		}

		let payload = Payload {
			payload: payload_data,
			position: DetectedSignedBuffer {
				from: 0,
				to: b.get_pos()
			}
		};

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

	pub fn detect_regions(&self, buffer: &[u8]) -> Vec<DetectedSignedBuffer> {
		let mut ret = Vec::new();

		let mut pos = 0;
		while pos < buffer.len() {

			let s = &buffer[pos..];
			if s.starts_with(self.header_magic_bytes) {
				// try to decode it straight, it's faster
				let pl = self.retrieve(s);
				match pl {
					Ok(Payload { position: p,.. } ) => { 						
						ret.push(DetectedSignedBuffer { from: pos + p.from, to: pos + p.to });
						pos += p.to - p.from;						
					},
					Err(_) => {
						pos += 1;
					}
				}
			} else {
				pos += 1;
			}
		}

		ret
	}
}

pub struct PointedSliceReader<'a, T> where T: 'a + Copy {
	slice: &'a[T],
	pos: usize
}

impl<'a, T> PointedSliceReader<'a, T> where T: 'a + Copy {
	pub fn new(data: &[T]) -> PointedSliceReader<T> {
		PointedSliceReader {
			slice: data,
			pos: 0
		}
	}

	pub fn get_next_slice(&mut self, len: usize) -> Option<&'a [T]> {
		if (self.pos + len) > self.slice.len() || len == 0 {
			return None;
		}
		
		let ret = Some(&self.slice[self.pos..(self.pos+len)]);
		self.pos += len;

		ret
	}

	pub fn get_pos(&self) -> usize {
		self.pos
	}	
}

pub struct PointedSliceWriter {
	pos: usize
}
impl PointedSliceWriter {
	pub fn new() -> PointedSliceWriter {
		PointedSliceWriter { pos: 0 }
	}

	pub fn write_and_advance<T>(&mut self, target: &mut[T], data: T) where T: Copy {
		self.write_slice_and_advance(target, &[data].as_slice());
	}

	pub fn write_slice_and_advance<T>(&mut self, target: &mut[T], data: &[T]) where T: Copy {
		for i in 0..data.len() {
			if self.pos >= target.len() {
				return;
			}

			target[self.pos] = data[i];
			self.pos += 1;
		}
	}

	pub fn get_pos(&self) -> usize {
		self.pos
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

	pub fn deserialize_u64(bytes: &[u8]) -> Option<u64> {
		if bytes.len() != 8 { return None; }
		Some(ByteSerializer::deserialize_uint(bytes))
	}

	pub fn deserialize_u64_opt(bytes: Option<&[u8]>) -> Option<u64> {
		if bytes.is_none() { return None; }
		ByteSerializer::deserialize_u64(bytes.unwrap())
	}


	pub fn serialize_u16(val: u16) -> [u8; 2] {
		let mut b = [0 as u8; 2];
		ByteSerializer::serialize_uint(val as u64, b.as_mut_slice());
		b
	}

	pub fn deserialize_u16(bytes: &[u8]) -> Option<u16> {
		if bytes.len() != 2 { return None; }
		Some(ByteSerializer::deserialize_uint(bytes) as u16)
	}

	pub fn deserialize_u16_opt(bytes: Option<&[u8]>) -> Option<u16> {
		if bytes.is_none() { return None; }
		ByteSerializer::deserialize_u16(bytes.unwrap())
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
	use collections::vec::Vec;

	#[test]
	fn pointed_slice_reader() {
		let data = [1,2,3,4,5,6];
		let mut p = PointedSliceReader::new(data.as_slice());

		let s = p.get_next_slice(0);
		assert_eq!(None, s);

		let s = p.get_next_slice(3).unwrap();
		assert_eq!([1,2,3].as_slice(), s);		
		let s = p.get_next_slice(3).unwrap();
		assert_eq!([4,5,6].as_slice(), s);

		let s = p.get_next_slice(3);
		assert_eq!(None, s);
		let s = p.get_next_slice(1);
		assert_eq!(None, s);
		let s = p.get_next_slice(0);
		assert_eq!(None, s);
	}

	#[test]
	fn pointed_slice_writer() {
		let mut w = PointedSliceWriter::new();
		let mut buffer = Vec::new();
		for i in 0..9 {
			buffer.push(0);
		}
		
		w.write_slice_and_advance(buffer.as_mut_slice(), [1, 2, 3].as_slice());
		w.write_slice_and_advance(buffer.as_mut_slice(), [4, 5, 6].as_slice());
		w.write_slice_and_advance(buffer.as_mut_slice(), [7, 8, 9].as_slice());

		assert_eq!([1,2,3,4,5,6,7,8,9].as_slice(), buffer.as_slice());
		assert_eq!(9, w.get_pos());
	}

	#[test]
	fn bytes() {
		{
			let num = 2418509812123184;
			let s = ByteSerializer::serialize_u64(num);

			assert_eq!(num, ByteSerializer::deserialize_u64(&s).unwrap());
		}

		{
			let num = 421894;
			let s = ByteSerializer::serialize_u16(num);

			assert_eq!(num, ByteSerializer::deserialize_u16(&s).unwrap());
		}

		{
			let b = [26, 124, 142, 98, 167, 23, 116, 11];
			let num = ByteSerializer::deserialize_u64(&b).unwrap();
			let d = ByteSerializer::serialize_u64(num);

			assert_eq!(b, d);
		}

	}

	#[test]
	fn detection() {
		let header = [100, 200];
		let trailer = [200, 100];


		let signed_buffer = SignedBuffer {
			size: BufferSize::Dynamic { max_bytes: 128 },
			header_magic_bytes: header.as_slice(),
			trailer_magic_bytes: trailer.as_slice()
		};

		let payload = [100, 200, 200, 100, 100, 200, 200, 200, 100, 200, 100];
		
		let mut buffer = [0; 128];

		signed_buffer.sign(payload.as_slice(), buffer.as_mut_slice()).unwrap();
		signed_buffer.sign(payload.as_slice(), buffer[60..].as_mut_slice()).unwrap();

		buffer[58] = 100;
		buffer[59] = 200;

		let detected = signed_buffer.detect_regions(buffer.as_slice());
		println!("detected buffers: {:?}", detected);

		for r in detected {
			let b = &buffer[(r.from)..(r.to)];
			let p = signed_buffer.retrieve(b.as_slice()).unwrap();
			assert_eq!(p.payload, payload.as_slice());
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

