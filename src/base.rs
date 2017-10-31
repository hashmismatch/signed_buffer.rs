use prelude::v1::*;

use structs::*;

use packed_struct::PackedStruct;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BufferSize {
	Fixed { bytes: usize },
	Dynamic { max_bytes: usize }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignedBufferError {
    InvalidMagic
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigningError {
	PayloadTooLarge,
    PayloadEmpty,
	InvalidBufferSize { expected: usize, actual: usize }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RetrievalError {
	InvalidBufferSize,
	InvalidHeader,
	InvalidTrailer,
	InvalidHash,
    InvalidChecksumStruct,
	MissingData,
    TooMuchData,
    UnsupportedVersion { received_version: u8 },
    EmptyPayloadSize
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedBuffer {
	pub payload_position: Range<usize>,
    pub entire_buffer: Range<usize>
}

impl DecodedBuffer {
    pub fn get_payload_from_buffer<'a>(&self, buffer: &'a [u8]) -> &'a [u8] {
        buffer.index(self.payload_position.clone())
    }

    pub fn offset(&self, offset: usize) -> DecodedBuffer {
        DecodedBuffer {
            payload_position: self.payload_position.start + offset .. self.payload_position.end + offset,
            entire_buffer: self.entire_buffer.start + offset .. self.entire_buffer.end + offset
        }
    }
}

#[derive(Debug)]
pub struct SignedBufferResult<'a> {
	pub checksum: BufferChecksum,
    pub payload: &'a [u8],
    pub header: &'a [u8],
    pub trailer: &'a [u8]
}

impl<'a> SignedBufferResult<'a> {
    pub fn assemble(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.header);
        v.extend_from_slice(&self.checksum.pack()[..]);
        v.extend_from_slice(self.payload);
        v.extend_from_slice(&self.trailer);
        v
    }
}