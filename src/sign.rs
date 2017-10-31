use prelude::v1::*;

use base::*;
use structs::*;

use siphasher::sip::SipHasher24;
use packed_struct::*;

#[derive(Debug)]
pub struct SignedBuffer<'a, H> {
	size: BufferSize,
	header_magic_bytes: &'a[u8],
	trailer_magic_bytes: &'a[u8],
    _hasher: PhantomData<H>
}

impl<'a, H> SignedBuffer<'a, H> where H: Hasher + Default {
    pub fn new(size: BufferSize, header: &'a [u8], trailer: &'a [u8]) -> Result<Self, SignedBufferError> {
        let s = SignedBuffer {
            size: size,
            header_magic_bytes: header,
            trailer_magic_bytes: trailer,
            _hasher: PhantomData
        };
        Ok(s)
    }

    pub fn sign(&'a self, payload: &'a [u8]) -> Result<SignedBufferResult<'a>, SigningError> {
        if payload.len() == 0 {
            return Err(SigningError::PayloadEmpty);
        }

        let version = self.version();
        let size = payload.len() as u32;

        let mut hasher: H = Default::default();
        hasher.write_u8(version);
        hasher.write_u32(size);
        hasher.write(payload);
        let checksum = hasher.finish();

        let b = BufferChecksum {
            version: version,
            size: size,
            checksum: checksum
        };
        
        let r = SignedBufferResult {
            checksum: b,
            payload: payload,
            header: self.header_magic_bytes,
            trailer: self.trailer_magic_bytes
        };
        Ok(r)
    }

    pub fn new_decoder(&self) -> SignedBufferDetector<H> {
        SignedBufferDetector::new(self)
    }

    /// Decodes a single buffer, the content (header) should start right at the beginning.
    /// Returns the number of consumed bytes
    pub fn decode(&self, buffer: &[u8]) -> Result<(usize, DecodedBuffer), RetrievalError> {
        let mut decoder = SignedBufferDecoder::new(self, 0);

        let mut i = 0;
        for &b in buffer {
            try!(decoder.read_byte(b));
            i += 1;

            if let State::Finished { checksum, payload } = decoder.state {
                return Ok((i, DecodedBuffer {
                    payload_position: payload,
                    entire_buffer: 0..i
                }));
            }
        }

        Err(RetrievalError::MissingData)
    }

    /// Tries to find all the valid buffers
    pub fn decode_all(&self, buffer: &[u8]) -> Vec<DecodedBuffer> {
        let mut decoder = self.new_decoder();
        let mut ret = Vec::new();

        for &b in buffer {
            if let Some(d) = decoder.decode_byte(b) {
                ret.push(d);
            }
        }

        ret
    }

    pub fn version(&self) -> u8 {
        1
    }

    pub fn buffer_len(&self, payload_size: usize) -> usize {
        self.header_magic_bytes.len() + self.trailer_magic_bytes.len() + BufferChecksum::packed_bytes() + payload_size
    }
}

pub struct SignedBufferDetector<'a, H: 'a> {
    decoder: SignedBufferDecoder<'a, H>,
    offset: usize
}

impl<'a, H> SignedBufferDetector<'a, H> where H: Hasher + Default {
    fn new(s: &'a SignedBuffer<'a, H>) -> Self {
        SignedBufferDetector {
            decoder: SignedBufferDecoder::new(s, 0),
            offset: 0
        }
    }

    pub fn decode_byte(&mut self, byte: u8) -> Option<DecodedBuffer> {
        let mut ret = None;

        self.offset += 1;

        match self.decoder.read_byte(byte) {
            Ok(_) => {
                if let State::Finished { checksum, ref payload } = self.decoder.state {                    
                    ret = Some(DecodedBuffer {
                        payload_position: payload.clone(),
                        entire_buffer: (self.offset - self.decoder.s.buffer_len(payload.len()))..self.offset
                    });
                }

                if ret.is_some() {
                    self.decoder = SignedBufferDecoder::new(self.decoder.s, self.offset);
                }
            },
            Err(e) => {
                self.decoder = SignedBufferDecoder::new(self.decoder.s, self.offset);
            }
        }

        ret
    }
}

struct SignedBufferDecoder<'a, H: 'a> {
    s: &'a SignedBuffer<'a, H>,
    state: State,
    offset: usize,
    hasher: H
}

impl<'a, H> SignedBufferDecoder<'a, H> where H: Hasher + Default {
    fn new(s: &'a SignedBuffer<'a, H>, offset: usize) -> Self {
        SignedBufferDecoder {
            s: s,
            state: State::Header { remaining: s.header_magic_bytes.len() },
            offset: offset,
            hasher: Default::default()
        }
    }

    fn read_byte(&mut self, byte: u8) -> Result<(), RetrievalError> {
        self.state = try!(self.process_state(byte));
        self.offset += 1;        
        Ok(())
    }

    fn process_state(&mut self, byte: u8) -> Result<State, RetrievalError> {
        match self.state {
            State::Header { remaining } => {
                if byte == self.s.header_magic_bytes[self.s.header_magic_bytes.len() - remaining] {
                    if remaining == 1 {
                        Ok(State::Checksum { bytes: [0; 13], remaining: 13 })
                    } else {
                        Ok(State::Header { remaining: remaining - 1 })
                    }
                } else {
                    Err(RetrievalError::InvalidHeader)
                }
            },
            State::Checksum { mut bytes, remaining } => {
                let idx = bytes.len() - remaining;
                bytes[idx] = byte;
                
                if remaining == 1 {
                    if let Ok(checksum) = BufferChecksum::unpack(&bytes) {
                        if checksum.version > self.s.version() {
                            return Err(RetrievalError::UnsupportedVersion { received_version: checksum.version });
                        }
                        if checksum.size == 0 {
                            return Err(RetrievalError::EmptyPayloadSize);
                        }

                        self.hasher.write_u8(checksum.version);
                        self.hasher.write_u32(checksum.size);
                        
                        Ok(State::Payload { checksum: checksum, start_offset: self.offset + 1, remaining: checksum.size as usize })
                    } else {
                        Err(RetrievalError::InvalidChecksumStruct)
                    }
                } else {
                    Ok(State::Checksum { bytes: bytes, remaining: remaining - 1})
                }
            },
            State::Payload { checksum, start_offset, remaining } => {
                self.hasher.write_u8(byte);

                if remaining == 1 {
                    Ok(State::Trailer { checksum: checksum, payload_offset: start_offset, remaining: self.s.trailer_magic_bytes.len() })
                } else {
                    Ok(State::Payload { checksum: checksum, start_offset: start_offset, remaining: remaining - 1 })
                }
            },
            State::Trailer { checksum, payload_offset, remaining } => {
                if byte == self.s.trailer_magic_bytes[self.s.trailer_magic_bytes.len() - remaining] {
                    if remaining == 1 {
                        
                        let payload = payload_offset..payload_offset + (checksum.size as usize);

                        if self.hasher.finish() != checksum.checksum {
                            return Err(RetrievalError::InvalidHash);
                        }
                        if payload.len() != checksum.size as usize {
                            return Err(RetrievalError::InvalidBufferSize);
                        }                        

                        Ok(State::Finished {
                            checksum: checksum,
                            payload: payload
                        })
                    } else {
                        Ok(State::Trailer { checksum: checksum, payload_offset: payload_offset, remaining: remaining - 1 })
                    }
                } else {
                    Err(RetrievalError::InvalidTrailer)
                }
            },
            State::Finished {..} => {
                Err(RetrievalError::TooMuchData)
            }
        }
    }
}

#[derive(Clone, PartialEq)]
enum State {
    Header { remaining: usize },
    Checksum { bytes: [u8; 13], remaining: usize },
    Payload { checksum: BufferChecksum, start_offset: usize, remaining: usize },
    Trailer { checksum: BufferChecksum, payload_offset: usize, remaining: usize },
    Finished { checksum: BufferChecksum, payload: Range<usize> }
}

impl<'a> SignedBuffer<'a, SipHasher24> {
    pub fn new_sip24(size: BufferSize, header: &'a [u8], trailer: &'a [u8]) -> Result<Self, SignedBufferError> {
        Self::new(size, header, trailer)
    }
}
