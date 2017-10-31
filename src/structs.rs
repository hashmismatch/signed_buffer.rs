use prelude::v1::*;


#[derive(Copy, Clone, Debug, PartialEq, PackedStruct)]
#[packed_struct(bit_numbering="msb0", size_bytes="13", endian="msb")]
pub struct BufferChecksum {
    #[packed_field(bytes="0")]
	pub version: u8,
    #[packed_field(bytes="1..4")]
    pub size: u32,
    #[packed_field(bytes="5..12")]
    pub checksum: u64
}

