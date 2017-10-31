#![cfg_attr(not(feature = "std"), no_std)]

#![cfg_attr(not(feature="std"), feature(alloc))]

#[cfg(not(feature="std"))]
#[macro_use]
extern crate alloc;

mod prelude;

use prelude::v1::*;

mod base;
mod sign;
mod structs;

pub use base::*;
pub use sign::*;

extern crate siphasher;


extern crate packed_struct;
#[macro_use]
extern crate packed_struct_codegen;