//! Generated guest ELF images and deterministic image IDs.
//!
//! `risc0_build::embed_methods` writes `methods.rs` into OUT_DIR at build
//! time after compiling each reviewed guest with the RISC Zero toolchain.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
