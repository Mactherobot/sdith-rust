//! # Utilities
//! This module contains the utilities used in the SDitH protocol.
//! 
//! - [`iterator`]: Contains the functions for iterating over the data. Uses feature flags to enable parallel iterations
//! - [`marshalling`]: Contains the trait and test function for serializing and deserializing data.

pub(crate) mod iterator;
pub mod marshalling;
