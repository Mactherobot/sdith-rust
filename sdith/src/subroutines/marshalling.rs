//! Marshalling module for serialising and deserialising types

use std::fmt::Debug;

/// Trait for serialising and deserialising types
pub trait Marshalling<S>
where
    Self: Sized,
{
    fn serialise(&self) -> S;
    fn parse(serialised: &S) -> Result<Self, String>;
}

pub(crate) fn test_marhalling<T, S>(value: T, changed_value: T)
where
    T: Marshalling<S> + Debug + Eq,
{
    // Serialise the value
    let serialised = value.serialise();
    // Parse the serialised value
    let parsed = T::parse(&serialised).unwrap();
    // Check if the parsed value is equal to the original value
    assert_eq!(value, parsed);

    // Negative test: Check if the parsed value is not equal to the original value
    assert_ne!(changed_value, value);

    let serialised = changed_value.serialise();
    let parsed = T::parse(&serialised).unwrap();
    assert_eq!(changed_value, parsed);
    assert_ne!(value, parsed);
}
