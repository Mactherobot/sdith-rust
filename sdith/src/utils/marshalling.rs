//! Marshalling module for serialising and deserialising types

/// Trait for serialising and deserialising types
pub trait Marshalling<S>
where
    Self: Sized,
{
    /// Serialise the type into an array of bytes
    fn serialise(&self) -> S;
    /// Parse the type from an array of bytes
    fn parse(serialised: &S) -> Result<Self, String>;
}

/// Test the marshalling of a type
#[cfg(test)]
pub(crate) fn test_marhalling<T, S>(value: T, changed_value: T)
where
    T: Marshalling<S> + std::fmt::Debug + Eq,
    S: std::cmp::PartialEq + std::fmt::Debug,
{
    // Positive test: Check that d = parse(serialise(d))
    // Serialise the value
    let serialised_value = value.serialise();
    // Parse the serialised value
    let parsed = T::parse(&serialised_value).unwrap();
    // Check if the parsed value is equal to the original value
    assert_eq!(value, parsed);

    // Negative test: Ensure that d != parse(serialise(d')) if d' != d
    assert_ne!(changed_value, value);

    let serialised_changed_value = changed_value.serialise();
    assert_ne!(serialised_changed_value, serialised_value);

    let parsed = T::parse(&serialised_changed_value).unwrap();
    assert_ne!(value, parsed);
}
