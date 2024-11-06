// TODO: Implement the Marshalling trait for all the types that need to be serialised and deserialised

pub trait Marshalling
where
    Self: Sized,
{
    fn serialise(&self) -> Vec<u8>;
    fn parse(serialised: &Vec<u8>) -> Result<Self, String>;
}
