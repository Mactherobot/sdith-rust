#![allow(unused)]
//! Iterator utilities for parallel and sequential iterators according to the feature flag `parallel`

#[cfg(feature = "parallel")]
pub use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};

#[cfg(not(feature = "parallel"))]
/// Get an iterator for the array
pub(crate) fn get_iterator_mut<V>(array: &mut [V]) -> std::slice::IterMut<'_, V> {
    array.iter_mut()
}

#[cfg(feature = "parallel")]
/// Get parallel iterator for the array
pub(crate) fn get_iterator_mut<V: Send>(array: &mut [V]) -> rayon::slice::IterMut<'_, V> {
    array.par_iter_mut()
}

#[cfg(not(feature = "parallel"))]
/// Get an iterator for the array
pub(crate) fn get_iterator<V>(array: &mut [V]) -> std::slice::Iter<'_, V> {
    array.iter()
}

#[cfg(feature = "parallel")]
/// Get parallel iterator for the array
pub(crate) fn get_iterator<V: Sync>(array: &[V]) -> rayon::slice::Iter<'_, V> {
    array.into_par_iter()
}
