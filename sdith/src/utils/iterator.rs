#[cfg(feature = "parallel")]
pub(crate) use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

#[cfg(not(feature = "parallel"))]
/// Get an iterator for the array
pub(crate) fn get_iterator<V>(array: &mut [V]) -> std::slice::IterMut<'_, V> {
    array.iter_mut()
}

#[cfg(feature = "parallel")]
/// Get parallel iterator for the array
pub(crate) fn get_iterator<V: Send>(array: &mut [V]) -> rayon::slice::IterMut<'_, V> {
    array.par_iter_mut()
}
