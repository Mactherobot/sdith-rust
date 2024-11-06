use std::fmt::Debug;

// TODO: Flip row and column naming. array[[[0u8; rows]; cols]; depth] to array[[[0u8; cols]; rows]; depth]

#[derive(Debug, Clone)]
pub(crate) struct Array2D<T> {
    rows: usize,
    columns: usize,
    data: Vec<T>,
}

#[derive(PartialEq)]
pub(crate) struct Array3D {
    rows: usize,
    columns: usize,
    depth: usize,
    data: Vec<u8>,
}

/// Trait for 2D arrays
pub(crate) trait Array2DTrait<T> {
    /// Creates a new Array2D instance
    /// `vec![vec![0u8; cols]; rows]``
    fn new(cols: usize, rows: usize) -> Self;
    /// Creates a new Array2D instance from a byte array
    /// array[[data];cols]
    fn from_bytes(cols: usize, rows: usize, data: &[T]) -> Self;
    /// Gets the value at a given column and row
    fn get(&self, row: usize, col: usize) -> T;
    /// Gets the inner slice of the array based on the column
    fn get_row(&self, row: usize) -> &[T];
    fn get_row_mut(&mut self, row: usize) -> &mut [T];
    /// Gets the last inner slice of the array
    fn last_row_mut(&mut self) -> &mut [T];
    /// Gets the length of the array
    fn row_len(&self) -> usize;
    /// Sets the value at a given column and row
    fn set(&mut self, row: usize, col: usize, val: T);
    /// Sets the inner slice of the array based on the column
    fn set_row_slice(&mut self, row: usize, val: &[T]);
    /// Converts the array to a byte array
    fn to_bytes(&self) -> &[T];
    fn iter_cols(&self) -> std::slice::ChunksExact<'_, T>;
}

/// Impl of the Array2DTrait for the Array2D struct
impl<T> Array2DTrait<T> for Array2D<T>
where
    T: Default + Clone + Copy,
{
    fn new(columns: usize, rows: usize) -> Self {
        Self {
            rows,
            columns,
            data: vec![T::default(); rows * columns],
        }
    }

    fn from_bytes(columns: usize, rows: usize, data: &[T]) -> Self {
        assert_eq!(
            rows * columns,
            data.len(),
            "Data length does not match dimensions"
        );

        Self {
            rows,
            columns,
            data: data.to_vec(),
        }
    }

    fn iter_cols(&self) -> std::slice::ChunksExact<'_, T> {
        self.data.chunks_exact(self.columns)
    }

    fn get(&self, row: usize, col: usize) -> T {
        assert!(row < self.rows && col < self.columns, "Index out of bounds");
        self.data[row * self.columns + col]
    }

    fn get_row(&self, row: usize) -> &[T] {
        assert!(row < self.rows, "Column out of bounds");
        let start = row * self.columns;
        &self.data[start..start + self.columns]
    }

    fn get_row_mut(&mut self, row: usize) -> &mut [T] {
        assert!(row < self.rows, "Row out of bounds");
        let start = row * self.columns;
        &mut self.data[start..start + self.columns]
    }

    fn set(&mut self, row: usize, col: usize, val: T) {
        assert!(row < self.rows && col < self.columns, "Index out of bounds");
        self.data[row * self.columns + col] = val;
    }

    fn set_row_slice(&mut self, row: usize, val: &[T]) {
        assert_eq!(
            val.len(),
            self.columns,
            "Slice length does not match columns"
        );
        assert!(row < self.rows, "Row out of bounds");
        let start = row * self.columns;
        self.data[start..start + self.columns].copy_from_slice(val);
    }

    fn last_row_mut(&mut self) -> &mut [T] {
        &mut self.data[(self.rows - 1) * self.columns..]
    }

    fn row_len(&self) -> usize {
        self.rows
    }

    fn to_bytes(&self) -> &[T] {
        &self.data
    }
}

impl<T> PartialEq<Vec<Vec<T>>> for Array2D<T>
where
    Self: Array2DTrait<T>,
    T: std::cmp::PartialEq,
{
    fn eq(&self, other: &Vec<Vec<T>>) -> bool {
        self.iter_cols()
            .enumerate()
            .all(|(i, col)| col == &other[i])
    }
}

impl<T> PartialEq<Array2D<T>> for Array2D<T>
where
    T: std::cmp::PartialEq,
{
    fn eq(&self, other: &Array2D<T>) -> bool {
        self.data == other.data && self.rows == other.rows && self.columns == other.columns
    }
}

/// Trait for 3D arrays
pub(crate) trait Array3DTrait {
    /// Creates a 3D Array
    /// array[[[0u8; cols]; rows]; depth]
    fn new(cols: usize, rows: usize, depth: usize) -> Self;
    /// Gets the value at a given `array[depth][col][row]`
    fn get(&self, depth: usize, row: usize, col: usize) -> u8;
    /// Gets the inner slice of the array based on the depth and column
    /// equivalent to array[depth][row]
    fn get_row_slice(&self, depth: usize, row: usize) -> &[u8];
    fn get_row_slice_mut(&mut self, depth: usize, row: usize) -> &mut [u8];
    /// Sets the value at a given array[depth][row][col]
    fn set(&mut self, depth: usize, row: usize, col: usize, val: u8);
    /// Sets the inner slice of the array based on the depth and column
    /// equivalent to array[depth][col]
    fn set_row_slice(&mut self, depth: usize, row: usize, val: &[u8]);
    /// Converts the array to a byte array
    fn to_bytes(&self) -> &[u8];
    fn get_last_row_slice(&self, depth: usize) -> &[u8];
}

/// Impl of the Array3DTrait for the Array3D struct
impl Array3DTrait for Array3D {
    fn new(columns: usize, rows: usize, depth: usize) -> Self {
        Self {
            rows,
            columns,
            depth,
            data: vec![0u8; rows * columns * depth],
        }
    }

    fn get(&self, depth: usize, row: usize, col: usize) -> u8 {
        assert!(
            depth < self.depth && row < self.rows && col < self.columns,
            "Index out of bounds"
        );
        self.data[depth * self.rows * self.columns + row * self.columns + col]
    }

    fn get_row_slice(&self, depth: usize, row: usize) -> &[u8] {
        assert!(depth < self.depth && row < self.rows, "Index out of bounds");
        let start = depth * self.rows * self.columns + row * self.columns;
        &self.data[start..start + self.columns]
    }

    fn get_row_slice_mut(&mut self, depth: usize, row: usize) -> &mut [u8] {
        assert!(depth < self.depth && row < self.rows, "Index out of bounds");
        let start = depth * self.rows * self.columns + row * self.columns;
        &mut self.data[start..start + self.columns]
    }

    fn set(&mut self, depth: usize, row: usize, col: usize, val: u8) {
        assert!(
            depth < self.depth && row < self.rows && col < self.columns,
            "Index out of bounds"
        );
        self.data[depth * self.rows * self.columns + row * self.columns + col] = val;
    }

    fn set_row_slice(&mut self, depth: usize, row: usize, val: &[u8]) {
        assert_eq!(
            val.len(),
            self.columns,
            "Slice length does not match columns"
        );
        assert!(depth < self.depth && row < self.rows, "Index out of bounds");
        let start = depth * self.rows * self.columns + row * self.columns;
        self.data[start..start + self.columns].copy_from_slice(val);
    }

    fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    fn get_last_row_slice(&self, depth: usize) -> &[u8] {
        self.get_row_slice(depth, self.rows - 1)
    }
}

impl Debug for Array3D {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print the 3D array as a list of 2D matrices
        writeln!(f, "Array3D: {}x{}x{}", self.rows, self.columns, self.depth)?;
        for i in 0..self.depth {
            write!(f, "[")?;
            for j in 0..self.columns {
                write!(f, "{:?}", self.get_row_slice(i, j))?;
                if (j + 1) < self.columns {
                    write!(f, ", ")?;
                }
            }
            write!(f, "]")?;
            if (i + 1) < self.depth {
                writeln!(f, ", ")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod array_tests_2d {
    use super::*;

    fn setup() -> Array2D<u8> {
        let mut array = Array2D::new(2, 3);

        for i in 0..3 {
            array.set(i, 0, i as u8 + 1);
            array.set(i, 1, i as u8 + 4);
        }

        array
    }

    #[test]
    fn test_basics() {
        // First test the 2D array basics
        let array = setup();

        for i in 0..3 {
            assert_eq!(array.get(i, 0), i as u8 + 1);
            assert_eq!(array.get(i, 1), i as u8 + 4);
        }
    }

    #[test]
    fn test_cols() {
        // Check that get inner returns the columns data
        let mut array = setup();

        let inner = array.get_row(0);
        assert_eq!(inner, vec![1, 4]);
        let inner = array.get_row(1);
        assert_eq!(inner, vec![2, 5]);
        let last_inner = array.last_row_mut();
        assert_eq!(last_inner, vec![3, 6]);
    }

    #[test]
    fn test_to_bytes() {
        let array = setup();
        // Check that the to_bytes returns a byte array
        let bytes = array.to_bytes();
        assert_eq!(bytes, vec![1, 4, 2, 5, 3, 6]);

        let array = super::Array2D::<u8>::new(2, 2);
        assert_eq!(array.row_len(), 2);

        let array = super::Array2D::<u8>::new(3, 3);
        assert_eq!(array.row_len(), 3);
    }

    #[test]
    fn test_get_row_mut() {
        let mut array = setup();

        let col = array.get_row_mut(0);
        col[0] = 3;
        col[1] = 6;
        assert_eq!(array.get(0, 0), 3);
        assert_eq!(array.get(0, 1), 6);

        let col = array.get_row_mut(2);
        col[0] = 5;
        col[1] = 8;
        assert_eq!(array.get(2, 0), 5);
        assert_eq!(array.get(2, 1), 8);
    }
}

#[cfg(test)]
mod array_tests_3d {
    use super::*;

    fn setup() -> Array3D {
        let mut array = Array3D::new(2, 3, 4);
        // Check the set method
        for i in 0..4 {
            for j in 0..3 {
                array.set(i, j, 0, i as u8 + j as u8 + 1);
                array.set(i, j, 1, i as u8 + j as u8 + 5);
            }
        }
        array
    }

    #[test]
    fn test_get() {
        let array = setup();

        // Check length
        assert_eq!(array.to_bytes().len(), 24);

        // Check the get method
        for i in 0..4 {
            for j in 0..3 {
                assert_eq!(array.get(i, j, 0), i as u8 + j as u8 + 1);
                assert_eq!(array.get(i, j, 1), i as u8 + j as u8 + 5);
            }
        }
    }

    #[test]
    fn test_get_last_row() {
        let array = setup();

        assert_eq!(array.get_last_row_slice(0), vec![3, 7]);
        assert_eq!(array.get_last_row_slice(1), vec![4, 8]);
        assert_eq!(array.get_last_row_slice(2), vec![5, 9]);
        assert_eq!(array.get_last_row_slice(3), vec![6, 10]);
    }

    #[test]
    fn test_get_row() {
        let array = setup();

        // Check the get_inner_array method
        let inner = array.get_row_slice(0, 0);
        assert_eq!(inner, vec![1, 5]);
        let inner = array.get_row_slice(3, 2);
        assert_eq!(inner, vec![6, 10]);
    }

    #[test]
    fn test_set_row_slice() {
        let mut array = setup();

        // Check the set_inner_array method
        array.set_row_slice(0, 0, &[3, 7]);
        assert_eq!(array.get(0, 0, 0), 3);
        assert_eq!(array.get(0, 0, 1), 7);

        array.set_row_slice(1, 2, &[4, 8]);
        assert_eq!(array.get(1, 2, 0), 4);
        assert_eq!(array.get(1, 2, 1), 8);
    }

    #[test]
    fn test_get_row_mut() {
        let mut array = setup();

        // Check the get_inner_array method
        let row = array.get_row_slice_mut(0, 0);
        assert_eq!(row, vec![1, 5]);
        row[0] = 3;
        row[1] = 7;
        assert_eq!(array.get(0, 0, 0), 3);
        assert_eq!(array.get(0, 0, 1), 7);

        let row = array.get_row_slice_mut(3, 2);
        assert_eq!(row, vec![6, 10]);
        row[0] = 4;
        row[1] = 8;
        assert_eq!(array.get(3, 2, 0), 4);
        assert_eq!(array.get(3, 2, 1), 8);
    }
}
