use std::fmt::Debug;

use base64::write;

#[derive(Debug, Clone)]
pub(crate) struct Array2D {
    rows: usize,
    columns: usize,
    data: Vec<u8>,
}

#[derive(PartialEq)]
pub(crate) struct Array3D {
    rows: usize,
    columns: usize,
    depth: usize,
    data: Vec<u8>,
}

/// Trait for 2D arrays
pub(crate) trait Array2DTrait {
    /// Creates a new Array2D instance
    /// `vec![vec![0u8; rows]; cols]``
    fn new(rows: usize, cols: usize) -> Self;
    /// Creates a new Array2D instance from a byte array
    /// array[[data];cols]
    fn from_bytes(rows: usize, cols: usize, data: &[u8]) -> Self;
    /// Gets the value at a given column and row
    fn get(&self, col: usize, row: usize) -> u8;
    /// Gets the inner slice of the array based on the column
    fn get_col(&self, col: usize) -> &[u8];
    /// Gets the last inner slice of the array
    fn last_col_mut(&mut self) -> &mut [u8];
    /// Gets the length of the array
    fn col_len(&self) -> usize;
    /// Sets the value at a given column and row
    fn set(&mut self, col: usize, row: usize, val: u8);
    /// Sets the inner slice of the array based on the column
    fn set_col_slice(&mut self, col: usize, val: &[u8]);
    /// Converts the array to a byte array
    fn to_bytes(&self) -> &[u8];
}

/// Impl of the Array2DTrait for the Array2D struct
impl Array2DTrait for Array2D {
    fn new(rows: usize, columns: usize) -> Self {
        Self {
            rows,
            columns,
            data: vec![0u8; rows * columns],
        }
    }

    fn from_bytes(rows: usize, cols: usize, data: &[u8]) -> Self {
        assert_eq!(
            rows * cols,
            data.len(),
            "Data length does not match dimensions"
        );
        Self {
            rows,
            columns: cols,
            data: data.to_vec(),
        }
    }

    fn get(&self, col: usize, row: usize) -> u8 {
        assert!(row < self.rows && col < self.columns, "Index out of bounds");
        self.data[col * self.rows + row]
    }

    fn get_col(&self, col: usize) -> &[u8] {
        assert!(col < self.columns, "Column out of bounds");
        let start = col * self.rows;
        &self.data[start..start + self.rows]
    }

    fn set(&mut self, col: usize, row: usize, val: u8) {
        assert!(row < self.rows && col < self.columns, "Index out of bounds");
        self.data[col * self.rows + row] = val;
    }

    fn set_col_slice(&mut self, col: usize, val: &[u8]) {
        assert_eq!(val.len(), self.rows, "Slice length does not match rows");
        assert!(col < self.columns, "Column out of bounds");
        let start = col * self.rows;
        self.data[start..start + self.rows].copy_from_slice(val);
    }

    fn last_col_mut(&mut self) -> &mut [u8] {
        &mut self.data[(self.columns - 1) * self.rows..]
    }

    fn col_len(&self) -> usize {
        self.columns
    }

    fn to_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Trait for 3D arrays
pub(crate) trait Array3DTrait {
    /// Creates a 3D Array
    /// array[[[0u8; rows]; cols]; depth]
    fn new(rows: usize, cols: usize, depth: usize) -> Self;
    /// Gets the value at a given `array[depth][col][row]`
    fn get(&self, depth: usize, col: usize, row: usize) -> u8;
    /// Gets the inner slice of the array based on the depth and column
    /// equivalent to array[depth][col]
    fn get_row_slice(&self, depth: usize, col: usize) -> &[u8];
    fn get_row_slice_mut(&mut self, depth: usize, col: usize) -> &mut [u8];
    /// Sets the value at a given array[depth][col][row]
    fn set(&mut self, depth: usize, col: usize, row: usize, val: u8);
    /// Sets the inner slice of the array based on the depth and column
    /// equivalent to array[depth][col]
    fn set_row_slice(&mut self, depth: usize, col: usize, val: &[u8]);
    /// Converts the array to a byte array
    fn to_bytes(&self) -> &[u8];
    fn get_last_row_slice(&self, depth: usize) -> &[u8];
}

/// Impl of the Array3DTrait for the Array3D struct
impl Array3DTrait for Array3D {
    fn new(rows: usize, columns: usize, depth: usize) -> Self {
        Self {
            rows,
            columns,
            depth,
            data: vec![0u8; rows * columns * depth],
        }
    }

    fn get(&self, depth: usize, col: usize, row: usize) -> u8 {
        assert!(
            depth < self.depth && row < self.rows && col < self.columns,
            "Index out of bounds"
        );
        self.data[depth * self.rows * self.columns + col * self.rows + row]
    }

    fn get_row_slice(&self, depth: usize, col: usize) -> &[u8] {
        assert!(
            depth < self.depth && col < self.columns,
            "Index out of bounds"
        );
        let start = depth * self.rows * self.columns + col * self.rows;
        &self.data[start..start + self.rows]
    }

    fn get_row_slice_mut(&mut self, depth: usize, col: usize) -> &mut [u8] {
        assert!(
            depth < self.depth && col < self.columns,
            "Index out of bounds"
        );
        let start = depth * self.rows * self.columns + col * self.rows;
        &mut self.data[start..start + self.rows]
    }

    fn set(&mut self, depth: usize, col: usize, row: usize, val: u8) {
        assert!(
            depth < self.depth && row < self.rows && col < self.columns,
            "Index out of bounds"
        );
        self.data[depth * self.rows * self.columns + col * self.rows + row] = val;
    }

    fn set_row_slice(&mut self, depth: usize, col: usize, val: &[u8]) {
        assert_eq!(val.len(), self.rows, "Slice length does not match rows");
        assert!(
            depth < self.depth && col < self.columns,
            "Index out of bounds"
        );
        let start = depth * self.rows * self.columns + col * self.rows;
        self.data[start..start + self.rows].copy_from_slice(val);
    }

    fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    fn get_last_row_slice(&self, depth: usize) -> &[u8] {
        self.get_row_slice(depth, self.columns - 1)
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

    fn setup() -> Array2D {
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

        let inner = array.get_col(0);
        assert_eq!(inner, vec![1, 4]);
        let inner = array.get_col(1);
        assert_eq!(inner, vec![2, 5]);
        let last_inner = array.last_col_mut();
        assert_eq!(last_inner, vec![3, 6]);
    }

    #[test]
    fn test_to_bytes() {
        let array = setup();
        // Check that the to_bytes returns a byte array
        let bytes = array.to_bytes();
        assert_eq!(bytes, vec![1, 4, 2, 5, 3, 6]);

        let array = super::Array2D::new(2, 2);
        assert_eq!(array.col_len(), 2);

        let array = super::Array2D::new(3, 3);
        assert_eq!(array.col_len(), 3);
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
