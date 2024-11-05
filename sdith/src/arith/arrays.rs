#[derive(Debug, Clone)]
pub(crate) struct Array2D {
    rows: usize,
    columns: usize,
    data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct Array3D {
    rows: usize,
    columns: usize,
    depth: usize,
    data: Vec<u8>,
}

/// Trait for 2D arrays
pub(crate) trait Array2DTrait {
    fn new(rows: usize, cols: usize) -> Self;
    fn from_bytes(rows: usize, cols: usize, data: &[u8]) -> Self;
    fn get(&self, col: usize, row: usize) -> u8;
    fn get_inner(&self, col: usize) -> &[u8];
    fn last_inner(&mut self) -> &mut [u8];
    fn len(&self) -> usize;
    fn set(&mut self, col: usize, row: usize, val: u8);
    fn set_inner_slice(&mut self, col: usize, val: &[u8]);
    fn to_bytes(&self) -> &[u8];
}

/// Impl of the Array2DTrait for the Array2D struct
impl Array2DTrait for Array2D {
    /// Creates a new Array2D instance
    /// array[[0u8; rows];cols]
    fn new(rows: usize, columns: usize) -> Self {
        Self {
            rows,
            columns,
            data: vec![0u8; rows * columns],
        }
    }

    /// Creates a new Array2D instance from a byte array
    /// array[[data];cols]
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

    /// Gets the value at a given column and row
    fn get(&self, col: usize, row: usize) -> u8 {
        assert!(row < self.rows && col < self.columns, "Index out of bounds");
        self.data[col * self.rows + row]
    }

    /// Gets the inner slice of the array based on the column
    fn get_inner(&self, col: usize) -> &[u8] {
        assert!(col < self.columns, "Column out of bounds");
        let start = col * self.rows;
        &self.data[start..start + self.rows]
    }

    /// Sets the value at a given column and row
    fn set(&mut self, col: usize, row: usize, val: u8) {
        assert!(row < self.rows && col < self.columns, "Index out of bounds");
        self.data[col * self.rows + row] = val;
    }

    /// Sets the inner slice of the array based on the column
    fn set_inner_slice(&mut self, col: usize, val: &[u8]) {
        assert_eq!(val.len(), self.rows, "Slice length does not match rows");
        assert!(col < self.columns, "Column out of bounds");
        let start = col * self.rows;
        self.data[start..start + self.rows].copy_from_slice(val);
    }

    /// Gets the last inner slice of the array
    fn last_inner(&mut self) -> &mut [u8] {
        &mut self.data[(self.columns - 1) * self.rows..]
    }

    /// Gets the length of the array
    fn len(&self) -> usize {
        self.columns
    }

    /// Converts the array to a byte array
    fn to_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Trait for 3D arrays
pub(crate) trait Array3DTrait {
    fn new(rows: usize, cols: usize, depth: usize) -> Self;
    fn get(&self, depth: usize, col: usize, row: usize) -> u8;
    fn get_2d(&self, depth: usize) -> Array2D;
    fn get_inner_slice(&self, depth: usize, col: usize) -> &[u8];
    fn set(&mut self, depth: usize, col: usize, row: usize, val: u8);
    fn set_inner_slice(&mut self, depth: usize, col: usize, val: &[u8]);
    fn to_bytes(&self) -> &[u8];
}

/// Impl of the Array3DTrait for the Array3D struct
impl Array3DTrait for Array3D {
    /// Creates a 3D Array
    /// array[[[0u8; rows]; cols]; depth]
    fn new(rows: usize, columns: usize, depth: usize) -> Self {
        Self {
            rows,
            columns,
            depth,
            data: vec![0u8; rows * columns * depth],
        }
    }

    /// Gets the value at a given array[depth][col][row]
    fn get(&self, depth: usize, col: usize, row: usize) -> u8 {
        assert!(
            depth < self.depth && row < self.rows && col < self.columns,
            "Index out of bounds"
        );
        self.data[depth * self.rows * self.columns + col * self.rows + row]
    }

    // TODO: Maybe do this in a better way by having the 2D array just point to the 3D array
    // instead of copying
    /// Gets the 2D array at a given depth equivalent to:
    /// array[0] where array is a 3D array[[[0u8; rows]; cols]; depth]
    fn get_2d(&self, depth: usize) -> Array2D {
        assert!(depth < self.depth, "Depth out of bounds");
        let start = depth * self.rows * self.columns;
        let end = start + self.rows * self.columns;
        Array2D::from_bytes(self.rows, self.columns, &self.data[start..end])
    }

    /// Gets the inner slice of the array based on the depth and column
    /// equivalent to array[depth][col]
    fn get_inner_slice(&self, depth: usize, col: usize) -> &[u8] {
        assert!(
            depth < self.depth && col < self.columns,
            "Index out of bounds"
        );
        let start = depth * self.rows * self.columns + col * self.rows;
        &self.data[start..start + self.rows]
    }

    /// Sets the value at a given array[depth][col][row]
    fn set(&mut self, depth: usize, col: usize, row: usize, val: u8) {
        assert!(
            depth < self.depth && row < self.rows && col < self.columns,
            "Index out of bounds"
        );
        self.data[depth * self.rows * self.columns + col * self.rows + row] = val;
    }

    /// Sets the inner slice of the array based on the depth and column
    /// equivalent to array[depth][col]
    fn set_inner_slice(&mut self, depth: usize, col: usize, val: &[u8]) {
        assert_eq!(val.len(), self.rows, "Slice length does not match rows");
        assert!(
            depth < self.depth && col < self.columns,
            "Index out of bounds"
        );
        let start = depth * self.rows * self.columns + col * self.rows;
        self.data[start..start + self.rows].copy_from_slice(val);
    }

    /// Converts the array to a byte array
    fn to_bytes(&self) -> &[u8] {
        &self.data
    }
}
#[cfg(test)]
mod array_tests {
    use super::*;

    #[test]
    fn test_array2d() {
        // First test the 2D array basics
        let mut array = super::Array2D::new(2, 3);
        for i in 0..3 {
            array.set(i, 0, i as u8 + 1);
            array.set(i, 1, i as u8 + 4);
        }
        println!("{:?}", array);
        for i in 0..3 {
            assert_eq!(array.get(i, 0), i as u8 + 1);
            assert_eq!(array.get(i, 1), i as u8 + 4);
        }

        // Check that get inner returns the columns data
        let inner = array.get_inner(0);
        assert_eq!(inner, vec![1, 4]);
        let inner = array.get_inner(1);
        assert_eq!(inner, vec![2, 5]);
        let last_inner = array.last_inner();
        assert_eq!(last_inner, vec![3, 6]);

        // Check that the to_bytes returns a byte array
        let bytes = array.to_bytes();
        assert_eq!(bytes, vec![1, 4, 2, 5, 3, 6]);

        let array = super::Array2D::new(2, 2);
        assert_eq!(array.len(), 2);

        let array = super::Array2D::new(3, 3);
        assert_eq!(array.len(), 3);
    }

    #[test]
    fn test_array3d() {
        let mut array = super::Array3D::new(2, 3, 4);
        // Check the set method
        for i in 0..4 {
            for j in 0..3 {
                array.set(i, j, 0, i as u8 + j as u8 + 1);
                array.set(i, j, 1, i as u8 + j as u8 + 5);
            }
        }

        // Check length
        assert_eq!(array.to_bytes().len(), 24);

        // Check the get method
        for i in 0..4 {
            for j in 0..3 {
                assert_eq!(array.get(i, j, 0), i as u8 + j as u8 + 1);
                assert_eq!(array.get(i, j, 1), i as u8 + j as u8 + 5);
            }
        }

        // Check the get_2d method
        let inner = array.get_2d(0);
        println!("{:?}", inner);
        assert_eq!(inner.get(0, 0), 1);
        assert_eq!(inner.get(0, 1), 5);
        assert_eq!(inner.get(1, 0), 2);
        assert_eq!(inner.get(1, 1), 6);
        assert_eq!(inner.get(2, 0), 3);
        assert_eq!(inner.get(2, 1), 7);

        // Check the get_inner_array method
        let inner = array.get_inner_slice(0, 0);
        assert_eq!(inner, vec![1, 5]);
        let inner = array.get_inner_slice(0, 1);
        assert_eq!(inner, vec![2, 6]);

        // Check that set_inner_array fails if size is wrong
        array.set_inner_slice(0, 0, &[1, 2]);
        assert_eq!(array.get(0, 0, 0), 1);
        assert_eq!(array.get(0, 0, 1), 2);
    }
}
