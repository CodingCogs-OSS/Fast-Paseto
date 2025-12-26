//! Pre-Authentication Encoding (PAE) implementation
//!
//! PAE is used to prevent canonicalization attacks by encoding multiple
//! pieces of data in a way that ensures unique parsing.
//!
//! Format: LE64(count) || LE64(len(p1)) || p1 || LE64(len(p2)) || p2 || ...

/// Pre-Authentication Encoding implementation
pub struct Pae;

impl Pae {
    /// Encode multiple pieces using PAE
    ///
    /// # Arguments
    /// * `pieces` - Slice of byte slices to encode
    ///
    /// # Returns
    /// * `Vec<u8>` - PAE-encoded output
    ///
    /// # Format
    /// The output format is:
    /// - First 8 bytes: count of pieces as 64-bit little-endian unsigned integer
    /// - For each piece: 8 bytes of length (LE64) followed by the piece data
    ///
    /// # Example
    /// ```
    /// use fast_paseto::pae::Pae;
    ///
    /// let pieces: &[&[u8]] = &[b"hello", b"world"];
    /// let encoded = Pae::encode(pieces);
    ///
    /// // Count (2) as LE64 + len("hello") as LE64 + "hello" + len("world") as LE64 + "world"
    /// // = 8 + 8 + 5 + 8 + 5 = 34 bytes
    /// assert_eq!(encoded.len(), 34);
    /// ```
    pub fn encode(pieces: &[&[u8]]) -> Vec<u8> {
        // Calculate total output size for pre-allocation
        // 8 bytes for count + (8 bytes for length + piece data) for each piece
        let total_size = 8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>();
        let mut output = Vec::with_capacity(total_size);

        // Encode count as 64-bit little-endian
        output.extend_from_slice(&(pieces.len() as u64).to_le_bytes());

        // Encode each piece: length (LE64) followed by data
        for piece in pieces {
            output.extend_from_slice(&(piece.len() as u64).to_le_bytes());
            output.extend_from_slice(piece);
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_pae_empty_pieces() {
        let pieces: &[&[u8]] = &[];
        let encoded = Pae::encode(pieces);

        // Should just be count (0) as LE64
        assert_eq!(encoded.len(), 8);
        assert_eq!(&encoded[..8], &0u64.to_le_bytes());
    }

    #[test]
    fn test_pae_single_piece() {
        let pieces: &[&[u8]] = &[b"test"];
        let encoded = Pae::encode(pieces);

        // Count (1) + len(4) + "test" = 8 + 8 + 4 = 20 bytes
        assert_eq!(encoded.len(), 20);

        // Verify count
        assert_eq!(&encoded[0..8], &1u64.to_le_bytes());

        // Verify length of first piece
        assert_eq!(&encoded[8..16], &4u64.to_le_bytes());

        // Verify piece data
        assert_eq!(&encoded[16..20], b"test");
    }

    #[test]
    fn test_pae_multiple_pieces() {
        let pieces: &[&[u8]] = &[b"hello", b"world"];
        let encoded = Pae::encode(pieces);

        // Count (2) + len(5) + "hello" + len(5) + "world" = 8 + 8 + 5 + 8 + 5 = 34 bytes
        assert_eq!(encoded.len(), 34);

        // Verify count
        assert_eq!(&encoded[0..8], &2u64.to_le_bytes());

        // Verify first piece length
        assert_eq!(&encoded[8..16], &5u64.to_le_bytes());

        // Verify first piece data
        assert_eq!(&encoded[16..21], b"hello");

        // Verify second piece length
        assert_eq!(&encoded[21..29], &5u64.to_le_bytes());

        // Verify second piece data
        assert_eq!(&encoded[29..34], b"world");
    }

    #[test]
    fn test_pae_empty_piece() {
        let pieces: &[&[u8]] = &[b""];
        let encoded = Pae::encode(pieces);

        // Count (1) + len(0) = 8 + 8 = 16 bytes
        assert_eq!(encoded.len(), 16);

        // Verify count
        assert_eq!(&encoded[0..8], &1u64.to_le_bytes());

        // Verify length of empty piece
        assert_eq!(&encoded[8..16], &0u64.to_le_bytes());
    }

    #[test]
    fn test_pae_total_length_formula() {
        // Verify the total length formula: 8 + sum(8 + len(piece) for each piece)
        let pieces: &[&[u8]] = &[b"a", b"bb", b"ccc"];
        let encoded = Pae::encode(pieces);

        let expected_len = 8 + (8 + 1) + (8 + 2) + (8 + 3);
        assert_eq!(encoded.len(), expected_len);
    }

    // **Feature: paseto-implementation, Property 13: PAE Encoding Correctness**
    // **Validates: Requirements 8.3, 8.4**
    //
    // For any list of byte arrays (pieces), the PAE encoding SHALL produce output where:
    // - The first 8 bytes are the count of pieces as a 64-bit little-endian unsigned integer
    // - For each piece, 8 bytes of length (LE64) followed by the piece data
    // - The total length equals 8 + sum(8 + len(piece) for each piece)
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_pae_encoding_correctness(pieces in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 0..10)) {
            // Convert Vec<Vec<u8>> to Vec<&[u8]> for the encode function
            let piece_refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
            let encoded = Pae::encode(&piece_refs);

            // Property 1: First 8 bytes are the count as LE64
            let count_bytes: [u8; 8] = encoded[0..8].try_into().unwrap();
            let count = u64::from_le_bytes(count_bytes);
            prop_assert_eq!(count, pieces.len() as u64, "Count mismatch");

            // Property 2: Total length equals 8 + sum(8 + len(piece) for each piece)
            let expected_len: usize = 8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>();
            prop_assert_eq!(encoded.len(), expected_len, "Total length mismatch");

            // Property 3: For each piece, verify length prefix and data
            let mut offset = 8; // Start after count
            for (i, piece) in pieces.iter().enumerate() {
                // Read length prefix (LE64)
                let len_bytes: [u8; 8] = encoded[offset..offset + 8].try_into().unwrap();
                let piece_len = u64::from_le_bytes(len_bytes);
                prop_assert_eq!(piece_len, piece.len() as u64, "Piece {} length mismatch", i);
                offset += 8;

                // Verify piece data
                prop_assert_eq!(&encoded[offset..offset + piece.len()], piece.as_slice(), "Piece {} data mismatch", i);
                offset += piece.len();
            }

            // Verify we consumed all bytes
            prop_assert_eq!(offset, encoded.len(), "Did not consume all encoded bytes");
        }
    }
}
