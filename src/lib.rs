// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//! For explanation see https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm

use std::{
    fs::{create_dir, read_to_string, File},
    io::{Read, Result, Write},
    path::PathBuf,
};

/// Create a quote with given input
pub fn create_quote(input: [u8; 64]) -> Result<Vec<u8>> {
    let quote_name = bytes_to_hex(&input);
    let mut quote = OpenQuote::new(&quote_name)?;
    quote.write_input(input)?;
    quote.read_output()
}

/// Represents a pending quote
pub struct OpenQuote {
    path: PathBuf,
    expected_generation: u32,
}

impl OpenQuote {
    /// Create a new open quote
    pub fn new(quote_name: &str) -> Result<Self> {
        let mut quote_path = PathBuf::from("/sys/kernel/config/tsm/report");
        quote_path.push(quote_name);
        create_dir(quote_path.clone())?;
        Ok(Self {
            path: quote_path,
            expected_generation: 0,
        })
    }

    /// Write input data to quote
    pub fn write_input(&mut self, input: [u8; 64]) -> Result<()> {
        let mut inblob_path = self.path.clone();
        inblob_path.push("inblob");
        let mut inblob_file = File::create(inblob_path)?;
        inblob_file.write_all(&input)?;

        self.update_generation()?;
        Ok(())
    }

    /// Generate the quote
    pub fn read_output(&self) -> Result<Vec<u8>> {
        let mut outblob_path = self.path.clone();
        outblob_path.push("outblob");
        let mut outblob_file = File::open(outblob_path)?;
        let mut output = Vec::new();
        outblob_file.read_to_end(&mut output)?;

        if self.expected_generation != self.read_generation()? {
            panic!("Wrong generation number - possible conflict");
        }
        Ok(output)
    }

    /// Read the current generation number
    pub fn read_generation(&self) -> Result<u32> {
        let mut generation_path = self.path.clone();
        generation_path.push("generation");
        let current_generation = read_to_string(generation_path)?;
        Ok(current_generation.parse().unwrap())
    }

    /// Read the current generation number
    fn update_generation(&mut self) -> Result<()> {
        self.expected_generation = self.read_generation()?;
        Ok(())
    }
}

fn bytes_to_hex(input: &[u8]) -> String {
    input
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}
