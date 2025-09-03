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

//! This can generate quotes for remote attestation on confidential computing platforms using Linux's
//! [configfs-tsm](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm) filesystem
//! interface.
//!
//! This is designed for and tested with Intel TDX, but since the `configfs-tsm` is a platform-agnostic
//! interface, this could potentially work with other platforms such as Intel SGX, or AMD SEV.
//!
//! This crate has no dependencies and generates quotes only by reading and writing local files.
//!
//! Warning: This crate is in early stages of development and has not been audited
use std::{
    error::Error,
    fmt::{self, Display},
    fs::{create_dir, read_to_string, File},
    hash::{DefaultHasher, Hash, Hasher},
    io::{ErrorKind, Read, Write},
    num::ParseIntError,
    path::PathBuf,
};

/// The path of the configfs-tsm interface
const CONFIGFS_TSM_PATH: &str = "/sys/kernel/config/tsm/report";

/// Create a quote with given input, using the input data as quote directory name
pub fn create_quote(input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
    let quote_name = create_quote_name(&input);
    let mut quote = OpenQuote::new(&quote_name)?;
    quote.write_input(input)?;
    quote.read_output()
}

/// Same as create_quote, but check that the provider (the TEE platform) matches one of a given set
/// of values
pub fn create_quote_with_providers(
    input: [u8; 64],
    accepted_providers: Vec<&str>,
) -> Result<Vec<u8>, QuoteGenerationError> {
    let quote_name = create_quote_name(&input);
    let mut quote = OpenQuote::new(&quote_name)?;
    quote.check_provider(accepted_providers)?;
    quote.write_input(input)?;
    quote.read_output()
}

/// Convenience function for creating a quote and checking the provider is tdx_guest
pub fn create_tdx_quote(input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
    create_quote_with_providers(input, vec!["tdx_guest"])
}

/// Represents a pending quote
pub struct OpenQuote {
    /// The path of the quote files
    path: PathBuf,
    /// What generation number we expect the quote to have when reading.
    /// This is used to detect conflicts when another process modifies the quote.
    expected_generation: u32,
}

impl OpenQuote {
    /// Create a new open quote
    pub fn new(quote_name: &str) -> Result<Self, QuoteGenerationError> {
        let mut quote_path = PathBuf::from(CONFIGFS_TSM_PATH);
        quote_path.push(quote_name);

        if let Err(error) = create_dir(quote_path.clone()) {
            match error.kind() {
                // If a quote with the same name has already been made, we ignore the error as we can still
                // re-use the quote
                ErrorKind::AlreadyExists => {}
                ErrorKind::NotFound => return Err(QuoteGenerationError::CannotFindTsmDir),
                _ => return Err(QuoteGenerationError::IO(error)),
            }
        }

        Ok(Self {
            path: quote_path,
            expected_generation: 0,
        })
    }

    /// Write input data to quote
    pub fn write_input(&mut self, input: [u8; 64]) -> Result<(), QuoteGenerationError> {
        self.update_generation()?;
        let mut inblob_path = self.path.clone();
        inblob_path.push("inblob");
        let mut inblob_file = File::create(inblob_path)?;
        inblob_file.write_all(&input)?;

        self.expected_generation += 1;
        Ok(())
    }

    /// Generate the quote
    pub fn read_output(&self) -> Result<Vec<u8>, QuoteGenerationError> {
        let mut outblob_path = self.path.clone();
        outblob_path.push("outblob");
        let mut outblob_file = File::open(outblob_path)?;
        let mut output = Vec::new();
        outblob_file.read_to_end(&mut output)?;

        let actual = self.read_generation()?;
        if self.expected_generation != actual {
            return Err(QuoteGenerationError::Generation(
                self.expected_generation,
                actual,
            ));
        }

        if output.is_empty() {
            return Err(QuoteGenerationError::EmptyQuote);
        }
        Ok(output)
    }

    /// Read the current generation number
    pub fn read_generation(&self) -> Result<u32, QuoteGenerationError> {
        let mut generation_path = self.path.clone();
        generation_path.push("generation");
        let mut current_generation = read_to_string(generation_path)?;
        trim_newline(&mut current_generation);
        Ok(current_generation.parse()?)
    }

    /// Check that the provider matches given accepted values
    pub fn check_provider(&self, accepted_values: Vec<&str>) -> Result<(), QuoteGenerationError> {
        let mut provider_path = self.path.clone();
        provider_path.push("provider");
        let mut provider = read_to_string(provider_path)?;
        trim_newline(&mut provider);
        if !accepted_values.contains(&provider.as_str()) {
            return Err(QuoteGenerationError::BadProvider(provider));
        }
        Ok(())
    }

    /// Update the expected generation number
    fn update_generation(&mut self) -> Result<(), QuoteGenerationError> {
        self.expected_generation = self.read_generation()?;
        Ok(())
    }
}

/// Derive a name for the quote directory from the input data by hashing and encoding as hex
fn create_quote_name(input: &[u8]) -> String {
    let mut s = DefaultHasher::new();
    input.hash(&mut s);
    let hash_bytes = s.finish().to_le_bytes();
    bytes_to_hex(&hash_bytes)
}

fn bytes_to_hex(input: &[u8]) -> String {
    input
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

/// Remove a trailing newline character from a given string if present
fn trim_newline(input: &mut String) {
    if input.ends_with('\n') {
        input.pop();
        if input.ends_with('\r') {
            input.pop();
        }
    }
}

/// An error when parsing a quote
#[derive(Debug)]
pub enum QuoteGenerationError {
    Generation(u32, u32),
    IO(std::io::Error),
    ParseInt,
    BadProvider(String),
    CannotFindTsmDir,
    EmptyQuote,
}

impl Display for QuoteGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteGenerationError::Generation(expected, actual) => f.write_str(&format!(
                "Wrong generation number - possible conflict. Expected: {} Actual: {}",
                expected, actual
            )),
            QuoteGenerationError::IO(error) => f.write_str(&error.to_string()),
            QuoteGenerationError::ParseInt => {
                f.write_str("Could not parse integer when reading generation value")
            }
            QuoteGenerationError::BadProvider(provider) => f.write_str(&format!(
                "Quote has provider which is not allowed: {}",
                provider
            )),
            QuoteGenerationError::CannotFindTsmDir => f.write_str(
                "Cannot find configfs-tsm directory - maybe your hardware does not support it",
            ),
            QuoteGenerationError::EmptyQuote => f.write_str("Empty quote. This could be an authorization issue with the quote generation socket."),
        }
    }
}

impl Error for QuoteGenerationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for QuoteGenerationError {
    fn from(error: std::io::Error) -> QuoteGenerationError {
        QuoteGenerationError::IO(error)
    }
}

impl From<ParseIntError> for QuoteGenerationError {
    fn from(_: ParseIntError) -> QuoteGenerationError {
        QuoteGenerationError::ParseInt
    }
}
