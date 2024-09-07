/// For explanation see https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm
use std::{
    fs::{create_dir, File},
    io::{Read, Result, Write},
    path::PathBuf,
};

/// Create a quote with given input
pub fn create_quote(input: [u8; 64]) -> Result<Vec<u8>> {
    let quote_name = bytes_to_hex(&input);
    let quote = OpenQuote::new(&quote_name)?;
    quote.write_input(input)?;
    quote.read_output()
}

/// Represents a pending quote
pub struct OpenQuote {
    path: PathBuf,
}

impl OpenQuote {
    /// Create a new open quote
    pub fn new(quote_name: &str) -> Result<Self> {
        let mut quote_path = PathBuf::from("/sys/kernel/config/tsm/report");
        quote_path.push(quote_name);
        create_dir(quote_path.clone())?;
        Ok(Self { path: quote_path })
    }

    /// Write input data to quote
    pub fn write_input(&self, input: [u8; 64]) -> Result<()> {
        let mut inblob_path = self.path.clone();
        inblob_path.push("inblob");
        let mut inblob_file = File::create(inblob_path)?;
        inblob_file.write_all(&input)?;
        Ok(())
    }

    /// Generate the quote
    pub fn read_output(&self) -> Result<Vec<u8>> {
        let mut outblob_path = self.path.clone();
        outblob_path.push("outblob");
        let mut outblob_file = File::open(outblob_path)?;
        let mut output = Vec::new();
        outblob_file.read_to_end(&mut output)?;
        Ok(output)
    }
}

fn bytes_to_hex(input: &[u8]) -> String {
    input
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}
