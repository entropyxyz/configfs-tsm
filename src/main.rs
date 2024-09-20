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

use configfs_tsm::OpenQuote;

fn main() {
    // If an argument is given it is used as the quote name
    let quote_name = std::env::args().nth(1).unwrap_or("test-quote".to_string());
    let mut quote = OpenQuote::new(&quote_name).unwrap();

    // Give 64 null bytes as input data
    quote.write_input([0; 64]).unwrap();

    let output = quote.read_output().unwrap();
    println!("Quote: {:?}", output);
    println!("Generation: {}", quote.read_generation().unwrap());
}
