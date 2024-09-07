use configfs_tsm::OpenQuote;

fn main() {
    let quote_name = std::env::args().nth(1).unwrap_or("test-quote".to_string());
    let quote = OpenQuote::new(&quote_name).unwrap();
    quote.write_input([0; 64]).unwrap();
    let output = quote.read_output().unwrap();
    println!("Quote: {:?}", output);
}
