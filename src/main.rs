mod sha256;

fn main() -> std::io::Result<()> {
  env_logger::init();
  
  let args: Vec<String> = std::env::args().collect();

  let file; // Declare file at this scope so that it can be used by the hasher
  let to_hash: Vec<u8>; // Declare the bytes to be hashed at this level so that it can be read by the hasher

  if args.len() > 1 {
    file = std::path::Path::new(&args[1]);
  } else {
    panic!("Must provide an input to hash.");
  }

  if file.exists() {
    to_hash = std::fs::read(file)?;
  } else {
    // Treat command line argument as a string to be hashed
    let file_as_str;
    let file_option = file.to_str();

    match file_option {
      Some(x) => file_as_str = x,
      None    => panic!("command line arg does not exist as a file and name cannot be written as a String. Don't know how you got here"),
    };
    to_hash = file_as_str.as_bytes().to_vec();
  } 

  let mut hasher = sha256::SHA256::new(); 
  let hashed: String = hasher.hash_u8_to_string(&to_hash);
  println!("{}", hashed);

  return Ok(());
}