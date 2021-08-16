mod sha256;

use pyo3::prelude::*;

#[pymodule]
fn sha256(_py: Python, m: &PyModule) -> PyResult<()> {
  m.add_function(wrap_pyfunction!(hash_string, m)?)?;
  m.add_function(wrap_pyfunction!(hash_file, m)?)?;
  Ok(())
}

#[pyfunction]
fn hash_string(py: Python, s: String) -> PyResult<String> {
  py.allow_threads(|| hash_string_threaded(s))
}

fn hash_string_threaded(s: String) -> PyResult<String> {
  let to_hash = s.as_bytes().to_vec();
  let mut hasher = sha256::SHA256::new(); 
  let hashed: String = hasher.hash_u8_to_string(&to_hash);
  return Ok(hashed);
}

#[pyfunction]
fn hash_file(py: Python, s: String) -> PyResult<String> {
  py.allow_threads(|| hash_file_threaded(s))
}

fn hash_file_threaded(s: String) -> PyResult<String> {
  let file = std::path::Path::new(&s);
  let to_hash: Vec<u8>; // Declare the bytes to be hashed at this level so that it can be read by the hasher

  if file.exists() {
    to_hash = std::fs::read(file)?;
  } else {
    return Ok(String::from("File could not be found."))
  }

  let mut hasher = sha256::SHA256::new(); 
  let hashed: String = hasher.hash_u8_to_string(&to_hash);
  return Ok(hashed);
}