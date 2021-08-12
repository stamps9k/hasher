mod sha256;

use pyo3::prelude::*;

#[pymodule]
fn sha256(_py: Python, m: &PyModule) -> PyResult<()> {
  m.add_function(wrap_pyfunction!(hash_string, m)?)?;
  Ok(())
}

#[pyfunction]
fn hash_string(s: String) -> PyResult<String> {
  let to_hash = s.as_bytes().to_vec();
  let mut hasher = sha256::SHA256::new(); 
  let hashed: String = hasher.hash_u8_to_string(&to_hash);
  return Ok(hashed);
}