mod sha256;

use pyo3::prelude::*;

#[pymodule]
fn sha256(_py: Python, m: &PyModule) -> PyResult<()> {
  m.add_function(wrap_pyfunction!(hash_string, m)?)?;
  m.add_function(wrap_pyfunction!(hash_file, m)?)?;
  Ok(())
}

#[pyfunction]
fn hash_string(py: Python, s: String, reporter: PyObject) -> PyResult<String> {
  py.allow_threads(|| hash_string_threaded(s, reporter))
}

fn hash_string_threaded(s: String, reporter: PyObject) -> PyResult<String> {
  let to_hash = s.as_bytes().to_vec();
  let mut hasher = sha256::SHA256::new(); 
  let hashed: String = hasher.hash_u8_to_string(&to_hash, &reporter);
  return Ok(hashed);
}

#[pyfunction]
fn hash_file(py: Python, s: String, reporter: PyObject) -> PyResult<String> {
  py.allow_threads(|| hash_file_threaded(s, reporter))
}

fn hash_file_threaded(s: String, reporter: PyObject) -> PyResult<String> {
  log::debug!("Hash file function called by python");

  let file = std::path::Path::new(&s);
  let to_hash: Vec<u8>; // Declare the bytes to be hashed at this level so that it can be read by the hasher

  if file.exists() {
    to_hash = std::fs::read(file)?;
  } else {
    return Ok(String::from("File could not be found."))
  }

  let reporter_addr: *const PyObject = &reporter;
  if !(reporter_addr.is_null()) {
    log::debug!("Python requested updates be reported");
  }

  let mut hasher = sha256::SHA256::new(); 
  let hashed: String = hasher.hash_u8_to_string(&to_hash, &reporter);
  return Ok(hashed);
}