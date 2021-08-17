pub mod hash_algorithms;

use pyo3::prelude::*;
use hash_algorithms::sha256::SHA256;

#[pymodule]
fn hasher(_py: Python, m: &PyModule) -> PyResult<()> {
  m.add_function(wrap_pyfunction!(hash_string, m)?)?;
  m.add_function(wrap_pyfunction!(hash_file, m)?)?;
  Ok(())
}

#[pyfunction]
fn hash_string(py: Python, s: String, reporter: PyObject) -> PyResult<String> {
  py.allow_threads(|| hash_string_threaded(s, reporter))
}

fn hash_string_threaded(s: String, reporter: PyObject) -> PyResult<String> {  
  log::debug!("Hash string function called by python");

  let to_hash = s.as_bytes().to_vec();
  let mut hasher = SHA256::new();
  
  let reporter_option: Option<&PyObject>; 
  let gil = Python::acquire_gil();
  if reporter.is_none(gil.python()) {
    reporter_option = None;
  } else {
    reporter_option = Some(&reporter);
  }

  let hashed = hasher.hash_u8_to_string(&to_hash, reporter_option);

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

  let reporter_option: Option<&PyObject>; 
  let gil = Python::acquire_gil();
  if reporter.is_none(gil.python()) {
    reporter_option = None;
  } else {
    reporter_option = Some(&reporter);
  }

  let mut hasher = SHA256::new();
  let hashed: String = hasher.hash_u8_to_string(&to_hash, reporter_option);

  return Ok(hashed);
}