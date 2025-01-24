//! Utility functions


use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::Path;

use clap::Error;
use colored::Colorize as _;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use rsdith::
    constants::{
        params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        types::{Salt, Seed},
    }
;

macro_rules! clap_err_result {
    ($e:expr, $t:expr) => {
        match $e {
            Ok(val) => Ok::<_, Error>(val),
            Err(e) => return Err(Error::raw($t, e)),
        }
    };

    ($e:expr) => {
        match $e {
            Ok(val) => Ok::<_, Error>(val),
            Err(e) => return Err(Error::raw(clap::error::ErrorKind::InvalidValue, e)),
        }
    };
}
pub(super) use clap_err_result;


macro_rules! clap_err_result_msg {
  ($e:expr, $m:expr, $t:expr) => {
    match $e {
      Ok(val) => Ok::<_, Error>(val),
      Err(e) => return Err(Error::raw($t, format!("{}: {}", $m, e))),
    }
  };
  
  ($e:expr,  $m:expr) => {
    clap_err_result_msg!($e, $m, clap::error::ErrorKind::InvalidValue)
  };
}
pub(super) use clap_err_result_msg;
pub(super) fn print_title(title: &str) {
  eprintln!("{}", title.green().bold());
}

/// Returns a seed. If no seed is provided, a random seed is generated. Returns true if seed is random.
pub(super) fn get_seed(_seed: Option<&String>) -> Result<Seed, Error> {
  let seed = if _seed.is_none() {
      // Generate a random seed using StdRng
      let mut rng = StdRng::from_entropy();
      let mut seed: Seed = [0u8; PARAM_SEED_SIZE];
      rng.fill_bytes(&mut seed);
      seed
  } else {
      let seed_string = _seed.as_ref().unwrap();

      let seed_vec = clap_err_result!(STANDARD.decode(seed_string))?;

      if seed_vec.len() != PARAM_SEED_SIZE {
          return Err(Error::raw(
              clap::error::ErrorKind::InvalidValue,
              format!("Seed must be {} bytes long", PARAM_SEED_SIZE),
          ));
      }

      let mut seed: Seed = [0u8; PARAM_SEED_SIZE];
      seed.copy_from_slice(&seed_vec);
      seed
  };

  if _seed.is_none() {
      eprintln!("{}: {}", "Seed".blue(), STANDARD.encode(seed));
  }

  Ok(seed)
}

pub(super) fn get_salt(_salt: Option<&String>) -> Result<Salt, Error> {
  let salt = if _salt.is_none() {
      // Generate a random salt using StdRng
      let mut rng = StdRng::from_entropy();
      let mut salt: Salt = [0u8; PARAM_SALT_SIZE];
      rng.fill_bytes(&mut salt);
      salt
  } else {
      let salt_string = _salt.as_ref().unwrap();

      let salt_vec = clap_err_result_msg!(
          STANDARD.decode(salt_string),
          "Could not decode salt from base64"
      )?;

      if salt_vec.len() != PARAM_SALT_SIZE {
          return Err(Error::raw(
              clap::error::ErrorKind::InvalidValue,
              format!("Salt must be {} bytes long", PARAM_SALT_SIZE),
          ));
      }

      let mut salt: Salt = [0u8; PARAM_SALT_SIZE];
      salt.copy_from_slice(&salt_vec);
      salt
  };

  if _salt.is_none() {
      eprintln!("{}: {}", "Salt".blue(), STANDARD.encode(salt));
  }

  Ok(salt)
}

/// Checks if the input is a file or a string. Returns the decoded string from the file or the input string.
pub(super) fn get_decoded_string_from_file_or_string(
  file_or_string: String,
  title: Option<String>,
) -> Result<Vec<u8>, Error> {
  let path = Path::new(&file_or_string);
  let read_title = match &title {
      Some(title) => format!("Reading {} from file", title).blue(),
      None => "Reading from file".blue(),
  };

  let encoded = if path.exists() {
      eprintln!("{}: {}", read_title, path.display());
      std::fs::read_to_string(path)?.trim().to_string()
  } else {
      file_or_string.clone()
  };

  clap_err_result_msg!(
      STANDARD.decode(encoded),
      format!(
          "Could not decode {} from base64",
          match title {
              Some(title) => title,
              None => "input".to_string(),
          }
      )
  )
}
