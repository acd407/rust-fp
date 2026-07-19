use std::fmt::{Display, Formatter};
use std::fs;
use std::io;

use rmp_serde::encode;

use crate::fp_file;
use crate::fp_file::{get_fp_dir, get_fp_dir_in, get_fp_file, get_fp_file_in};
use crate::template::Templates;

#[derive(Debug)]
pub enum Error {
    Encode(encode::Error),
    FpDir(fp_file::Error),
    CreateDir(io::Error),
    FpFile(fp_file::Error),
    Write(io::Error),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(e) => {
                write!(f, "Error encoding file: {:#?}", e)
            }
            Self::FpDir(e) => {
                write!(f, "Error getting fp file: {:#?}", e)
            }
            Self::CreateDir(e) => {
                write!(f, "Error creating dir: {:#?}", e)
            }
            Self::FpFile(e) => {
                write!(f, "Error getting fp file: {:#?}", e)
            }
            Self::Write(e) => {
                write!(f, "Error writing file: {:#?}", e)
            }
        }
    }
}

pub fn set_templates(templates: &Templates) -> Result<(), Error> {
    let vec = encode::to_vec(templates).map_err(Error::Encode)?;
    let fp_file = get_fp_file().map_err(Error::FpFile)?;
    let fp_dir = get_fp_dir().map_err(Error::FpDir)?;
    set_templates_in(&fp_file, &fp_dir, &vec)
}

pub fn set_templates_for(home_dir: &str, templates: &Templates) -> Result<(), Error> {
    let vec = encode::to_vec(templates).map_err(Error::Encode)?;
    let fp_file = get_fp_file_in(home_dir);
    let fp_dir = get_fp_dir_in(home_dir);
    set_templates_in(&fp_file, &fp_dir, &vec)
}

pub fn set_templates_in(fp_file: &str, fp_dir: &str, encoded: &[u8]) -> Result<(), Error> {
    fs::create_dir_all(fp_dir).map_err(Error::CreateDir)?;
    fs::write(fp_file, encoded).map_err(Error::Write)?;
    Ok(())
}
