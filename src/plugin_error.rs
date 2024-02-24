use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

pub struct PluginError(pub String);

impl Debug for PluginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for PluginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for PluginError {}