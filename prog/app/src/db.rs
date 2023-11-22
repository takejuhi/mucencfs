use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::sync::Mutex;

pub(super) static DATABASE: Lazy<Mutex<BTreeMap<u8, u8>>> = Lazy::new(|| Mutex::default());
