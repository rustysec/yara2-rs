use crate::bindings;
use crate::callbacks::scan_callback;
pub use crate::{Error, Result, Rule};
use std::convert::AsRef;
use std::ffi::CString;
use std::fs::File;
use std::os::raw::c_void;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;

lazy_static! {
    static ref INIT_MUTEX: Mutex<()> = Mutex::new(());
}

/// Main entry point for all yara usage
///
/// # Example
///
/// ```
/// use yara2::*;
/// let mut yara = Yara::new().unwrap();
/// yara.add_rule_str(r#"rule is_awesome {
///  strings:
///    $rust = "rust" nocase
///
///  condition:
///    $rust
///}"#, None).unwrap();
/// let results = yara.scan_memory(b"some data to scan contains rust").unwrap();
/// assert_eq!(results.len(), 1);
/// ```
pub struct Yara {
    compiler: *mut bindings::YR_COMPILER,
    rules: Option<*mut bindings::YR_RULES>,
}

impl Drop for Yara {
    fn drop(&mut self) {
        if let Some(rules) = self.rules {
            unsafe {
                bindings::yr_rules_destroy(rules);
            }
        }
        unsafe {
            bindings::yr_compiler_destroy(self.compiler);
        }
        self.finalize().unwrap();
    }
}

impl Yara {
    /// Initialize the Yara library
    ///
    /// Can be called multiple times without problems.
    /// Is thread safe.
    pub fn new() -> Result<Yara> {
        let _guard = INIT_MUTEX.lock();
        let result = unsafe { bindings::yr_initialize() };

        Error::from_code(result).map_err(Error::from).and_then(|_| {
            let mut pointer: *mut bindings::YR_COMPILER = ptr::null_mut();
            let result = unsafe { bindings::yr_compiler_create(&mut pointer) };

            unsafe {
                bindings::yr_compiler_set_callback(
                    pointer,
                    Some(crate::errors::error_callback),
                    std::ptr::null_mut(),
                );
            }

            Error::from_code(result)
                .map(|()| Yara {
                    compiler: pointer,
                    rules: None,
                })
                .map_err(Error::from)
        })
    }

    /// De-initialize the Yara library
    ///
    /// Must not be called more time than [`initialize`].
    /// Is thread safe.
    fn finalize(&self) -> Result<()> {
        let _guard = INIT_MUTEX.lock();
        let result = unsafe { bindings::yr_finalize() };
        Error::from_code(result).map_err(Error::from)
    }

    /// Add a rule to yara engine
    ///
    /// All rules must be added before the first scans are done. These
    /// will be compiled at first scan and yara does not allow additional
    /// rules to be added after compilation.
    ///
    /// # Arguments
    /// `rule` - valid yara rule
    /// `namespace` - optional namespace to store yara results
    ///
    pub fn add_rule_str(&mut self, rule: &str, namespace: Option<&str>) -> Result<()> {
        match self.rules {
            Some(_) => Err(Error::AlreadyCompiled),
            None => unsafe {
                let c_rule = CString::new(rule).unwrap();
                match bindings::yr_compiler_add_string(
                    self.compiler,
                    c_rule.as_ptr(),
                    namespace.map_or_else(ptr::null, |ns| {
                        CString::new(ns).unwrap_or_default().as_ptr()
                    }),
                ) {
                    0 => Ok(()),
                    count => {
                        let messages = (0..count + 1)
                            .map(|_| crate::errors::get_last_error())
                            .filter_map(|err| err)
                            .collect::<Vec<_>>();
                        Err(Error::Multiple(messages))
                    }
                }
            },
        }
    }

    /// Compiles rules if needed
    fn check_rules(&mut self) -> Result<()> {
        if self.rules.is_none() {
            let mut pointer = ptr::null_mut();
            Error::from_code(unsafe {
                bindings::yr_compiler_get_rules(self.compiler, &mut pointer)
            })
            .map_err(Error::from)?;
            self.rules = Some(pointer);
        }
        Ok(())
    }

    /// Scan a buffer loaded into memory
    ///
    /// # Arguments
    /// `data` - byte array of data to scan
    pub fn scan_memory(&mut self, data: &[u8]) -> Result<Vec<Rule>> {
        self.check_rules()?;

        if let Some(rules) = self.rules {
            let mut results = Vec::<Rule>::new();
            Error::from_code(unsafe {
                bindings::yr_rules_scan_mem(
                    rules,
                    data.as_ptr(),
                    data.len() as _,
                    0,
                    Some(scan_callback),
                    &mut results as *mut Vec<_> as *mut c_void,
                    10,
                )
            })
            .map_err(Error::from)
            .map(|_| results)
        } else {
            Ok(Vec::new())
        }
    }

    /// Scan a file
    ///
    /// # Arguments
    /// `path` - path to file to scan
    pub fn scan_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<Rule>> {
        self.check_rules()?;

        if let Some(rules) = self.rules {
            let mut results = Vec::<Rule>::new();
            File::open(&path)
                .map_err(|_| Error::InvalidFile(path.as_ref().to_str().unwrap().to_string()))
                .and_then(|ref file| unsafe {
                    Error::from_code(self.rules_scan_raw(&mut *rules, file, 10, &mut results))
                        .map(|_| results)
                })
        } else {
            Ok(Vec::new())
        }
    }

    /// Scan a running process
    ///
    /// # Arguments
    /// `pid` - process id to scan
    pub fn scan_process(&mut self, pid: std::os::raw::c_int) -> Result<Vec<Rule>> {
        self.check_rules()?;

        if let Some(rules) = self.rules {
            let mut results = Vec::<Rule>::new();
            Error::from_code(unsafe {
                bindings::yr_rules_scan_proc(
                    rules,
                    pid,
                    0,
                    Some(scan_callback),
                    &mut results as *mut Vec<_> as *mut c_void,
                    10,
                )
            })
            .map_err(Error::from)
            .map(|_| results)
        } else {
            Ok(Vec::new())
        }
    }

    #[cfg(unix)]
    pub fn rules_scan_raw(
        &self,
        rules: &mut bindings::YR_RULES,
        file: &File,
        timeout: i32,
        results: &mut Vec<Rule>,
    ) -> i32 {
        let fd = file.as_raw_fd();
        unsafe {
            bindings::yr_rules_scan_fd(
                rules,
                fd,
                0,
                Some(scan_callback),
                results as *mut Vec<_> as *mut c_void,
                timeout,
            )
        }
    }

    #[cfg(windows)]
    pub fn rules_scan_raw(
        &self,
        rules: &mut bindings::YR_RULES,
        file: &File,
        timeout: i32,
        results: &mut Vec<Rule>,
    ) -> i32 {
        let handle = file.as_raw_handle();
        unsafe {
            bindings::yr_rules_scan_fd(
                rules,
                handle as _,
                0,
                Some(scan_callback),
                results as *mut Vec<_> as *mut c_void,
                timeout,
            )
        }
    }
}
