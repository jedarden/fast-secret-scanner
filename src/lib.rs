//! Low-latency detection for common secret patterns.
//!
//! The library never retains or exposes matched values. A [`Finding`] contains
//! only a path, line number, and stable rule ID.

mod detector;
mod git;

pub use detector::{Finding, MAX_FILE_BYTES, ScanSkips, Scanner, Span};
pub use git::{MAX_PATCH_BYTES, scan_staged, scan_staged_patch, scan_worktree};
