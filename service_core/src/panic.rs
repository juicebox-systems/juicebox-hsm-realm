use std::io::IsTerminal;
use std::panic::{set_hook, take_hook};
use std::process::abort;

/// Sets a panic hook that will print a "PANIC" header in red text (if stderr
/// is a terminal), perform the standard panic behavior, and then exit the
/// process.
pub fn set_abort_on_panic() {
    let is_terminal = std::io::stderr().is_terminal();
    let default_panic = take_hook();
    set_hook(Box::new(move |info| {
        if is_terminal {
            eprintln!("\x1b[1;31m=== PANIC (exiting) ===\x1b[0m");
        }
        default_panic(info);
        abort();
    }));
}
