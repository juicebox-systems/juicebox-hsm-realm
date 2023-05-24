use std::panic::{set_hook, take_hook};
use std::process::abort;

/// Set's a panic hook that will perform the standard panic behavior and then
/// exit the process.
pub fn set_abort_on_panic() {
    let default_panic = take_hook();
    set_hook(Box::new(move |info| {
        default_panic(info);
        abort();
    }));
}
