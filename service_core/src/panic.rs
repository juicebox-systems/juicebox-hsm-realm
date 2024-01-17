use serde::Serialize;
use std::backtrace::Backtrace;
use std::io::{self, IsTerminal, Write};
use std::panic::{set_hook, take_hook, PanicInfo};
use std::process::abort;

/// Sets a panic hook that will exit the process on any panics.
///
/// If stderr is a terminal, this will print a "PANIC" header in red text,
/// perform the standard panic behavior, and then exit the process.
///
/// If stderr is not a terminal, this will print a JSON-formatted panic message
/// to stderr, then exit the process. This allows the panic messages to be
/// ingested by Datadog without complex parsing.
pub fn set_abort_on_panic() {
    let is_terminal = io::stderr().is_terminal();
    let default_panic = take_hook();
    set_hook(Box::new(move |info| {
        if is_terminal {
            eprintln!("\x1b[1;31m=== PANIC (exiting) ===\x1b[0m");
            default_panic(info);
        } else {
            json_panic_handler(info);
        }
        abort();
    }));
}

// This is loosely based on the default panic handler but quite stripped down.
fn json_panic_handler(info: &PanicInfo<'_>) {
    let location: String = match info.location() {
        Some(location) => location.to_string(),
        None => String::from("N/A"),
    };

    let reason: &str = if let Some(reason) = info.payload().downcast_ref::<&'static str>() {
        reason
    } else if let Some(reason) = info.payload().downcast_ref::<String>() {
        reason
    } else {
        "Box<dyn Any>"
    };

    let backtrace = Backtrace::force_capture().to_string();

    // Note: This code would be slightly shorter by using the `json!` macro
    // instead of this struct. However, that outputs the backtrace as the first
    // field, making the message hard to find. Using this struct preserves the
    // field order.
    #[derive(Serialize)]
    struct PanicMessage<'a> {
        message: &'a str,
        reason: &'a str,
        panic: bool,
        level: &'a str,
        location: String,
        backtrace: String,
    }

    let mut stderr = io::stderr().lock();
    _ = serde_json::to_writer(
        &mut stderr,
        &PanicMessage {
            message: "panicked. exiting",
            reason,
            panic: true,
            level: "ERROR",
            location,
            backtrace,
        },
    );
    _ = writeln!(&mut stderr);
}
