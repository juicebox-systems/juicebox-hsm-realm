# cd to repo root
cd -P -- "$(dirname -- "$0")/.."

# Install grcov with cargo install grcov.
# The output has some issues
#   a) macros that wrap functions such as async-trait & instrument confuse it.
#   b) the function counts/% reported are flat out wrong.
#
# But even with all this, the by file report is generally useful, and something is better than nothing.

cargo clean
# By building all the binaries this way, we'll get coverage information from the
# binaries that get run by the tests. e.g. when a test starts a load balancer
# process, we'll get coverage info from that.
#
# This however seems unreliable. Sometimes it looks like the .profraw file
# doesn't get generated e.g. the tests/testing/append_battle.rs test often
# doesn't generate .profraw's from all the agents, but removing the last part of
# that test seems to solve that. Its not clear what's different the triggers
# the file to not get written.
CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' cargo build
find . -name "*.profraw" -delete
CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' LLVM_PROFILE_FILE='cov-%p-%m.profraw' cargo test
grcov . --binary-path target/debug/ -s . -t html --llvm \
    --excl-start "mod tests \{" \
    --excl-line '^\s*((debug_)?assert(_eq|_ne)?!|#\[derive|trace!|info!)' \
    --ignore-not-existing --ignore '../*' --ignore "/*" --ignore "target/debug/build/**" \
    --ignore "google/src/autogen/*" --ignore "codegen/*" \
    -o target/coverage/html
find . -name "*.profraw" -delete
open target/coverage/html/index.html
