Symbolicate is a rust binary that can parse macOS crash reports and generates a backtrace more like you might see from a panic.

## Installation

```
cargo install symbolicate
```

## Usage

```
symbolicate <ips-file> <dwarf-container>
```

The ips-file will typically come from `~/Library/Logs/DiagnosticReports/` and can be found using macOS's built in `Console` app.

The dwarf-container should either be the built binary that generated the crash report, or the DWARF information extracted by running `dsymutil`.
