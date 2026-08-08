use std::{env, fs, path::{Path, PathBuf}};

fn main() {

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let defs_dir = manifest_dir.join("defs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let combined_def = out_dir.join("combined.def");

    let lib_name = env::var("CARGO_PKG_NAME").unwrap(); // used as LIBRARY name

    let mut exports: Vec<String> = Vec::new();

    // Collect *.def files in defs/ (sorted for stable builds)
    let mut files: Vec<PathBuf> = fs::read_dir(&defs_dir)
        .expect("defs/ folder missing")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("def"))
        .collect();

    files.sort();

    for path in files {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("failed to read {}", path.display()));
        exports.extend(extract_exports(&text, &path));
    }

    // Optional: de-dup exact duplicate lines
    exports.sort();
    exports.dedup();

    let mut out = String::new();
    out.push_str(&format!("LIBRARY {}\nEXPORTS\n", lib_name));
    for line in exports {
        out.push_str("    ");
        out.push_str(&line);
        out.push('\n');
    }

    fs::write(&combined_def, out).expect("write combined.def");

    // Pass the combined .def to the MinGW linker
    println!("cargo:rustc-link-arg={}", combined_def.display());
}

fn extract_exports(text: &str, path: &Path) -> Vec<String> {
    let mut in_exports = false;
    let mut out = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();

        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        // If you accidentally keep LIBRARY in snippets, we just ignore it.
        if line.to_ascii_uppercase().starts_with("LIBRARY ") {
            continue;
        }

        if line.eq_ignore_ascii_case("EXPORTS") {
            in_exports = true;
            continue;
        }

        if !in_exports {
            // Allow “EXPORTS-only” files without an explicit EXPORTS header:
            // treat first non-empty line as an export if it looks like one.
            if line.contains('=') || line.contains('@') {
                out.push(line.to_string());
            } else {
                panic!(
                    "Unexpected content before EXPORTS in {} at line {}: {}",
                    path.display(),
                    idx + 1,
                    line
                );
            }
        } else {
            out.push(line.to_string());
        }
    }

    out
}
