#[cfg(feature = "wasm-scripting")]
use aa_proxy_rs::config::wasm_script_limits_config_section;
use aa_proxy_rs::config::{AppConfig, ConfigJson, ConfigValues};
use serde_json::Value;
use std::path::PathBuf;
use std::{collections::BTreeMap, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting default config generation...");

    // Path to the generated .toml file, located relative to the
    // executable's directory (based on the target triple)
    let output_path: PathBuf = std::env::current_exe()?
        .parent()
        .ok_or("Unable to get parent directory of the binary")?
        .join("config.toml");

    println!("💾 Saving config to: {}", output_path.display());

    generate_config(output_path)?;
    println!("✅ Config generation completed successfully!");

    Ok(())
}

pub fn generate_config<P: AsRef<Path>>(output_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_json: ConfigJson = AppConfig::load_config_json()?;

    // The WASM hooks section is appended dynamically at runtime; do the same
    // here so the generated TOML matches what the dashboard shows.
    #[cfg(feature = "wasm-scripting")]
    config_json.titles.push(wasm_script_limits_config_section());

    let default_config = AppConfig::default();

    // Convert AppConfig into a serde_json::Value and collect it as a map
    let default_map: BTreeMap<String, Value> = serde_json::to_value(default_config)?
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut output = String::new();

    for section in &config_json.titles {
        emit_section(section, &[], &mut output, &default_map);
    }

    fs::write(&output_path, output)?;

    Ok(())
}

/// Recursively emit a section's values and any nested sub-sections. The
/// header for a nested section is a breadcrumb of all ancestor titles
/// joined with " / ".
fn emit_section(
    section: &ConfigValues,
    ancestors: &[&str],
    output: &mut String,
    default_map: &BTreeMap<String, Value>,
) {
    let trimmed_title = section.title.trim();
    let mut breadcrumb: Vec<&str> = ancestors.to_vec();
    breadcrumb.push(trimmed_title);
    output.push_str(&format!("### {}\n", breadcrumb.join(" / ")));

    for (key, val) in &section.values {
        // Write comment lines for each description line
        for line in val.description.lines() {
            output.push_str(&format!("  # {}\n", line.trim()));
        }

        // Get the default value from AppConfig (or a fallback default based on type)
        let default = default_map
            .get(key.as_str())
            .map(to_toml_value_string)
            .unwrap_or_else(|| match val.typ.as_str() {
                "string" => r#""""#.to_string(),
                "integer" => "0".to_string(),
                "float" => "0.0".to_string(),
                "boolean" => "false".to_string(),
                "select" => {
                    if let Some(values) = &val.values {
                        format!(r#""{}""#, values.first().map(String::as_str).unwrap_or(""))
                    } else {
                        r#""""#.to_string()
                    }
                }
                "multi-select" => r#""""#.to_string(),
                _ => r#""""#.to_string(),
            });

        // These values are generated at runtime on the actual device; comment
        // them out so the generated TOML doesn't override the live detection.
        let commented: &str = if key == "wifi_version" || key == "band" || key == "channel" {
            "#"
        } else {
            ""
        };
        output.push_str(&format!("  {}{} = {}\n\n", commented, key, default));
    }

    for sub in &section.subsections {
        emit_section(sub, &breadcrumb, output, default_map);
    }
}

/// Converts a serde_json::Value into a TOML-compatible string representation
fn to_toml_value_string(value: &Value) -> String {
    match value {
        Value::String(s) => format!(r#""{}""#, s),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => r#""""#.to_string(),
        _ => format!(r#""{}""#, value), // fallback for other types
    }
}
