// Simple tool to generate rule manifest
// Usage: cargo run --bin generate-manifest -- <rules_dir> <key_file>

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    pub version: String,
    pub created_at: String,
    pub signatures: HashMap<String, String>,
    pub key_id: String,
}

fn derive_key(input: &str) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

fn compute_hmac(data: &[u8], key: &[u8]) -> String {
    use hmac_sha256::HMAC;
    hex::encode(HMAC::mac(data, key))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <rules_dir> <key_file>", args[0]);
        std::process::exit(1);
    }

    let rules_dir = Path::new(&args[1]);
    let key_file = Path::new(&args[2]);

    // Read key
    let key_string = fs::read_to_string(key_file)
        .expect("Failed to read key file");
    let key = derive_key(key_string.trim());

    // Generate signatures
    let mut signatures = HashMap::new();
    
    for entry in fs::read_dir(rules_dir).expect("Failed to read rules dir") {
        let entry = entry.expect("Failed to read entry");
        let path = entry.path();
        
        if path.extension().map(|e| e == "json").unwrap_or(false) 
            && path.file_name().map(|n| n != ".manifest.json").unwrap_or(false) 
        {
            let content = fs::read(&path).expect("Failed to read rule file");
            let hmac = compute_hmac(&content, &key);
            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            
            println!("Signing: {} -> {}", filename, hmac);
            signatures.insert(filename, hmac);
        }
    }

    // Create manifest
    let manifest = RuleManifest {
        version: "1.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        signatures,
        key_id: "guardian-production-key-001".to_string(),
    };

    // Save manifest
    let manifest_path = rules_dir.join(".manifest.json");
    let json = serde_json::to_string_pretty(&manifest)
        .expect("Failed to serialize manifest");
    fs::write(&manifest_path, json)
        .expect("Failed to write manifest");
    
    println!("\n✓ Manifest saved to: {}", manifest_path.display());
}
