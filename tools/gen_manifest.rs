use std::fs;

fn main() {
    let rules_dir = std::path::Path::new("/root/.openclaw/workspace/open-guardian/rules");
    let key_file = "/root/.openclaw/workspace/open-guardian/.guardian_key";
    
    // Read key
    let key_string = fs::read_to_string(key_file)
        .expect("Failed to read key file")
        .trim()
        .to_string();
    
    // Use the same RuleIntegrityChecker from the main crate
    let checker = open_guardian::security::integrity::RuleIntegrityChecker::new(
        rules_dir,
        &key_string,
        false, // emergency kit disabled for signing
    ).expect("Failed to create checker");
    
    // Generate and save manifest
    checker.save_manifest()
        .expect("Failed to save manifest");
    
    println!("✓ Manifest generated successfully!");
}
