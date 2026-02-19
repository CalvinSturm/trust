use std::fs;
use std::path::Path;

fn template_paths() -> [&'static str; 3] {
    [
        "assets/native-host-manifests/chrome_native_host_manifest.win.template.json",
        "assets/native-host-manifests/chrome_native_host_manifest.macos.template.json",
        "assets/native-host-manifests/chrome_native_host_manifest.linux.template.json",
    ]
}

#[test]
fn native_host_templates_contain_required_placeholders() {
    for rel in template_paths() {
        let p = Path::new(rel);
        let text = fs::read_to_string(p).expect("template should be readable");
        assert!(
            text.contains("__HOST_NAME__"),
            "missing host placeholder in {rel}"
        );
        assert!(
            text.contains("__BINARY_PATH__"),
            "missing path placeholder in {rel}"
        );
        assert!(
            text.contains("__EXTENSION_ID__"),
            "missing extension placeholder in {rel}"
        );
        assert!(
            text.contains("\"type\": \"stdio\""),
            "missing stdio type in {rel}"
        );
    }
}

#[test]
fn native_host_templates_render_to_valid_json() {
    for rel in template_paths() {
        let text = fs::read_to_string(rel).expect("template should be readable");
        let rendered = text
            .replace("__HOST_NAME__", "dev.calvinbuild.c2pa_inspect")
            .replace("__BINARY_PATH__", "/tmp/c2pa-native-host")
            .replace("__EXTENSION_ID__", "abcdefghijklmnopabcdefghijklmnop");
        let v: serde_json::Value =
            serde_json::from_str(&rendered).expect("rendered template must parse");
        assert_eq!(v["name"], "dev.calvinbuild.c2pa_inspect");
        assert_eq!(v["type"], "stdio");
    }
}
