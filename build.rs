const INTER_VERSION: &'static str = "4.1";

fn extract_file<R>(zip: &mut zip::ZipArchive<R>, name: &str, path: &std::path::Path)
where
    R: std::io::Seek + std::io::Read,
{
    let mut reader = zip.by_name(name).unwrap();
    let mut writer = std::fs::File::create(path).unwrap();
    std::io::copy(&mut reader, &mut writer).unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=migrations");

    let package_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_dir = std::path::Path::new(&package_dir);
    let frontend_dir = package_dir.join("frontend");
    let static_dir = frontend_dir.join("static");
    let inter_normal_path = static_dir.join(format!("inter-normal-{}.woff2", INTER_VERSION));
    let inter_italic_path = static_dir.join(format!("inter-italic-{}.woff2", INTER_VERSION));
    
    std::process::Command::new("npm").arg("run").arg("build").current_dir(frontend_dir).status().unwrap();

    if inter_normal_path.exists() && inter_italic_path.exists() {
        return;
    }

    let url = format!(
        "https://github.com/rsms/inter/releases/download/v{0}/Inter-{0}.zip",
        INTER_VERSION
    );
    let bytes = ureq::get(url)
        .call()
        .unwrap()
        .body_mut()
        .with_config()
        .limit(48 * 1024 * 1024)
        .read_to_vec()
        .unwrap();

    let reader = std::io::Cursor::new(bytes);

    let mut zip = zip::ZipArchive::new(reader).unwrap();
    extract_file(&mut zip, "web/InterVariable.woff2", &inter_normal_path);
    extract_file(
        &mut zip,
        "web/InterVariable-Italic.woff2",
        &inter_italic_path,
    );
}
