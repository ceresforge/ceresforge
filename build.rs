const INTER_VERSION: &'static str = "4.1";
const JET_BRAINS_MONO_VERSION: &'static str = "2.304";

fn extract_file<R>(zip: &mut zip::ZipArchive<R>, name: &str, path: &std::path::Path)
where
    R: std::io::Seek + std::io::Read,
{
    let mut reader = zip.by_name(name).unwrap();
    let mut writer = std::fs::File::create(path).unwrap();
    std::io::copy(&mut reader, &mut writer).unwrap();
}

fn download_inter(inter_normal_path: &std::path::PathBuf, inter_italic_path: &std::path::PathBuf) {
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

fn download_jet_brains_mono(
    jet_brains_mono_normal_path: &std::path::PathBuf,
    jet_brains_mono_italic_path: &std::path::PathBuf,
) {
    let url = format!(
        "https://github.com/JetBrains/JetBrainsMono/releases/download/v{0}/JetBrainsMono-{0}.zip",
        JET_BRAINS_MONO_VERSION
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
    let mut normal_ttf_path = jet_brains_mono_normal_path.clone();
    normal_ttf_path.set_extension("ttf");
    extract_file(
        &mut zip,
        "fonts/variable/JetBrainsMono[wght].ttf",
        &normal_ttf_path,
    );
    assert!(
        std::process::Command::new("woff2_compress")
            .arg(&normal_ttf_path)
            .current_dir(&normal_ttf_path.parent().unwrap())
            .status()
            .unwrap()
            .success()
    );
    std::fs::remove_file(normal_ttf_path).unwrap();
    let mut italic_ttf_path = jet_brains_mono_italic_path.clone();
    italic_ttf_path.set_extension("ttf");
    extract_file(
        &mut zip,
        "fonts/variable/JetBrainsMono-Italic[wght].ttf",
        &italic_ttf_path,
    );
    assert!(
        std::process::Command::new("woff2_compress")
            .arg(&italic_ttf_path)
            .current_dir(&italic_ttf_path.parent().unwrap())
            .status()
            .unwrap()
            .success()
    );
    std::fs::remove_file(italic_ttf_path).unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=frontend");
    println!("cargo:rerun-if-changed=migrations");

    let package_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_dir = std::path::Path::new(&package_dir);
    let frontend_dir = package_dir.join("frontend");
    let static_dir = frontend_dir.join("static");

    let inter_normal_path = static_dir.join(format!("inter-normal-{}.woff2", INTER_VERSION));
    let inter_italic_path = static_dir.join(format!("inter-italic-{}.woff2", INTER_VERSION));
    if !inter_normal_path.exists() || !inter_italic_path.exists() {
        download_inter(&inter_normal_path, &inter_italic_path);
    }

    let jet_brains_mono_normal_path = static_dir.join(format!(
        "jet-brains-mono-normal-{}.woff2",
        JET_BRAINS_MONO_VERSION
    ));
    let jet_brains_mono_italic_path = static_dir.join(format!(
        "jet-brains-mono-italic-{}.woff2",
        JET_BRAINS_MONO_VERSION
    ));
    if !jet_brains_mono_normal_path.exists() || !jet_brains_mono_italic_path.exists() {
        download_jet_brains_mono(&jet_brains_mono_normal_path, &jet_brains_mono_italic_path);
    }

    assert!(
        std::process::Command::new("pnpm")
            .arg("install")
            .current_dir(&frontend_dir)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("npm")
            .arg("run")
            .arg("build")
            .current_dir(frontend_dir)
            .status()
            .unwrap()
            .success()
    );
}
