//! Production update path: signature, checksum, downgrade, redirect, rollback.

#![allow(clippy::format_push_string, clippy::too_many_lines)]

use flate2::write::GzEncoder;
use flate2::Compression;
use minisign::{sign, KeyPair};
use ownmesh_update::{
    apply_binaries, binary_file_name, binary_file_name_for, download_and_verify,
    extract_required_binaries, finalize_apply, recover_interrupted_apply, refuse_downgrade,
    rollback_apply, sha256_hex, validate_url_host, ArchiveKind, FetchKind, FetchRequest,
    HttpTransport, MapTransport, ReleaseMeta, SelectedRelease, TrustRoot, UpdateChannel,
    UpdateEngine, UpdateError, REQUIRED_BINARIES,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use tar::Builder;

struct TestKeys {
    trust: TrustRoot,
    sk: minisign::SecretKey,
}

fn test_keys() -> TestKeys {
    let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair().expect("keypair");
    let pk_box = pk.to_box().expect("pk box");
    let pub_file = pk_box.to_string();
    // minisign public key box already includes the untrusted comment line.
    TestKeys {
        trust: TrustRoot::from_public_key_file(pub_file),
        sk,
    }
}

fn sign_sums(sk: &minisign::SecretKey, sums: &[u8]) -> String {
    let signature_box = sign(None, sk, Cursor::new(sums), None, None).expect("sign");
    signature_box.into_string()
}

fn make_tar_gz(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut raw = Vec::new();
    {
        let mut builder = Builder::new(&mut raw);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, data.as_slice())
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoded = Vec::new();
    let mut gz = GzEncoder::new(&mut encoded, Compression::default());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap();
    encoded
}

fn fixture_binaries(os: &str) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        let name = binary_file_name_for(base, os);
        files.insert(name, format!("binary-{base}-v2").into_bytes());
    }
    files.insert("LICENSE".into(), b"license".to_vec());
    files
}

struct Bundle {
    trust: TrustRoot,
    sums: String,
    archive: Vec<u8>,
    sig: String,
    asset_name: String,
    meta: String,
}

fn build_release_bundle(version: &str) -> Bundle {
    let keys = test_keys();
    let files = fixture_binaries("linux");
    let archive = make_tar_gz(&files);
    let asset_name = "ownmesh-linux-x64.tar.gz".to_owned();
    let meta = ReleaseMeta {
        schema_version: 1,
        version: version.to_owned(),
        channel: "stable".into(),
        min_protocol: 1,
        max_protocol: 1,
    };
    let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
    let mut sums = String::new();
    sums.push_str(&format!("{}  {asset_name}\n", sha256_hex(&archive)));
    sums.push_str(&format!(
        "{}  ownmesh-release-meta.json\n",
        sha256_hex(&meta_bytes)
    ));
    let sig = sign_sums(&keys.sk, sums.as_bytes());
    Bundle {
        trust: keys.trust,
        sums,
        archive,
        sig,
        asset_name,
        meta: String::from_utf8(meta_bytes).unwrap(),
    }
}

fn selected(version: &str, asset_name: &str) -> SelectedRelease {
    SelectedRelease {
        tag_name: format!("v{version}"),
        version: version.to_owned(),
        prerelease: false,
        asset_name: asset_name.to_owned(),
        asset_url: format!(
            "https://github.com/Aero123421/OwnMesh/releases/download/v{version}/{asset_name}"
        ),
        sha256sums_url: format!(
            "https://github.com/Aero123421/OwnMesh/releases/download/v{version}/SHA256SUMS"
        ),
        sha256sums_sig_url: format!(
            "https://github.com/Aero123421/OwnMesh/releases/download/v{version}/SHA256SUMS.minisig"
        ),
        release_meta_url: format!(
            "https://github.com/Aero123421/OwnMesh/releases/download/v{version}/ownmesh-release-meta.json"
        ),
    }
}

fn map_for(bundle: &Bundle, version: &str) -> MapTransport {
    let base = format!("https://github.com/Aero123421/OwnMesh/releases/download/v{version}");
    MapTransport::default()
        .with_text(format!("{base}/SHA256SUMS"), bundle.sums.clone())
        .with_text(format!("{base}/SHA256SUMS.minisig"), bundle.sig.clone())
        .with_text(
            format!("{base}/ownmesh-release-meta.json"),
            bundle.meta.clone(),
        )
        .with_bytes(
            format!("{base}/{}", bundle.asset_name),
            bundle.archive.clone(),
        )
}

#[test]
fn good_signature_checksum_path_succeeds() {
    let bundle = build_release_bundle("1.2.0");
    let release = selected("1.2.0", &bundle.asset_name);
    let transport = map_for(&bundle, "1.2.0");
    let verified = download_and_verify(&transport, &bundle.trust, &release, 1).unwrap();
    assert_eq!(verified.meta.version, "1.2.0");
    let bins =
        extract_required_binaries(&verified.archive_bytes, ArchiveKind::TarGz, "linux").unwrap();
    assert_eq!(bins.len(), REQUIRED_BINARIES.len());
}

#[test]
fn bad_signature_fails_closed() {
    let bundle = build_release_bundle("1.2.0");
    let release = selected("1.2.0", &bundle.asset_name);
    let transport = map_for(&bundle, "1.2.0").with_text(
        "https://github.com/Aero123421/OwnMesh/releases/download/v1.2.0/SHA256SUMS.minisig",
        "untrusted comment: bad\nRWTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    );
    let err = download_and_verify(&transport, &bundle.trust, &release, 1).unwrap_err();
    assert!(matches!(err, UpdateError::BadSignature));
}

#[test]
fn bad_checksum_fails_closed() {
    let mut bundle = build_release_bundle("1.2.0");
    bundle.archive.push(b'x');
    let release = selected("1.2.0", &bundle.asset_name);
    let transport = map_for(&bundle, "1.2.0");
    let err = download_and_verify(&transport, &bundle.trust, &release, 1).unwrap_err();
    assert!(matches!(err, UpdateError::BadChecksum));
}

#[test]
fn downgrade_refused_on_engine_download() {
    assert!(matches!(
        refuse_downgrade("1.1.0", "1.0.0"),
        Err(UpdateError::DowngradeRefused(_))
    ));

    let bundle = build_release_bundle("1.0.0");
    let engine = UpdateEngine {
        current_version: "9.9.9".into(),
        trust: bundle.trust.clone(),
        platform_override: Some(("linux".into(), "x86_64".into())),
        ..UpdateEngine::default()
    };

    let latest = serde_json::json!({
        "tag_name": "v1.0.0",
        "draft": false,
        "prerelease": false,
        "assets": [
            {
                "name": bundle.asset_name,
                "size": bundle.archive.len(),
                "browser_download_url": format!(
                    "https://github.com/Aero123421/OwnMesh/releases/download/v1.0.0/{}",
                    bundle.asset_name
                )
            },
            {
                "name": "SHA256SUMS",
                "size": bundle.sums.len(),
                "browser_download_url": "https://github.com/Aero123421/OwnMesh/releases/download/v1.0.0/SHA256SUMS"
            },
            {
                "name": "SHA256SUMS.minisig",
                "size": bundle.sig.len(),
                "browser_download_url": "https://github.com/Aero123421/OwnMesh/releases/download/v1.0.0/SHA256SUMS.minisig"
            },
            {
                "name": "ownmesh-release-meta.json",
                "size": bundle.meta.len(),
                "browser_download_url": "https://github.com/Aero123421/OwnMesh/releases/download/v1.0.0/ownmesh-release-meta.json"
            }
        ]
    });
    let transport = map_for(&bundle, "1.0.0").with_text(
        "https://api.github.com/repos/Aero123421/OwnMesh/releases/latest",
        latest.to_string(),
    );
    let err = engine
        .download(&transport, UpdateChannel::Stable)
        .unwrap_err();
    assert!(matches!(err, UpdateError::DowngradeRefused(_)));
}

#[test]
fn redirect_host_refused() {
    assert!(validate_url_host("https://evil.example/SHA256SUMS").is_err());
    let transport =
        MapTransport::default().with_text("https://evil.example/SHA256SUMS", "deadbeef  x\n");
    let err = transport
        .fetch(&FetchRequest {
            url: "https://evil.example/SHA256SUMS".into(),
            kind: FetchKind::Checksums,
            headers: BTreeMap::new(),
        })
        .unwrap_err();
    assert!(matches!(err, UpdateError::RedirectHostRefused(_)));
}

#[test]
fn rollback_and_partial_set_refused() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    fs::create_dir_all(&install).unwrap();
    for base in REQUIRED_BINARIES {
        let name = binary_file_name(base);
        fs::write(install.join(&name), format!("old-{base}")).unwrap();
    }

    let mut good = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        let name = binary_file_name(base);
        good.insert(name, format!("new-{base}").into_bytes());
    }
    apply_binaries(&install, &good, "1.2.0").unwrap();
    assert_eq!(
        fs::read_to_string(install.join(binary_file_name("ownmesh"))).unwrap(),
        "new-ownmesh"
    );

    let mut partial = good;
    partial.remove(&binary_file_name("ownmesh-broker"));
    let err = apply_binaries(&install, &partial, "1.2.1").unwrap_err();
    assert!(matches!(err, UpdateError::Install(_)));
    assert_eq!(
        fs::read_to_string(install.join(binary_file_name("ownmesh"))).unwrap(),
        "new-ownmesh"
    );
    assert_eq!(
        fs::read_to_string(install.join(binary_file_name("ownmesh-broker"))).unwrap(),
        "new-ownmesh-broker"
    );
}

#[test]
fn interrupted_apply_recovers_all_five_binaries_and_finalize_commits() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    fs::create_dir_all(&install).unwrap();
    let mut next = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        let name = binary_file_name(base);
        fs::write(install.join(&name), format!("old-{base}")).unwrap();
        next.insert(name, format!("new-{base}").into_bytes());
    }

    let _report = apply_binaries(&install, &next, "1.2.11").unwrap();
    assert!(recover_interrupted_apply(&install).unwrap());
    for base in REQUIRED_BINARIES {
        assert_eq!(
            fs::read_to_string(install.join(binary_file_name(base))).unwrap(),
            format!("old-{base}")
        );
    }
    assert!(!recover_interrupted_apply(&install).unwrap());

    let report = apply_binaries(&install, &next, "1.2.11").unwrap();
    finalize_apply(&report).unwrap();
    assert!(!recover_interrupted_apply(&install).unwrap());
    for base in REQUIRED_BINARIES {
        assert_eq!(
            fs::read_to_string(install.join(binary_file_name(base))).unwrap(),
            format!("new-{base}")
        );
    }

    let report = apply_binaries(&install, &next, "1.2.12").unwrap();
    rollback_apply(&report).unwrap();
    assert!(!recover_interrupted_apply(&install).unwrap());
}

#[test]
fn interrupted_first_install_removes_every_new_binary() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let mut next = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        next.insert(binary_file_name(base), format!("new-{base}").into_bytes());
    }

    let report = apply_binaries(&install, &next, "1.2.11").unwrap();
    assert!(report.backup_dir.as_ref().is_some_and(|path| path.is_dir()));
    assert!(recover_interrupted_apply(&install).unwrap());
    for base in REQUIRED_BINARIES {
        assert!(!install.join(binary_file_name(base)).exists());
    }
    assert!(!recover_interrupted_apply(&install).unwrap());
}

#[test]
fn unsafe_version_label_is_refused_before_staging() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let mut bins = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        bins.insert(binary_file_name(base), b"new".to_vec());
    }
    let error = apply_binaries(&install, &bins, "../escape").unwrap_err();
    assert!(matches!(error, UpdateError::Install(_)));
    assert!(!install.join(".ownmesh-staging-../escape").exists());
}

#[test]
fn corrupted_rollback_backup_is_refused_without_overwriting_new_binary() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    fs::create_dir_all(&install).unwrap();
    let mut bins = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        let name = binary_file_name(base);
        fs::write(install.join(&name), format!("old-{base}")).unwrap();
        bins.insert(name, format!("new-{base}").into_bytes());
    }
    let report = apply_binaries(&install, &bins, "1.2.11").unwrap();
    let backup = report.backup_dir.as_ref().unwrap();
    fs::write(backup.join(binary_file_name("ownmesh")), b"tampered").unwrap();

    let error = recover_interrupted_apply(&install).unwrap_err();
    assert!(matches!(error, UpdateError::Install(_)));
    assert_eq!(
        fs::read_to_string(install.join(binary_file_name("ownmesh"))).unwrap(),
        "new-ownmesh"
    );
}

#[test]
fn homebrew_path_refuses_self_update() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir
        .path()
        .join("Cellar")
        .join("ownmesh")
        .join("1.1.0")
        .join("bin");
    fs::create_dir_all(&install).unwrap();
    let mut bins = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        bins.insert(binary_file_name(base), b"x".to_vec());
    }
    let err = apply_binaries(&install, &bins, "1.2.0").unwrap_err();
    assert!(matches!(err, UpdateError::HomebrewManaged));
}

#[test]
fn traversal_member_rejected() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("../../tmp/evil", options).unwrap();
        zip.write_all(b"x").unwrap();
        zip.finish().unwrap();
    }
    let archive = cursor.into_inner();
    let result = extract_required_binaries(&archive, ArchiveKind::Zip, "windows");
    assert!(result.is_err());
}

#[test]
fn protocol_incompatible_fails() {
    let keys = test_keys();
    let files = fixture_binaries("linux");
    let archive = make_tar_gz(&files);
    let asset_name = "ownmesh-linux-x64.tar.gz".to_owned();
    let meta = ReleaseMeta {
        schema_version: 1,
        version: "1.2.0".into(),
        channel: "stable".into(),
        min_protocol: 9,
        max_protocol: 9,
    };
    let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
    let mut sums = String::new();
    sums.push_str(&format!("{}  {asset_name}\n", sha256_hex(&archive)));
    sums.push_str(&format!(
        "{}  ownmesh-release-meta.json\n",
        sha256_hex(&meta_bytes)
    ));
    let sig = sign_sums(&keys.sk, sums.as_bytes());
    let bundle = Bundle {
        trust: keys.trust,
        sums,
        archive,
        sig,
        asset_name: asset_name.clone(),
        meta: String::from_utf8(meta_bytes).unwrap(),
    };
    let release = selected("1.2.0", &bundle.asset_name);
    let transport = map_for(&bundle, "1.2.0");
    let err = download_and_verify(&transport, &bundle.trust, &release, 1).unwrap_err();
    assert!(matches!(err, UpdateError::ProtocolIncompatible(_)));
}

#[test]
fn zip_bomb_entry_count_rejected() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default();
        // Exceed MAX_ARCHIVE_ENTRIES (64).
        for i in 0..80 {
            zip.start_file(format!("pad-{i}.txt"), options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap();
    }
    let archive = cursor.into_inner();
    let err = extract_required_binaries(&archive, ArchiveKind::Zip, "windows").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("entry count") || msg.contains("limit"),
        "{msg}"
    );
}

#[test]
fn zip_unexpected_and_duplicate_members_rejected() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("ownmesh.exe", options).unwrap();
        zip.write_all(b"bin").unwrap();
        zip.start_file("evil-extra.dll", options).unwrap();
        zip.write_all(b"x").unwrap();
        zip.finish().unwrap();
    }
    let archive = cursor.into_inner();
    let err = extract_required_binaries(&archive, ArchiveKind::Zip, "windows").unwrap_err();
    assert!(
        err.to_string().contains("unexpected") || err.to_string().contains("missing"),
        "{err}"
    );

    // Duplicate required binary.
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default();
        for base in REQUIRED_BINARIES {
            let name = binary_file_name_for(base, "windows");
            zip.start_file(&name, options).unwrap();
            zip.write_all(b"a").unwrap();
        }
        // Second ownmesh.exe
        zip.start_file("wrapper/ownmesh.exe", options).unwrap();
        zip.write_all(b"b").unwrap();
        zip.finish().unwrap();
    }
    let archive = cursor.into_inner();
    let err = extract_required_binaries(&archive, ArchiveKind::Zip, "windows").unwrap_err();
    assert!(
        err.to_string().contains("duplicate") || err.to_string().contains("unexpected"),
        "{err}"
    );
}

#[test]
fn tar_symlink_and_bomb_rejected() {
    // Symlink member.
    let mut raw = Vec::new();
    {
        let mut builder = Builder::new(&mut raw);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "ownmesh", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    let mut encoded = Vec::new();
    {
        let mut gz = GzEncoder::new(&mut encoded, Compression::default());
        gz.write_all(&raw).unwrap();
        gz.finish().unwrap();
    }
    let err = extract_required_binaries(&encoded, ArchiveKind::TarGz, "linux").unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("symlink")
            || err.to_string().contains("link"),
        "{err}"
    );

    // Entry-count bomb.
    let mut raw = Vec::new();
    {
        let mut builder = Builder::new(&mut raw);
        for i in 0..80 {
            let mut header = tar::Header::new_gnu();
            let data = b"x";
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("pad-{i}.txt"), &data[..])
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoded = Vec::new();
    {
        let mut gz = GzEncoder::new(&mut encoded, Compression::default());
        gz.write_all(&raw).unwrap();
        gz.finish().unwrap();
    }
    let err = extract_required_binaries(&encoded, ArchiveKind::TarGz, "linux").unwrap_err();
    assert!(
        err.to_string().contains("entry count") || err.to_string().contains("unexpected"),
        "{err}"
    );
}
