#![allow(clippy::too_many_lines)]

use ownmesh_fs::{apply_unified_diff, read_file, write_file, FsError, WorkspaceRoot};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[test]
fn rejects_legacy_and_mixed_multi_file_headers_without_writing() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    let before = b"alpha\nbeta\n";
    for first in ["", "diff --git a/note.txt b/note.txt\n"] {
        for second in ["", "diff --git a/other.txt b/other.txt\n"] {
            for separator in ["", "\n", "index 1234567..7654321 100644\n"] {
                write_file(&ws, "note.txt", before).unwrap();
                let diff = format!(
                    "{first}--- a/note.txt\n+++ b/note.txt\n@@ -1 +1 @@\n-alpha\n+ALPHA\n{separator}{second}--- a/other.txt\n+++ b/other.txt\n@@ -2 +2 @@\n-beta\n+BETA\n"
                );
                assert!(
                    matches!(
                        apply_unified_diff(&ws, "note.txt", &diff, None),
                        Err(FsError::Patch(_))
                    ),
                    "accepted multiple file patches: {diff:?}"
                );
                assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), before);
            }
        }
    }
}

#[test]
fn inserts_after_zero_length_old_range() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    write_file(&ws, "note.txt", b"one\ntwo\nthree\n").unwrap();
    let diff = concat!(
        "--- a/note.txt\n",
        "+++ b/note.txt\n",
        "@@ -1,0 +2,1 @@\n",
        "+insert\n",
    );

    let expected = b"one\ninsert\ntwo\nthree\n";
    let actual_hash = apply_unified_diff(&ws, "note.txt", diff, None).unwrap();

    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), expected);
    assert_eq!(actual_hash, hash(expected));
}

#[test]
fn preserves_crlf_line_endings_when_applying_patch() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    write_file(&ws, "note.txt", b"alpha\r\nbeta\r\ngamma\r\n").unwrap();
    let diff = concat!(
        "--- a/note.txt\r\n",
        "+++ b/note.txt\r\n",
        "@@ -1,3 +1,3 @@\r\n",
        " alpha\r\n",
        "-beta\r\n",
        "+BETA\r\n",
        " gamma\r\n",
    );

    let expected = b"alpha\r\nBETA\r\ngamma\r\n";
    let actual_hash = apply_unified_diff(&ws, "note.txt", diff, None).unwrap();

    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), expected);
    assert_eq!(actual_hash, hash(expected));
}

#[test]
fn honors_newline_markers_for_created_and_final_lines() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    let create = concat!(
        "--- /dev/null\n",
        "+++ b/note.txt\n",
        "@@ -0,0 +1,2 @@\n",
        "+created\n",
        "+\n",
    );
    let created = b"created\n\n";
    let actual_hash = apply_unified_diff(&ws, "note.txt", create, None).unwrap();
    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), created);
    assert_eq!(actual_hash, hash(created));

    let replace = concat!(
        "--- a/note.txt\n",
        "+++ b/note.txt\n",
        "@@ -2 +2 @@\n",
        "-\n",
        "+final\n",
        "\\ No newline at end of file\n",
    );
    // The create patch leaves two empty lines. Replace the final empty line
    // and explicitly request a post-image without an EOF newline.
    let final_bytes = b"created\nfinal";
    let actual_hash = apply_unified_diff(&ws, "note.txt", replace, None).unwrap();
    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), final_bytes);
    assert_eq!(actual_hash, hash(final_bytes));
}

#[test]
fn honors_missing_newline_marker_as_post_image_newline() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    write_file(&ws, "note.txt", b"created\nfinal").unwrap();
    let diff = concat!(
        "--- a/note.txt\n",
        "+++ b/note.txt\n",
        "@@ -2 +2 @@\n",
        "-final\n",
        "\\ No newline at end of file\n",
        "+updated\n",
    );

    let expected = b"created\nupdated\n";
    let actual_hash = apply_unified_diff(&ws, "note.txt", diff, None).unwrap();
    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), expected);
    assert_eq!(actual_hash, hash(expected));
}

#[test]
fn rejects_malformed_hunk_without_mutating_target() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    let before = b"alpha\nbeta\n";
    write_file(&ws, "note.txt", before).unwrap();
    let diff = concat!(
        "--- a/note.txt\n",
        "+++ b/note.txt\n",
        "@@ -1,2 +1,2 @@\n",
        " alpha\n",
        "-BETA\n",
        "+gamma\n",
    );

    let err = apply_unified_diff(&ws, "note.txt", diff, None).unwrap_err();
    assert!(matches!(err, FsError::Patch(_)), "{err:?}");
    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), before);
}

#[test]
fn rejects_non_ascii_invalid_hunk_tag_without_panicking() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    write_file(&ws, "note.txt", b"alpha\n").unwrap();
    let diff = concat!(
        "--- a/note.txt\n",
        "+++ b/note.txt\n",
        "@@ -1 +1 @@\n",
        "éinvalid\n",
    );

    let err = apply_unified_diff(&ws, "note.txt", diff, None).unwrap_err();
    assert!(matches!(err, FsError::Patch(_)), "{err:?}");
}

#[test]
fn rejects_mid_hunk_newline_marker_without_mutating_target() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    let before = b"old\n";
    write_file(&ws, "note.txt", before).unwrap();
    let diff = concat!(
        "--- a/note.txt\n",
        "+++ b/note.txt\n",
        "@@ -0,0 +1,2 @@\n",
        "+first\n",
        "\\ No newline at end of file\n",
        "+second\n",
    );

    let err = apply_unified_diff(&ws, "note.txt", diff, None).unwrap_err();
    assert!(matches!(err, FsError::Patch(_)), "{err:?}");
    assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), before);
}

#[test]
fn rejects_excess_hunk_records_without_mutating_target() {
    let extras = [
        "+extra\n",
        " extra\n",
        "-extra\n",
        "+++ extra\n",
        "--- extra\n",
        "\\ invalid\n",
    ];
    for extra in extras {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
        let before = b"old\n";
        write_file(&ws, "note.txt", before).unwrap();
        let diff = format!("--- a/note.txt\n+++ b/note.txt\n@@ -1 +1 @@\n-old\n+new\n{extra}");

        let result = apply_unified_diff(&ws, "note.txt", &diff, None);
        assert!(
            matches!(result, Err(FsError::Patch(_))),
            "extra={extra:?}: {result:?}"
        );
        assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), before);
    }
}

/// Fixtures generated with:
///
/// ```text
/// git -c core.autocrlf=false diff --no-ext-diff --no-textconv --no-index -U0 -- old.txt new.txt
/// ```
#[test]
fn applies_git_generated_fixtures_byte_for_byte() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path().join("workspace"), false).unwrap();
    std::fs::create_dir_all(ws.root()).unwrap();
    let fixtures = [
        (
            b"one\ntwo\nthree\n".as_slice(),
            b"one\ninsert\ntwo\nthree\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index 4cb29ea..3b754d0 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -1,0 +2 @@ one\n",
                "+insert\n",
            ),
        ),
        (
            b"alpha\r\nbeta\r\ngamma\r\n".as_slice(),
            b"alpha\r\nBETA\r\ngamma\r\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index b4ec4d1..c6d393e 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -2 +2 @@ alpha\n",
                "-beta\r\n",
                "+BETA\r\n",
            ),
        ),
        (
            b"first\nsecond\r\nthird\n".as_slice(),
            b"first\nSECOND\r\nthird\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index 44f36ff..06ae2a7 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -2 +2 @@ first\n",
                "-second\r\n",
                "+SECOND\r\n",
            ),
        ),
        (
            b"keep\n-- text\nend\n".as_slice(),
            b"keep\nchanged\nend\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index 0cf50c3..ef90919 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -2 +2 @@ keep\n",
                "--- text\n",
                "+changed\n",
            ),
        ),
        (
            b"alpha\r\nbeta\r\n".as_slice(),
            b"alpha\nbeta\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index 17f2fc0..fbbee86 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -1,2 +1,2 @@\n",
                "-alpha\r\n",
                "-beta\r\n",
                "+alpha\n",
                "+beta\n",
            ),
        ),
        (
            b"alpha\nbeta\n".as_slice(),
            b"alpha\r\nbeta\r\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index fbbee86..17f2fc0 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -1,2 +1,2 @@\n",
                "-alpha\n",
                "-beta\n",
                "+alpha\r\n",
                "+beta\r\n",
            ),
        ),
        (
            b"prefix\r\nlast\r".as_slice(),
            b"prefix\r\nLAST\r".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index f1b3c06..e726119 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -2 +2 @@ prefix\n",
                "-last\r\n",
                "\\ No newline at end of file\n",
                "+LAST\r\n",
                "\\ No newline at end of file\n",
            ),
        ),
        (
            b"gone\n".as_slice(),
            b"".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index 286c5f5..e69de29 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -1 +0,0 @@\n",
                "-gone\n",
            ),
        ),
        (
            b"before\n".as_slice(),
            b"before\n\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index 90be1f3..3140f73 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -1,0 +2 @@ before\n",
                "+\n",
            ),
        ),
        (
            b"".as_slice(),
            b"created\n\n".as_slice(),
            concat!(
                "diff --git a/old.txt b/new.txt\n",
                "index e69de29..d3379d8 100644\n",
                "--- a/old.txt\n",
                "+++ b/new.txt\n",
                "@@ -0,0 +1,2 @@\n",
                "+created\n",
                "+\n",
            ),
        ),
    ];

    for (index, (old, new, diff)) in fixtures.iter().enumerate() {
        write_file(&ws, "note.txt", old).unwrap();
        let expected_hash = hash(new);
        let actual_hash = apply_unified_diff(&ws, "note.txt", diff, None).unwrap();
        assert_eq!(actual_hash, expected_hash, "fixture {index} hash");
        assert_eq!(read_file(&ws, "note.txt", 1024).unwrap(), *new);
    }
}
