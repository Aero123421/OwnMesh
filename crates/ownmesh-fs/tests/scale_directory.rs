//! Issue #230 Phase 1: production-scale filesystem boundaries.
//!
//! These tests create thousands of real files and must NOT run in the default
//! PR suite. Run explicitly:
//!
//! ```bash
//! cargo test --locked -p ownmesh-fs --test scale_directory \
//!   -- --ignored --test-threads=1
//! ```
//!
//! Nightly/weekly/manual runs all scale tests. Each test isolates spool IO via
//! `OWNMESH_STATE_DIR` under its own temp dir; single-thread execution avoids
//! the process-global env var racing between tests.

use ownmesh_fs::{list_dir_page, write_file, WorkspaceRoot};
use std::collections::HashSet;
use tempfile::tempdir;

/// Former `scan_budget=4000` trap with real 4,500 files.
#[test]
#[ignore = "scale: creates 4,500 real filesystem entries"]
fn production_pagination_walks_past_four_thousand_entries() {
    const N: usize = 4_500;
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
    for i in 0..N {
        let name = format!("f{i:05}.txt");
        write_file(&ws, &name, b"x").unwrap();
    }
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0_usize;
    loop {
        pages += 1;
        assert!(pages < 200, "pagination failed to terminate");
        let page = list_dir_page(&ws, "", false, 200, cursor.as_deref()).unwrap();
        for entry in &page.entries {
            assert!(
                seen.insert(entry.name.clone()),
                "duplicate entry across pages: {}",
                entry.name
            );
        }
        if !page.truncated {
            break;
        }
        cursor = page.next_cursor;
        assert!(cursor.is_some(), "truncated page must carry next_cursor");
    }
    assert_eq!(
        seen.len(),
        N,
        "expected every entry once across {pages} pages"
    );
}

/// Production 25,000 in-memory bound with 25,050 real files via durable spool.
#[test]
#[ignore = "scale: creates 25,050 real filesystem entries"]
fn production_directory_spool_boundary() {
    const N: usize = 25_050;
    let dir = tempdir().unwrap();
    std::env::set_var("OWNMESH_STATE_DIR", dir.path().join("state"));
    let ws = WorkspaceRoot::new(dir.path().join("tree"), true).unwrap();
    std::fs::create_dir_all(ws.root()).unwrap();
    for i in 0..N {
        let name = format!("g{i:05}.txt");
        write_file(&ws, &name, b"x").unwrap();
    }
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0_usize;
    let mut saw_v2 = false;
    loop {
        pages += 1;
        assert!(pages < 400, "pagination failed to terminate");
        let page = list_dir_page(&ws, "", false, 200, cursor.as_deref()).unwrap();
        for entry in &page.entries {
            assert!(
                seen.insert(entry.name.clone()),
                "duplicate entry across pages: {}",
                entry.name
            );
        }
        if let Some(c) = page.next_cursor.as_deref() {
            if c.starts_with("v2:") {
                saw_v2 = true;
            }
        }
        if !page.truncated {
            break;
        }
        cursor = page.next_cursor;
        assert!(cursor.is_some(), "truncated page must carry next_cursor");
    }
    assert!(
        saw_v2,
        "expected durable v2 spool cursor for >25k directory"
    );
    assert_eq!(seen.len(), N, "expected every entry once via spool pages");
}

/// v2 cursor bound to workspace root with a production-size tree.
#[test]
#[ignore = "scale: creates 25,050 real filesystem entries for cursor binding"]
fn production_v2_cursor_bound_to_root() {
    const N: usize = 25_050;
    let dir = tempdir().unwrap();
    std::env::set_var("OWNMESH_STATE_DIR", dir.path().join("state"));
    let ws_a = WorkspaceRoot::new(dir.path().join("a"), true).unwrap();
    let ws_b = WorkspaceRoot::new(dir.path().join("b"), true).unwrap();
    std::fs::create_dir_all(ws_a.root()).unwrap();
    std::fs::create_dir_all(ws_b.root()).unwrap();
    for i in 0..N {
        write_file(&ws_a, format!("a{i:05}.txt"), b"x").unwrap();
    }
    write_file(&ws_b, "only-b.txt", b"b").unwrap();
    let page_a = list_dir_page(&ws_a, "", false, 10, None).unwrap();
    assert!(page_a.truncated);
    let cursor = page_a.next_cursor.expect("v2 cursor");
    assert!(cursor.starts_with("v2:"), "cursor={cursor}");
    let err = list_dir_page(&ws_b, "", false, 10, Some(cursor.as_str())).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not match") || msg.contains("cursor"),
        "expected request-identity bind failure, got {msg}"
    );
    let page_a2 = list_dir_page(&ws_a, "", false, 10, Some(cursor.as_str())).unwrap();
    assert!(!page_a2.entries.is_empty());
}

/// Aggregate byte budget with 8,000 long-but-legal basenames.
#[test]
#[ignore = "scale: creates 8,000 real files with 200-char names"]
fn production_aggregate_byte_budget() {
    const M: usize = 8_000;
    let dir = tempdir().unwrap();
    std::env::set_var("OWNMESH_STATE_DIR", dir.path().join("state"));
    let ws = WorkspaceRoot::new(dir.path().join("tree"), true).unwrap();
    std::fs::create_dir_all(ws.root()).unwrap();
    for i in 0..M {
        let name = format!("N{i:05}_{}.txt", "x".repeat(200));
        write_file(&ws, &name, b"x").unwrap();
    }
    match list_dir_page(&ws, "", false, 50, None) {
        Ok(page) => {
            let json = serde_json::to_vec(&page.entries).unwrap();
            assert!(json.len() <= 96_000 + 8_192);
            assert!(!page.entries.is_empty());
        }
        Err(e) => {
            assert!(
                e.to_string().contains("limit") || e.to_string().contains("Entry"),
                "unexpected error: {e}"
            );
        }
    }
}
