//! Deterministic input/focus regressions; no daemon, network, or real user state.

use super::*;
use ownmesh_policy::AccessPreset;
use tempfile::{tempdir, TempDir};

fn fixture() -> (TempDir, App, tokio::runtime::Runtime) {
    let dir = tempdir().expect("isolated app");
    let app = App::new(OwnMeshPaths::for_base(dir.path()), None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    (dir, app, rt)
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn repeat(code: KeyCode) -> KeyEvent {
    KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Repeat)
}

#[test]
fn dashboard_tab_and_shift_tab_are_inverses_and_wrap() {
    let (_dir, mut app, rt) = fixture();
    for back in [
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
        KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT),
    ] {
        app.overview_action_cursor = 0;
        handle_key(&mut app, press(KeyCode::Tab), &rt);
        assert_eq!(app.overview_action_cursor, 1);
        handle_key(&mut app, back, &rt);
        assert_eq!(app.overview_action_cursor, 0);
        handle_key(&mut app, back, &rt);
        assert_eq!(app.overview_action_cursor, app.overview_actions().len() - 1);
        assert_eq!(app.screen, Screen::Dashboard);
    }
    app.goto_screen(Screen::Settings);
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT),
        &rt,
    );
    assert_eq!(app.screen, Screen::Approvals);
}

#[test]
fn modified_letters_do_not_trigger_plain_shortcuts() {
    let (_dir, mut app, rt) = fixture();
    app.set_approvals_from_json(&serde_json::json!({
        "approvals": [{"id": "a1", "state": "pending", "capability": "fs.read"}]
    }));
    for modifiers in [
        KeyModifiers::CONTROL,
        KeyModifiers::ALT,
        KeyModifiers::SUPER,
    ] {
        app.goto_screen(Screen::Approvals);
        for c in ['a', 'd', 'q', 'w', '1', 'r'] {
            handle_key(&mut app, KeyEvent::new(KeyCode::Char(c), modifiers), &rt);
        }
        assert!(!app.should_quit);
        assert_eq!(app.take_pending_approval(), None);
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(app.screen, Screen::Approvals);
        app.goto_screen(Screen::Settings);
        let preset = app.policy_preset;
        let lang = app.lang;
        for c in ['p', 'l'] {
            handle_key(&mut app, KeyEvent::new(KeyCode::Char(c), modifiers), &rt);
        }
        assert_eq!(app.policy_preset, preset);
        assert_eq!(app.lang, lang);
    }
}

#[test]
fn ctrl_k_toggles_without_losing_the_underlying_dialog() {
    let (_dir, mut app, rt) = fixture();
    app.open_setup_wizard();
    app.wizard.step = WizardStep::Server;
    app.wizard.control_plane_url = "https://draft.example".into();
    let ctrl_k = KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL);
    handle_key(&mut app, ctrl_k, &rt);
    assert!(app.palette.open);
    let mut repeated = ctrl_k;
    repeated.kind = KeyEventKind::Repeat;
    handle_key(&mut app, repeated, &rt);
    assert!(app.palette.open);
    handle_key(&mut app, ctrl_k, &rt);
    assert!(!app.palette.open);
    assert_eq!(app.overlay, Overlay::Wizard);
    assert_eq!(app.wizard.control_plane_url, "https://draft.example");
    handle_key(
        &mut app,
        KeyEvent::new(
            KeyCode::Char('K'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ),
        &rt,
    );
    assert!(app.palette.open);
}

#[test]
fn palette_navigation_reveals_its_destination_from_every_overlay() {
    let (_dir, mut app, rt) = fixture();
    for overlay in [
        Overlay::Wizard,
        Overlay::Help,
        Overlay::Connector,
        Overlay::CustodyRepair,
    ] {
        app.overlay = overlay;
        app.open_palette();
        app.palette.query = "goto.devices".into();
        handle_key(&mut app, press(KeyCode::Enter), &rt);
        assert_eq!(app.screen, Screen::Devices);
        assert_eq!(app.overlay, Overlay::None);
        assert!(!app.palette.open);
        assert!(app.take_pending_setup().is_none());
    }
}

#[test]
fn cancelling_or_running_an_empty_palette_keeps_the_underlying_dialog() {
    let (_dir, mut app, rt) = fixture();
    app.overlay = Overlay::Wizard;
    app.open_palette();
    app.palette.query = "no-such-command-123456".into();
    handle_key(&mut app, press(KeyCode::Enter), &rt);
    assert!(app.palette.open);
    assert_eq!(app.overlay, Overlay::Wizard);
    handle_key(&mut app, press(KeyCode::Esc), &rt);
    assert!(!app.palette.open);
    assert_eq!(app.overlay, Overlay::Wizard);
}

#[test]
fn palette_can_replace_one_dialog_with_another() {
    let (_dir, mut app, rt) = fixture();
    app.overlay = Overlay::Help;
    app.open_palette();
    app.palette.query = "onboarding".into();
    handle_key(&mut app, press(KeyCode::Enter), &rt);
    assert_eq!(app.overlay, Overlay::Wizard);
    app.open_palette();
    app.palette.query = "f1".into();
    handle_key(&mut app, press(KeyCode::Enter), &rt);
    assert_eq!(app.overlay, Overlay::Help);
}

#[test]
fn paste_goes_to_the_focused_palette_not_the_hidden_wizard() {
    let (_dir, mut app, _rt) = fixture();
    app.open_setup_wizard();
    app.wizard.step = WizardStep::Server;
    app.wizard.control_plane_url = "https://draft.example".into();
    app.open_palette();
    app.palette.cursor = 4;
    handle_paste(&mut app, "goto.devices\r\n\t");
    assert_eq!(app.palette.query, "goto.devices");
    assert_eq!(app.palette.cursor, 0);
    assert_eq!(app.wizard.control_plane_url, "https://draft.example");
    assert_eq!(app.screen, Screen::Dashboard);
    assert!(app.take_pending_setup().is_none());
}

#[test]
fn paste_outside_a_text_field_does_nothing() {
    let (_dir, mut app, _rt) = fixture();
    for overlay in [
        Overlay::None,
        Overlay::Help,
        Overlay::Connector,
        Overlay::Wizard,
    ] {
        app.overlay = overlay;
        app.wizard.step = WizardStep::Welcome;
        let url = app.wizard.control_plane_url.clone();
        handle_paste(&mut app, "q\r\nw\r\na\r\n");
        assert_eq!(app.wizard.control_plane_url, url);
        assert!(!app.should_quit);
        assert!(app.take_pending_setup().is_none());
        assert_eq!(app.take_pending_approval(), None);
    }
}

#[test]
fn typing_and_pasting_share_a_utf8_safe_byte_limit() {
    let (_dir, mut app, rt) = fixture();
    app.open_setup_wizard();
    app.wizard.step = WizardStep::Server;
    app.wizard.control_plane_url = "x".repeat(MAX_INPUT_BYTES - 1);
    handle_key(&mut app, press(KeyCode::Char('界')), &rt);
    assert_eq!(app.wizard.control_plane_url.len(), MAX_INPUT_BYTES - 1);
    handle_key(&mut app, press(KeyCode::Char('x')), &rt);
    assert_eq!(app.wizard.control_plane_url.len(), MAX_INPUT_BYTES);
    handle_paste(&mut app, "extra");
    assert_eq!(app.wizard.control_plane_url.len(), MAX_INPUT_BYTES);

    app.wizard.control_plane_url = "x".repeat(MAX_INPUT_BYTES - 3);
    handle_paste(&mut app, "界extra");
    assert_eq!(app.wizard.control_plane_url.len(), MAX_INPUT_BYTES);
    assert!(app.wizard.control_plane_url.ends_with('界'));
    app.open_palette();
    handle_paste(&mut app, &"界".repeat(MAX_INPUT_BYTES));
    assert!(app.palette.query.len() <= MAX_INPUT_BYTES);
    assert!(app.palette.query.is_char_boundary(app.palette.query.len()));
}

#[test]
fn repeat_and_release_events_do_not_confirm_or_submit_actions() {
    let (_dir, mut app, rt) = fixture();
    app.open_setup_wizard();
    app.wizard.step = WizardStep::Welcome;
    handle_key(&mut app, press(KeyCode::Enter), &rt);
    assert_eq!(app.wizard.step, WizardStep::Language);
    handle_key(&mut app, repeat(KeyCode::Enter), &rt);
    assert_eq!(app.wizard.step, WizardStep::Language);
    assert!(app.take_pending_setup().is_none());
    app.overlay = Overlay::None;
    app.goto_screen(Screen::Approvals);
    app.set_approvals_from_json(&serde_json::json!({
        "approvals": [{"id": "a1", "state": "pending", "capability": "fs.read"}]
    }));
    for code in [KeyCode::Char('a'), KeyCode::Char('d')] {
        handle_key(&mut app, repeat(code), &rt);
        assert_eq!(app.take_pending_approval(), None);
    }
    let mut release = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    release.kind = KeyEventKind::Release;
    handle_key(&mut app, release, &rt);
    assert!(!app.should_quit);
    handle_key(&mut app, press(KeyCode::Char('d')), &rt);
    assert_eq!(
        app.take_pending_approval(),
        Some(PendingApproval {
            id: "a1".into(),
            decision: ApprovalDecision::Deny,
        })
    );
}

#[test]
fn cursor_movement_and_text_editing_still_repeat() {
    let (_dir, mut app, rt) = fixture();
    handle_key(&mut app, repeat(KeyCode::Down), &rt);
    assert_eq!(app.overview_action_cursor, 1);
    app.open_palette();
    handle_key(&mut app, repeat(KeyCode::Char('x')), &rt);
    assert_eq!(app.palette.query, "x");
    handle_key(&mut app, repeat(KeyCode::Backspace), &rt);
    assert!(app.palette.query.is_empty());
}

#[test]
fn sessions_refresh_updates_rows_and_clamps_selection() {
    let (_dir, mut app, _rt) = fixture();
    app.goto_screen(Screen::Sessions);
    let sessions = serde_json::json!({
        "sessions": [{"id": "s1", "state": "active"}, {"id": "s2", "state": "active"}]
    });
    apply_sessions_refresh(&mut app, Ok(sessions));
    app.move_list_cursor(1);
    assert_eq!(app.list_cursor, 1);
    let empty = serde_json::json!({"sessions": []});
    apply_sessions_refresh(&mut app, Ok(empty));
    assert!(app.sessions.is_empty());
    assert_eq!(app.list_cursor, 0);
    assert!(app.status_line.ends_with(": 0"));
}

#[test]
fn failed_sessions_refresh_preserves_rows_and_reports_the_error() {
    let (_dir, mut app, _rt) = fixture();
    app.sessions = vec!["s1 active".into()];
    let error = ownmesh_ipc::IpcError::Protocol("offline".into());
    apply_sessions_refresh(&mut app, Err(error));
    assert_eq!(app.sessions, vec!["s1 active"]);
    assert!(app.status_line.contains("offline"));
}

#[test]
fn local_refresh_preserves_edits_but_invalidates_changed_inventory_source() {
    let (_dir, mut app, _rt) = fixture();
    app.lang = Lang::JaJp;
    app.policy_preset = AccessPreset::FullAccess;
    app.wizard.control_plane_url = "https://unsaved.example".into();
    app.readiness.server_url = Some("https://old.example".into());
    app.readiness.account_present = true;
    app.readiness.agent_running = true;
    app.device_inventory = DeviceInventory::Empty;
    app.overview_action_cursor = usize::MAX;
    let error = ownmesh_ipc::IpcError::Protocol("offline".into());
    apply_local_refresh(&mut app, Err(error));
    assert_eq!(app.lang, Lang::JaJp);
    assert_eq!(app.policy_preset, AccessPreset::FullAccess);
    assert_eq!(app.wizard.control_plane_url, "https://unsaved.example");
    assert!(!app.readiness.agent_running);
    assert!(app.daemon.is_none());
    assert!(matches!(
        app.device_inventory,
        DeviceInventory::NotConfigured
    ));
    assert!(app.overview_action_cursor < app.overview_actions().len());
    assert!(app.status_line.contains("offline"));
}
