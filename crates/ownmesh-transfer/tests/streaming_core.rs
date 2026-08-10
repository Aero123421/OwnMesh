use ownmesh_fs::WorkspaceRoot;
use ownmesh_transfer::{
    ChunkSink, JournalLimits, JournalState, JournalStore, PartFileSink, PlanLimits,
    TransferBinding, TransferChunk, TransferError, TransferGrant, TransferPlan, TransferReceiver,
    MAX_CHUNK_BYTES,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn binding() -> TransferBinding {
    TransferBinding {
        tenant_id: "tenant-a".into(),
        source_principal_id: "user-a".into(),
        destination_principal_id: "user-b".into(),
        source_device_id: "device-a".into(),
        destination_device_id: "device-b".into(),
        source_workspace_id: "workspace-a".into(),
        destination_workspace_id: "workspace-b".into(),
        source_relative_path: "input.bin".into(),
        destination_relative_path: "output.bin".into(),
    }
}

fn grant() -> TransferGrant {
    TransferGrant {
        grant_id: "grant-1".into(),
        operation_id: "operation-1".into(),
        payload_sha256: "a".repeat(64),
        expires_at_unix: u64::MAX,
    }
}

fn make_plan(bytes: &[u8]) -> TransferPlan {
    TransferPlan::from_verified(binding(), grant(), bytes.len() as u64, digest(bytes)).unwrap()
}

fn workspace(dir: &std::path::Path) -> WorkspaceRoot {
    WorkspaceRoot::new(dir, true).unwrap()
}

#[derive(Default)]
struct TestSink(Vec<u8>);
impl ChunkSink for TestSink {
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        if offset != self.0.len() as u64 {
            return Err("offset".into());
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn finalize(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn cancel(&mut self) -> Result<(), String> {
        self.0.clear();
        Ok(())
    }
}

#[test]
fn binary_three_chunk_stream_round_trips_with_bounded_frames() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.bin");
    let bytes: Vec<u8> = (0..(MAX_CHUNK_BYTES * 2 + 31))
        .map(|i| u8::try_from(i % 251).expect("modulo is below u8 maximum"))
        .collect();
    std::fs::write(&source, &bytes).unwrap();
    let ws = workspace(dir.path());
    let plan = TransferPlan::for_workspace_source(
        ws.open_verified_read("source.bin").unwrap(),
        binding(),
        grant(),
        PlanLimits::default(),
        1,
    )
    .unwrap();
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let mut sender = store
        .open_source_sender_at(
            plan.clone(),
            ws.open_verified_read("source.bin").unwrap(),
            0,
            0,
        )
        .unwrap();
    let mut receiver = TransferReceiver::new(plan, "owner-a", 1, 1, 9_000).unwrap();
    let mut sink = TestSink::default();
    let mut count = 0;
    while let Some(chunk) = sender.next_chunk().unwrap() {
        assert!(chunk.bytes.len() <= MAX_CHUNK_BYTES);
        receiver
            .receive(
                &mut sink,
                TransferChunk::decode(&chunk.encode().unwrap()).unwrap(),
            )
            .unwrap();
        count += 1;
    }
    assert_eq!(count, 3);
    assert_eq!(sink.0, bytes);
    assert_eq!(receiver.journal().state(), JournalState::Completed);
}

#[test]
fn duplicate_gap_hash_and_overflow_are_rejected() {
    let bytes = b"checked data";
    let plan = make_plan(bytes);
    let mut receiver = TransferReceiver::new(plan, "owner-a", 1, 1, 9_000).unwrap();
    let mut sink = TestSink::default();
    let first = TransferChunk::new(0, 0, bytes[..4].to_vec()).unwrap();
    receiver.receive(&mut sink, first.clone()).unwrap();
    assert_eq!(
        receiver.receive(&mut sink, first).unwrap_err(),
        TransferError::Replay
    );
    let gap = TransferChunk::new(2, 4, bytes[4..].to_vec()).unwrap();
    assert_eq!(
        receiver.receive(&mut sink, gap).unwrap_err(),
        TransferError::Gap
    );
    let mut corrupt = TransferChunk::new(1, 4, bytes[4..].to_vec()).unwrap();
    corrupt.bytes[0] ^= 0x80;
    assert_eq!(
        receiver.receive(&mut sink, corrupt).unwrap_err(),
        TransferError::ChunkHashMismatch
    );
    assert_eq!(
        TransferChunk::new(0, u64::MAX, vec![1, 2]).unwrap_err(),
        TransferError::Overflow
    );

    let wrong_plan = make_plan(b"abc");
    let mut wrong_receiver = TransferReceiver::new(wrong_plan, "owner-a", 1, 1, 9_000).unwrap();
    let mut wrong_sink = TestSink::default();
    assert_eq!(
        wrong_receiver
            .receive(
                &mut wrong_sink,
                TransferChunk::new(0, 0, b"abd".to_vec()).unwrap()
            )
            .unwrap_err(),
        TransferError::HashMismatch
    );
    assert_eq!(wrong_receiver.journal().state(), JournalState::Failed);
}

#[test]
fn resume_hashes_private_part_without_reading_whole_file() {
    let dir = tempdir().unwrap();
    let bytes = vec![7_u8; MAX_CHUNK_BYTES + 9];
    let plan = make_plan(&bytes);
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let mut sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let mut receiver = TransferReceiver::new(plan.clone(), "owner-a", 1, 1, 9_000).unwrap();
    receiver
        .receive(
            &mut sink,
            TransferChunk::new(0, 0, bytes[..MAX_CHUNK_BYTES].to_vec()).unwrap(),
        )
        .unwrap();
    let journal = receiver.journal_snapshot();
    let part = sink.path().to_path_buf();
    drop(sink);
    let mut resumed = TransferReceiver::resume_from_part(plan.clone(), journal, &part).unwrap();
    let mut resumed_sink = PartFileSink::create(&store, &plan, 1, MAX_CHUNK_BYTES as u64).unwrap();
    resumed
        .receive(
            &mut resumed_sink,
            TransferChunk::new(1, MAX_CHUNK_BYTES as u64, bytes[MAX_CHUNK_BYTES..].to_vec())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(resumed.journal().state(), JournalState::Completed);
}

#[test]
fn part_cancel_only_deletes_its_own_private_part_and_publish_refuses_overwrite() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"hello");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let mut sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let part = sink.path().to_path_buf();
    let mut receiver = TransferReceiver::new(plan.clone(), "owner-a", 1, 1, 9_000).unwrap();
    receiver.cancel(&mut sink).unwrap();
    assert!(!part.exists());

    let mut publish_sink = PartFileSink::create(&store, &plan, 2, 0).unwrap();
    let mut publish_receiver =
        TransferReceiver::new(plan.clone(), "owner-a", 2, 1, u64::MAX).unwrap();
    publish_receiver
        .receive(
            &mut publish_sink,
            TransferChunk::new(0, 0, b"hello".to_vec()).unwrap(),
        )
        .unwrap();
    drop(publish_sink);
    let journal = publish_receiver.journal_snapshot();
    let lease = store.acquire(&plan, 1, u64::MAX).unwrap();
    store.save(&lease, &journal).unwrap();
    let destination = dir.path().join("output.bin");
    std::fs::write(&destination, b"do not replace").unwrap();
    let publish_error = store
        .publish_completed_no_replace(&plan, &workspace(dir.path()))
        .unwrap_err();
    assert_eq!(publish_error, TransferError::DestinationExists);
    assert_eq!(std::fs::read(&destination).unwrap(), b"do not replace");
}

#[test]
fn durable_journal_fences_corruption_and_quota_fail_closed() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"one");
    let store = JournalStore::open(
        dir.path().join("state"),
        JournalLimits {
            max_journals: 1,
            max_bytes: 1024,
            max_snapshots: 1,
            max_snapshot_bytes: 1024,
            max_plans: 1,
            max_plan_bytes: 1024,
        },
    )
    .unwrap();
    let lease = store.acquire(&plan, 1, 9_000).unwrap();
    let journal = store
        .claim(&lease, &plan, "owner-a", 1, 1, 1, 9_000)
        .unwrap();
    store.save(&lease, &journal).unwrap();
    let other_plan = make_plan(b"two");
    let other_lease = store.acquire(&other_plan, 1, 9_000).unwrap();
    assert_eq!(
        store
            .claim(&other_lease, &other_plan, "owner-a", 1, 1, 1, 9_000)
            .unwrap_err(),
        TransferError::JournalQuotaExceeded
    );
    assert_eq!(
        store
            .claim(&lease, &plan, "owner-a", 1, 1, 1, 9_000)
            .unwrap_err(),
        TransferError::StaleFence
    );
    drop(lease);
    let path = store.root().join(format!(".{}.json", plan.id()));
    std::fs::write(&path, b"not-json").unwrap();
    assert_eq!(
        store.load(&plan).unwrap_err(),
        TransferError::CorruptJournal
    );
}

#[test]
fn stale_lease_drop_cannot_remove_a_fresh_cross_process_unique_lease() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"lease");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let stale = store.acquire(&plan, 1, 2).unwrap();
    // This models a restarted/new process reclaiming an expired lock while an
    // old holder remains alive long enough to run its Drop implementation.
    let fresh = store.acquire(&plan, 3, 9_000).unwrap();
    drop(stale);
    assert!(
        matches!(
            store.acquire(&plan, 3, 9_000),
            Err(TransferError::LeaseBusy)
        ),
        "old lease release must not unlink a fresh UUID-bound lock"
    );
    drop(fresh);
}

#[test]
fn newer_fence_reclaims_crash_orphan_and_retired_holder_cannot_save() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"resume");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let retired = store.acquire_for_fence(&plan, 1, 9_000, 1, 1).unwrap();
    let old = store
        .claim(&retired, &plan, "owner-a", 1, 1, 1, 9_000)
        .unwrap();

    // Model a coordinator fence advance while the previous process/operation
    // never got to release its durable lease record.
    let current = store.acquire_for_fence(&plan, 2, 9_000, 2, 2).unwrap();
    let resumed = store
        .claim(&current, &plan, "owner-a", 2, 2, 2, 9_000)
        .unwrap();
    assert_eq!(resumed.epoch(), 2);
    assert_eq!(resumed.fence(), 2);
    assert_eq!(store.save(&retired, &old), Err(TransferError::StaleFence));
    drop(retired);
    assert!(matches!(
        store.acquire(&plan, 2, 9_000),
        Err(TransferError::LeaseBusy)
    ));
    drop(current);
    assert!(store.acquire(&plan, 2, 9_000).is_ok());
}

#[test]
fn fresh_fence_rolls_local_save_back_to_room_ack_cursor() {
    let dir = tempdir().unwrap();
    let bytes: Vec<u8> = (0..(MAX_CHUNK_BYTES * 2 + 17))
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let plan = make_plan(&bytes);
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let first_lease = store.acquire_for_fence(&plan, 1, 9_000, 1, 1).unwrap();
    let first_journal = store
        .claim_at_room_cursor(&first_lease, &plan, "owner-a", 1, 1, 1, 9_000, 0, 0)
        .unwrap();
    let mut first_sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let first_path = first_sink.path().to_path_buf();
    let mut first_receiver =
        TransferReceiver::resume_from_part(plan.clone(), first_journal, &first_path).unwrap();
    for sequence in 0..2_u64 {
        let offset = usize::try_from(sequence).unwrap() * MAX_CHUNK_BYTES;
        first_receiver
            .receive(
                &mut first_sink,
                TransferChunk::new(
                    sequence,
                    offset as u64,
                    bytes[offset..offset + MAX_CHUNK_BYTES].to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
        store
            .save(&first_lease, &first_receiver.journal_snapshot())
            .unwrap();
    }
    assert_eq!(
        std::fs::read(&first_path).unwrap(),
        bytes[..MAX_CHUNK_BYTES * 2]
    );
    drop(first_sink);

    // Model a crash after the second local journal save but before its Room
    // ACK. Only the first chunk is in the relay's durable cursor.
    let second_lease = store.acquire_for_fence(&plan, 2, 9_000, 2, 2).unwrap();
    assert_eq!(
        store.claim_at_room_cursor(
            &second_lease,
            &plan,
            "owner-a",
            2,
            2,
            2,
            9_000,
            3,
            (MAX_CHUNK_BYTES * 2 + 17) as u64,
        ),
        Err(TransferError::Gap),
        "Room cursor may never move local progress forward",
    );
    assert_eq!(
        store.claim_at_room_cursor(
            &second_lease,
            &plan,
            "owner-a",
            2,
            2,
            2,
            9_000,
            1,
            (MAX_CHUNK_BYTES + 1) as u64,
        ),
        Err(TransferError::Gap),
        "sequence/offset pair must be a canonical source chunk boundary",
    );
    assert_eq!(
        std::fs::read(&first_path).unwrap(),
        bytes[..MAX_CHUNK_BYTES * 2]
    );

    let resumed = store
        .claim_at_room_cursor(
            &second_lease,
            &plan,
            "owner-a",
            2,
            2,
            2,
            9_000,
            1,
            MAX_CHUNK_BYTES as u64,
        )
        .unwrap();
    assert_eq!(resumed.state(), JournalState::Receiving);
    assert_eq!(resumed.contiguous_ack(), Some(0));
    assert_eq!(resumed.bytes_received(), MAX_CHUNK_BYTES as u64);
    let second_sink = PartFileSink::create(&store, &plan, 2, resumed.bytes_received()).unwrap();
    assert_ne!(second_sink.path(), first_path);
    assert_eq!(
        std::fs::read(second_sink.path()).unwrap(),
        bytes[..MAX_CHUNK_BYTES]
    );
    assert!(
        !first_path.exists(),
        "retired generation is removed after prefix staging"
    );
}

#[test]
fn room_cursor_at_size_rehashes_the_fresh_generation_part() {
    let dir = tempdir().unwrap();
    let bytes: Vec<u8> = (0..(MAX_CHUNK_BYTES + 17))
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let plan = make_plan(&bytes);
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let first_lease = store.acquire_for_fence(&plan, 1, 9_000, 1, 1).unwrap();
    let first_journal = store
        .claim_at_room_cursor(&first_lease, &plan, "owner-a", 1, 1, 1, 9_000, 0, 0)
        .unwrap();
    let mut first_sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let mut receiver =
        TransferReceiver::resume_from_part(plan.clone(), first_journal, first_sink.path()).unwrap();
    receiver
        .receive(
            &mut first_sink,
            TransferChunk::new(0, 0, bytes[..MAX_CHUNK_BYTES].to_vec()).unwrap(),
        )
        .unwrap();
    receiver
        .receive(
            &mut first_sink,
            TransferChunk::new(1, MAX_CHUNK_BYTES as u64, bytes[MAX_CHUNK_BYTES..].to_vec())
                .unwrap(),
        )
        .unwrap();
    store
        .save(&first_lease, &receiver.journal_snapshot())
        .unwrap();
    drop(first_sink);

    let second_lease = store.acquire_for_fence(&plan, 2, 9_000, 2, 2).unwrap();
    let completed = store
        .claim_at_room_cursor(
            &second_lease,
            &plan,
            "owner-a",
            2,
            2,
            2,
            9_000,
            2,
            bytes.len() as u64,
        )
        .unwrap();
    assert_eq!(completed.state(), JournalState::Completed);
    let mut second_sink =
        PartFileSink::create(&store, &plan, 2, completed.bytes_received()).unwrap();
    second_sink.verify_complete().unwrap();
    let second_path = second_sink.path().to_path_buf();
    drop(second_sink);
    let mut substituted = std::fs::read(&second_path).unwrap();
    substituted[0] ^= 0xff;
    std::fs::write(&second_path, substituted).unwrap();
    let mut reopened = PartFileSink::create(&store, &plan, 2, completed.bytes_received()).unwrap();
    assert!(matches!(
        reopened.verify_complete(),
        Err(TransferError::Sink(_))
    ));
}

#[test]
fn retired_holder_late_write_is_isolated_from_new_generation_part() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"abclate!");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let retired_lease = store.acquire_for_fence(&plan, 1, 9_000, 1, 1).unwrap();
    let retired_journal = store
        .claim(&retired_lease, &plan, "owner-a", 1, 1, 1, 9_000)
        .unwrap();
    let mut retired_sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let retired_path = retired_sink.path().to_path_buf();
    let mut retired_receiver =
        TransferReceiver::resume_from_part(plan.clone(), retired_journal, &retired_path).unwrap();
    retired_receiver
        .receive(
            &mut retired_sink,
            TransferChunk::new(0, 0, b"abc".to_vec()).unwrap(),
        )
        .unwrap();
    store
        .save(&retired_lease, &retired_receiver.journal_snapshot())
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = Arc::clone(&barrier);
    let retired_store = store.clone();
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        retired_receiver
            .receive(
                &mut retired_sink,
                TransferChunk::new(1, 3, b"late".to_vec()).unwrap(),
            )
            .unwrap();
        retired_store.save(&retired_lease, &retired_receiver.journal_snapshot())
    });

    let current_lease = store.acquire_for_fence(&plan, 2, 9_000, 2, 2).unwrap();
    let current_journal = store
        .claim(&current_lease, &plan, "owner-a", 2, 2, 2, 9_000)
        .unwrap();
    let first_attempt = PartFileSink::create(&store, &plan, 2, current_journal.bytes_received());
    assert!(first_attempt.is_ok() || matches!(&first_attempt, Err(TransferError::LeaseBusy)));
    barrier.wait();
    assert_eq!(writer.join().unwrap(), Err(TransferError::StaleFence));
    let (current_sink, _current_lease) = match first_attempt {
        Ok(sink) => (sink, current_lease),
        Err(TransferError::LeaseBusy) => {
            drop(current_lease);
            let next_lease = store.acquire_for_fence(&plan, 3, 9_000, 3, 3).unwrap();
            let next_journal = store
                .claim(&next_lease, &plan, "owner-a", 3, 3, 3, 9_000)
                .unwrap();
            (
                PartFileSink::create(&store, &plan, 3, next_journal.bytes_received()).unwrap(),
                next_lease,
            )
        }
        Err(error) => panic!("unexpected generation staging error: {error}"),
    };
    let current_path = current_sink.path().to_path_buf();
    assert_ne!(retired_path, current_path);
    assert_eq!(std::fs::read(&current_path).unwrap(), b"abc");
}

#[test]
fn fresh_fence_recovers_after_generation_staging_conflict() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"abc1234567");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let first_lease = store.acquire_for_fence(&plan, 1, 9_000, 1, 1).unwrap();
    let first_journal = store
        .claim(&first_lease, &plan, "owner-a", 1, 1, 1, 9_000)
        .unwrap();
    let mut first_sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let mut receiver =
        TransferReceiver::resume_from_part(plan.clone(), first_journal, first_sink.path()).unwrap();
    receiver
        .receive(
            &mut first_sink,
            TransferChunk::new(0, 0, b"abc".to_vec()).unwrap(),
        )
        .unwrap();
    store
        .save(&first_lease, &receiver.journal_snapshot())
        .unwrap();
    drop(first_sink);
    drop(first_lease);

    // Model a Windows staging conflict: the journal claim committed epoch 2,
    // while removing an open retired epoch-1 part failed and the staged epoch-2
    // part was rolled back. A fresh coordinator generation must still recover.
    let conflicted_lease = store.acquire_for_fence(&plan, 2, 9_000, 2, 2).unwrap();
    let conflicted = store
        .claim(&conflicted_lease, &plan, "owner-a", 2, 2, 2, 9_000)
        .unwrap();
    assert_eq!(conflicted.bytes_received(), 3);
    drop(conflicted_lease);

    let fresh_lease = store.acquire_for_fence(&plan, 3, 9_000, 3, 3).unwrap();
    let fresh = store
        .claim(&fresh_lease, &plan, "owner-a", 3, 3, 3, 9_000)
        .unwrap();
    let fresh_sink = PartFileSink::create(&store, &plan, 3, fresh.bytes_received()).unwrap();
    assert_eq!(std::fs::read(fresh_sink.path()).unwrap(), b"abc");
    let parts: Vec<_> = std::fs::read_dir(store.root())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .collect();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].path(), fresh_sink.path());
}

#[test]
fn repeated_fence_resume_keeps_one_bounded_generation_part() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"abc1234567");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let first_lease = store.acquire_for_fence(&plan, 1, 9_000, 1, 1).unwrap();
    let first_journal = store
        .claim(&first_lease, &plan, "owner-a", 1, 1, 1, 9_000)
        .unwrap();
    let mut first_sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let mut receiver =
        TransferReceiver::resume_from_part(plan.clone(), first_journal, first_sink.path()).unwrap();
    receiver
        .receive(
            &mut first_sink,
            TransferChunk::new(0, 0, b"abc".to_vec()).unwrap(),
        )
        .unwrap();
    store
        .save(&first_lease, &receiver.journal_snapshot())
        .unwrap();
    drop(first_sink);
    drop(first_lease);

    for epoch in 2..=24_u64 {
        let lease = store
            .acquire_for_fence(&plan, epoch, 9_000, epoch, epoch)
            .unwrap();
        let journal = store
            .claim(&lease, &plan, "owner-a", epoch, epoch, epoch, 9_000)
            .unwrap();
        let sink = PartFileSink::create(&store, &plan, epoch, journal.bytes_received()).unwrap();
        assert_eq!(std::fs::read(sink.path()).unwrap(), b"abc");
        let parts: Vec<_> = std::fs::read_dir(store.root())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
            .collect();
        assert_eq!(
            parts.len(),
            1,
            "retired generation parts must not accumulate"
        );
        assert_eq!(parts[0].metadata().unwrap().len(), 3);
        drop(sink);
        drop(lease);
    }
}

#[test]
fn startup_cleanup_removes_only_expired_owned_part() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"hello");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let lease = store.acquire(&plan, 1, 2).unwrap();
    store.save_plan(&plan).unwrap();
    let journal = store.claim(&lease, &plan, "owner-a", 1, 1, 1, 2).unwrap();
    let sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let part = sink.path().to_path_buf();
    drop(sink);
    store.save(&lease, &journal).unwrap();
    assert_eq!(store.cleanup_expired(3).unwrap(), 1);
    assert!(!part.exists());
    assert!(store.load(&plan).unwrap().is_none());
    assert!(store.load_plan(plan.id(), 3).unwrap().is_none());
}

#[test]
fn private_plan_round_trips_and_rechecks_its_grant() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"plan");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    store.save_plan(&plan).unwrap();
    assert_eq!(store.load_plan(plan.id(), 1).unwrap(), Some(plan));
}

#[test]
fn source_only_plan_and_snapshot_retries_are_aggregate_quota_bounded() {
    let dir = tempdir().unwrap();
    let store = JournalStore::open(
        dir.path().join("state"),
        JournalLimits {
            max_journals: 4,
            max_bytes: 4096,
            max_snapshots: 1,
            max_snapshot_bytes: 8,
            max_plans: 2,
            max_plan_bytes: 4096,
        },
    )
    .unwrap();
    let first = make_plan(b"one");
    let second = make_plan(b"two");
    let third = make_plan(b"three");
    store.save_plan(&first).unwrap();
    store.save_plan(&second).unwrap();
    assert_eq!(
        store.save_plan(&third).unwrap_err(),
        TransferError::JournalQuotaExceeded,
        "fresh source preflights cannot accumulate plan records without a journal",
    );

    let source = dir.path().join("input.bin");
    std::fs::write(&source, b"one").unwrap();
    let ws = workspace(dir.path());
    let _sender = store
        .open_source_sender_at(
            first.clone(),
            ws.open_verified_read("input.bin").unwrap(),
            0,
            0,
        )
        .unwrap();
    std::fs::write(&source, b"two").unwrap();
    assert!(matches!(
        store.open_source_sender_at(second, ws.open_verified_read("input.bin").unwrap(), 0, 0),
        Err(TransferError::JournalQuotaExceeded)
    ));
}

#[test]
fn concurrent_store_clones_cannot_overadmit_plan_or_snapshot_quotas() {
    let dir = tempdir().unwrap();
    let limits = JournalLimits {
        max_journals: 4,
        max_bytes: 4096,
        max_snapshots: 1,
        max_snapshot_bytes: 8,
        max_plans: 1,
        max_plan_bytes: 4096,
    };
    let store = JournalStore::open(dir.path().join("plans"), limits).unwrap();
    let first = make_plan(b"one");
    let mut second_binding = binding();
    second_binding.source_relative_path = "input-two.bin".into();
    let second = TransferPlan::from_verified(second_binding, grant(), 3, digest(b"two")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_store = store.clone();
    let second_store = store.clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first_task = scope.spawn(move || {
            first_barrier.wait();
            first_store.save_plan(&first)
        });
        let second_task = scope.spawn(move || {
            second_barrier.wait();
            second_store.save_plan(&second)
        });
        (first_task.join().unwrap(), second_task.join().unwrap())
    });
    assert_eq!(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
        1,
        "store-wide reservation must admit only one plan"
    );

    let snapshot_store = JournalStore::open(dir.path().join("snapshots"), limits).unwrap();
    std::fs::write(dir.path().join("input-one.bin"), b"one").unwrap();
    std::fs::write(dir.path().join("input-two.bin"), b"two").unwrap();
    let first = make_plan(b"one");
    let mut second_binding = binding();
    second_binding.source_relative_path = "input-two.bin".into();
    let second = TransferPlan::from_verified(second_binding, grant(), 3, digest(b"two")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_store = snapshot_store.clone();
    let second_store = snapshot_store.clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let root = dir.path().to_path_buf();
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first_task = scope.spawn({
            let root = root.clone();
            move || {
                first_barrier.wait();
                let ws = WorkspaceRoot::new(root, true).unwrap();
                first_store.open_source_sender_at(
                    first,
                    ws.open_verified_read("input-one.bin").unwrap(),
                    0,
                    0,
                )
            }
        });
        let second_task = scope.spawn(move || {
            second_barrier.wait();
            let ws = WorkspaceRoot::new(root, true).unwrap();
            second_store.open_source_sender_at(
                second,
                ws.open_verified_read("input-two.bin").unwrap(),
                0,
                0,
            )
        });
        (first_task.join().unwrap(), second_task.join().unwrap())
    });
    assert_eq!(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
        1,
        "store-wide reservation must admit only one snapshot: {:?} {:?}",
        first_result.as_ref().err(),
        second_result.as_ref().err()
    );
}

#[test]
fn concurrent_source_staging_succeeds_when_two_snapshot_reservations_fit() {
    let dir = tempdir().unwrap();
    let store = JournalStore::open(
        dir.path().join("state"),
        JournalLimits {
            max_journals: 4,
            max_bytes: 4096,
            max_snapshots: 2,
            max_snapshot_bytes: 8,
            max_plans: 2,
            max_plan_bytes: 4096,
        },
    )
    .unwrap();
    std::fs::write(dir.path().join("one.bin"), b"one").unwrap();
    std::fs::write(dir.path().join("two.bin"), b"two").unwrap();
    let first = make_plan(b"one");
    let mut second_binding = binding();
    second_binding.source_relative_path = "two.bin".into();
    let second = TransferPlan::from_verified(second_binding, grant(), 3, digest(b"two")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_store = store.clone();
    let second_store = store.clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let root = dir.path().to_path_buf();
    let (first, second) = std::thread::scope(|scope| {
        let first_task = scope.spawn({
            let root = root.clone();
            move || {
                first_barrier.wait();
                let ws = WorkspaceRoot::new(root, true).unwrap();
                first_store.open_source_sender_at(
                    first,
                    ws.open_verified_read("one.bin").unwrap(),
                    0,
                    0,
                )
            }
        });
        let second_task = scope.spawn(move || {
            second_barrier.wait();
            let ws = WorkspaceRoot::new(root, true).unwrap();
            second_store.open_source_sender_at(
                second,
                ws.open_verified_read("two.bin").unwrap(),
                0,
                0,
            )
        });
        (first_task.join().unwrap(), second_task.join().unwrap())
    });
    assert!(
        first.is_ok() && second.is_ok(),
        "fitting reservations must both stage: {:?} {:?}",
        first.as_ref().err(),
        second.as_ref().err()
    );
}

#[test]
fn startup_cleanup_removes_expired_source_only_plan_snapshot_pair() {
    let dir = tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut short_grant = grant();
    short_grant.expires_at_unix = now + 60;
    let plan = TransferPlan::from_verified(binding(), short_grant, 3, digest(b"one")).unwrap();
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    store.save_plan(&plan).unwrap();
    std::fs::write(dir.path().join("input.bin"), b"one").unwrap();
    let ws = workspace(dir.path());
    let sender = store
        .open_source_sender_at(
            plan.clone(),
            ws.open_verified_read("input.bin").unwrap(),
            0,
            0,
        )
        .unwrap();
    drop(sender);
    let source = store.root().join(format!(".{}.source", plan.id()));
    let plan_path = store.root().join(format!(".{}.plan.json", plan.id()));
    assert!(source.exists() && plan_path.exists());
    assert_eq!(store.cleanup_expired(now + 61).unwrap(), 1);
    assert!(!source.exists() && !plan_path.exists());
}

#[test]
fn source_terminal_cleanup_removes_its_plan_and_snapshot() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"terminal-source");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    store.save_plan(&plan).unwrap();
    std::fs::write(dir.path().join("input.bin"), b"terminal-source").unwrap();
    let ws = workspace(dir.path());
    drop(
        store
            .open_source_sender_at(
                plan.clone(),
                ws.open_verified_read("input.bin").unwrap(),
                0,
                0,
            )
            .unwrap(),
    );
    let source = store.root().join(format!(".{}.source", plan.id()));
    let plan_path = store.root().join(format!(".{}.plan.json", plan.id()));
    assert!(source.exists() && plan_path.exists());

    store.remove_source_terminal_state(&plan).unwrap();
    assert!(!source.exists() && !plan_path.exists());
}

#[test]
fn source_terminal_cleanup_never_hides_snapshot_unlink_failure() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"cleanup-failure");
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    store.save_plan(&plan).unwrap();
    std::fs::write(dir.path().join("input.bin"), b"cleanup-failure").unwrap();
    let ws = workspace(dir.path());
    drop(
        store
            .open_source_sender_at(
                plan.clone(),
                ws.open_verified_read("input.bin").unwrap(),
                0,
                0,
            )
            .unwrap(),
    );
    let source = store.root().join(format!(".{}.source", plan.id()));
    let plan_path = store.root().join(format!(".{}.plan.json", plan.id()));
    std::fs::remove_file(&source).unwrap();
    std::fs::create_dir(&source).unwrap();

    assert_eq!(
        store.remove_source_terminal_state(&plan),
        Err(TransferError::CustodyUnavailable)
    );
    assert!(
        plan_path.exists(),
        "plan must remain retryable after cleanup failure"
    );
}

#[test]
fn source_mutation_is_detected_before_streaming() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.bin");
    std::fs::write(&source, b"first").unwrap();
    let ws = workspace(dir.path());
    let plan = TransferPlan::for_workspace_source(
        ws.open_verified_read("source.bin").unwrap(),
        binding(),
        grant(),
        PlanLimits::default(),
        1,
    )
    .unwrap();
    std::fs::write(&source, b"other").unwrap();
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    assert!(matches!(
        store.open_source_sender_at(plan, ws.open_verified_read("source.bin").unwrap(), 0, 0),
        Err(TransferError::SourceChanged)
    ));
}

#[test]
fn source_snapshot_retains_the_verified_file_across_path_replacement() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.bin");
    let original = b"verified source".to_vec();
    std::fs::write(&source, &original).unwrap();
    let ws = workspace(dir.path());
    let plan = TransferPlan::for_workspace_source(
        ws.open_verified_read("source.bin").unwrap(),
        binding(),
        grant(),
        PlanLimits::default(),
        1,
    )
    .unwrap();
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    let mut sender = store
        .open_source_sender_at(
            plan.clone(),
            ws.open_verified_read("source.bin").unwrap(),
            0,
            0,
        )
        .unwrap();

    // Simulate a rename/replacement race after admission. Every emitted byte
    // must still come from the owner-only verified snapshot, not this path.
    std::fs::rename(&source, dir.path().join("source.old")).unwrap();
    std::fs::write(&source, b"attacker changed").unwrap();
    let mut sent = Vec::new();
    while let Some(chunk) = sender.next_chunk().unwrap() {
        sent.extend_from_slice(&chunk.bytes);
    }
    assert_eq!(sent, original);
    drop(sender);
    store.remove_source_snapshot(&plan).unwrap();
}

#[cfg(unix)]
#[test]
fn source_symlink_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let target = dir.path().join("target.bin");
    let link = dir.path().join("source.bin");
    std::fs::write(&target, b"private target").unwrap();
    symlink(&target, &link).unwrap();
    let ws = workspace(dir.path());
    assert!(matches!(ws.open_verified_read("source.bin"), Err(_)));
}

#[test]
fn relative_paths_and_generic_nonempty_resume_fail_closed() {
    let mut bad = binding();
    bad.destination_relative_path = "../escape".into();
    assert!(TransferPlan::from_verified(bad, grant(), 1, digest(b"x")).is_err());
    let plan = make_plan(b"x");
    let mut receiver = TransferReceiver::new(plan.clone(), "owner-a", 1, 1, 9_000).unwrap();
    let mut sink = TestSink::default();
    receiver
        .receive(&mut sink, TransferChunk::new(0, 0, b"x".to_vec()).unwrap())
        .unwrap();
    let mut cursor = Cursor::new(b"x".to_vec());
    assert!(matches!(
        TransferReceiver::resume_from_reader(plan, receiver.journal_snapshot(), &mut cursor),
        Err(TransferError::Terminal)
    ));
}

#[test]
fn expired_grants_are_rejected_at_every_live_side_effect_boundary() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.bin");
    std::fs::write(&source, b"x").unwrap();
    let mut expired_grant = grant();
    expired_grant.expires_at_unix = 1;
    let expired =
        TransferPlan::from_verified(binding(), expired_grant.clone(), 1, digest(b"x")).unwrap();
    let ws = workspace(dir.path());
    assert!(matches!(
        TransferPlan::for_workspace_source(
            ws.open_verified_read("source.bin").unwrap(),
            binding(),
            expired_grant,
            PlanLimits::default(),
            1
        ),
        Err(TransferError::InvalidPlan(_))
    ));
    assert!(matches!(
        TransferReceiver::new(expired.clone(), "owner-a", 1, 1, 9_000),
        Err(TransferError::InvalidPlan(_))
    ));
    let store = JournalStore::open(dir.path().join("state"), JournalLimits::default()).unwrap();
    assert!(matches!(
        PartFileSink::create(&store, &expired, 1, 0),
        Err(TransferError::InvalidPlan(_))
    ));
}

#[test]
fn substituted_private_part_and_stale_lock_are_never_reused() {
    let dir = tempdir().unwrap();
    let plan = make_plan(b"x");
    let root = dir.path().join("state");
    let store = JournalStore::open(&root, JournalLimits::default()).unwrap();
    let sink = PartFileSink::create(&store, &plan, 1, 0).unwrap();
    let part = sink.path().to_path_buf();
    drop(sink);
    std::fs::remove_file(&part).unwrap();
    std::fs::create_dir(&part).unwrap();
    assert!(matches!(
        PartFileSink::create(&store, &plan, 1, 0),
        Err(TransferError::CustodyUnavailable)
    ));

    let lock = root.join(format!(".{}.lock", plan.id()));
    std::fs::write(&lock, format!("{}\n1\n", plan.id())).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    assert!(matches!(
        store.acquire(&plan, 2, 9_000),
        Err(TransferError::LeaseBusy)
    ));
}
