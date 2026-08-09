use ownmesh_transfer::{
    ChunkSink, JournalLimits, JournalState, JournalStore, PartFileSink, PlanLimits,
    TransferBinding, TransferChunk, TransferError, TransferGrant, TransferPlan, TransferReceiver,
    TransferSender, MAX_CHUNK_BYTES,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;
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
    let plan =
        TransferPlan::for_source(&source, binding(), grant(), PlanLimits::default(), 1).unwrap();
    let mut sender = TransferSender::open(plan.clone(), &source).unwrap();
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
    publish_sink.write_chunk(0, b"hello").unwrap();
    publish_sink.finalize().unwrap();
    let destination = dir.path().join("existing.bin");
    std::fs::write(&destination, b"do not replace").unwrap();
    assert_eq!(
        publish_sink.publish_no_replace(&destination).unwrap_err(),
        TransferError::DestinationExists
    );
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
fn source_mutation_is_detected_before_streaming() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.bin");
    std::fs::write(&source, b"first").unwrap();
    let plan =
        TransferPlan::for_source(&source, binding(), grant(), PlanLimits::default(), 1).unwrap();
    std::fs::write(&source, b"other").unwrap();
    let mut sender = TransferSender::open(plan, &source).unwrap();
    assert_eq!(
        sender.next_chunk().unwrap_err(),
        TransferError::SourceChanged
    );
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
    let expired = TransferPlan::from_verified(binding(), expired_grant, 1, digest(b"x")).unwrap();
    assert!(matches!(
        TransferSender::open(expired.clone(), &source),
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
