use super::*;
use crate::authority::recovery::vector_tests::{
    DEFAULT_PROFILE, JournalPath, TestAnchor, fund_root,
};

struct Directory(PathBuf);

impl Directory {
    fn create() -> Self {
        let parent = std::env::temp_dir();
        let nonce = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("oip-archive-test-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn journal() -> (JournalPath, AnchorHead) {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    fund_root(&mut service);
    (path, anchor.head())
}

fn archive_ref(source: &mut File, head: AnchorHead) -> ArchiveRef {
    let prefix_bytes = head.offset.checked_add(head.length).unwrap();
    let prefix_sha256 = copy_prefix(source, prefix_bytes, &mut io::sink()).unwrap();
    ArchiveRef {
        head,
        prefix_bytes,
        prefix_sha256,
    }
}

#[test]
fn archive_checks_exact_head_profile_length_and_whole_prefix() {
    let (path, head) = journal();
    let dir = Directory::create();
    let archive = JournalArchive::new(&dir.0, DEFAULT_PROFILE, u64::MAX).unwrap();
    let mut source = path.file();
    let expected = archive_ref(&mut source, head);
    archive.verify(&mut source, expected).unwrap();

    let bad_profile = RecoveryProfile {
        deployment: 8,
        ..DEFAULT_PROFILE
    };
    assert!(
        JournalArchive::new(&dir.0, bad_profile, u64::MAX)
            .unwrap()
            .verify(&mut source, expected)
            .is_err()
    );
    let bad_head = AnchorHead {
        offset: u64::MAX,
        ..head
    };
    assert!(
        archive
            .verify(
                &mut source,
                ArchiveRef {
                    head: bad_head,
                    ..expected
                }
            )
            .is_err()
    );
    let mut bad = expected;
    bad.head.digest[0] ^= 1;
    assert!(archive.verify(&mut source, bad).is_err());
    assert!(JournalArchive::new(Path::new("relative"), DEFAULT_PROFILE, u64::MAX).is_err());
    assert!(
        JournalArchive::new(&dir.0, DEFAULT_PROFILE, expected.prefix_bytes - 1)
            .unwrap()
            .verify(&mut source, expected)
            .is_err()
    );

    source.seek(SeekFrom::Start(0)).unwrap();
    let mut original = Vec::new();
    source.read_to_end(&mut original).unwrap();
    let destination = archive.archive_path(expected);
    fs::write(dir.0.join(".pending-partial"), &original[..10]).unwrap();
    assert!(archive.open_verified(expected).is_err());
    fs::write(&destination, &original[..original.len() - 1]).unwrap();
    assert!(archive.open_verified(expected).is_err());

    let mut mutated = original;
    mutated[0] ^= 1;
    fs::write(&destination, &mutated).unwrap();
    assert!(archive.open_verified(expected).is_err());
    let wrong_prefix = ArchiveRef {
        prefix_sha256: Sha256::digest(&mutated).into(),
        ..expected
    };
    // Even a newly computed digest cannot hide the broken predecessor chain.
    assert!(
        archive
            .verify(&mut File::open(&destination).unwrap(), wrong_prefix)
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn archive_linux_retain_and_restore_use_only_the_selected_prefix() {
    let (path, head) = journal();
    let dir = Directory::create();
    let archive = JournalArchive::new(&dir.0, DEFAULT_PROFILE, u64::MAX).unwrap();
    let mut source = path.file();
    let expected = archive_ref(&mut source, head);
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut original = Vec::new();
    source.read_to_end(&mut original).unwrap();
    source.seek(SeekFrom::End(0)).unwrap();
    source.write_all(b"unanchored suffix").unwrap();
    source.sync_all().unwrap();

    let first = archive.retain(&mut source, head).unwrap();
    let second = archive.retain(&mut source, head).unwrap();
    assert_eq!(first, expected);
    assert_eq!(second, expected);
    assert_eq!(fs::read(archive.archive_path(first)).unwrap(), original);
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);

    let restore = Directory::create();
    let destination = restore.0.join("restored.records");
    archive.restore(first, &destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), original);
    assert_eq!(
        archive.restore(first, &destination),
        Err(RecoveryError::AlreadyInitialized)
    );
    assert_eq!(fs::read(&destination).unwrap(), original);
    assert!(
        archive
            .restore(first, &dir.0.join("unsafe.records"))
            .is_err()
    );
}

#[test]
#[ignore = "requires an external sealed native archive fixture"]
fn sealed_native_archive_verifies_exact_prefix_and_latest_slice() {
    #[derive(Deserialize)]
    struct Manifest {
        head: AnchorHead,
        blob_bytes: u64,
        blob_sha256: String,
    }

    let fixture = PathBuf::from(std::env::var_os("OIP_SEALED_ARCHIVE_DIR").unwrap());
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(fixture.join("sealed-manifest.json")).unwrap()).unwrap();
    let head: AnchorHead =
        serde_json::from_slice(&fs::read(fixture.join("restored-head.json")).unwrap()).unwrap();
    assert_eq!(head, manifest.head);
    assert_eq!(head.sequence, 6);
    assert_eq!(manifest.blob_bytes, 41814);
    let mut source = File::open(fixture.join("restored.records")).unwrap();
    let expected = archive_ref(&mut source, head);
    assert_eq!(expected.prefix_bytes, manifest.blob_bytes);
    assert_eq!(
        crate::wire::legacy::hex(&expected.prefix_sha256),
        manifest.blob_sha256
    );
    let dir = Directory::create();
    let archive = JournalArchive::new(&dir.0, head.profile, manifest.blob_bytes).unwrap();
    archive.verify(&mut source, expected).unwrap();
    #[cfg(target_os = "linux")]
    {
        let actual = archive.retain(&mut source, head).unwrap();
        assert_eq!(actual, expected);
        archive.open_verified(actual).unwrap();
    }
    println!(
        "archive_prefix_bytes={} head={} archive_sha256={}",
        expected.prefix_bytes, head.sequence, manifest.blob_sha256
    );
}
