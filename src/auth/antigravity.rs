use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::Utc;

use super::files;
use super::identity;
use super::secure_store;
use crate::config::{AuthMethod, ConfigStore, CredentialBackend, ProfileMeta};
use crate::live_apply::LiveFileChange;
use crate::profile::ProfileStore;
use crate::types::Tool;

pub(crate) const KEYRING_METADATA_FILE: &str = "keyring.json";
const SECRET_FILE: &str = "keyring-secret.json";
const AUTH_SOURCE_FILE: &str = "auth-source.json";
pub(crate) const HEADLESS_TOKEN_FILE: &str = "antigravity-oauth-token";
pub(crate) const STORED_HEADLESS_TOKEN_FILE: &str = "app/antigravity-oauth-token";

#[derive(Debug)]
struct InvalidLiveHeadlessToken(String);

impl fmt::Display for InvalidLiveHeadlessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InvalidLiveHeadlessToken {}

const APP_PREFIX: &str = "app";
const SHARED_PREFIX: &str = "shared";
const OAUTH_TIMEOUT: Duration = Duration::from_secs(180);
const KEYRING_SERVICE: &str = "gemini";
const KEYRING_ACCOUNT: &str = "antigravity";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntigravityAuthClassification {
    OauthSharedLiveKeyring,
    OauthSharedLiveHeadlessFile,
}

impl AntigravityAuthClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OauthSharedLiveKeyring => "oauth_shared_live_keyring",
            Self::OauthSharedLiveHeadlessFile => "oauth_shared_live_headless_file",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            Self::OauthSharedLiveKeyring => "OAuth shared live keyring",
            Self::OauthSharedLiveHeadlessFile => "OAuth shared live headless file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveCredentialSource {
    Keyring,
    HeadlessFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringRef {
    pub service: String,
    pub account: String,
}

#[derive(Debug, Clone)]
pub struct LiveSnapshot {
    pub credential_source: LiveCredentialSource,
    pub keyring_ref: KeyringRef,
    pub keyring_secret: Option<Vec<u8>>,
    pub app_files: BTreeMap<String, Vec<u8>>,
    pub shared_files: BTreeMap<String, Vec<u8>>,
}

pub fn live_app_dir(user_home: &Path) -> PathBuf {
    user_home.join(".gemini").join("antigravity-cli")
}

pub fn live_shared_dir(user_home: &Path) -> PathBuf {
    user_home.join(".gemini").join("config")
}

pub fn default_live_keyring_ref() -> KeyringRef {
    KeyringRef {
        service: KEYRING_SERVICE.to_owned(),
        account: KEYRING_ACCOUNT.to_owned(),
    }
}

pub fn classify_profile(
    profile_store: &ProfileStore,
    name: &str,
    auth_method: AuthMethod,
    _credential_backend: CredentialBackend,
) -> Result<AntigravityAuthClassification> {
    if auth_method != AuthMethod::OAuth {
        bail!("Antigravity currently supports OAuth profiles only");
    }
    Ok(match read_profile_credential_source(profile_store, name)? {
        LiveCredentialSource::Keyring => AntigravityAuthClassification::OauthSharedLiveKeyring,
        LiveCredentialSource::HeadlessFile => {
            AntigravityAuthClassification::OauthSharedLiveHeadlessFile
        }
    })
}

pub(crate) fn profile_credential_file(
    profile_store: &ProfileStore,
    profile_name: &str,
) -> Result<&'static str> {
    Ok(
        match read_profile_credential_source(profile_store, profile_name)? {
            LiveCredentialSource::Keyring => SECRET_FILE,
            LiveCredentialSource::HeadlessFile => STORED_HEADLESS_TOKEN_FILE,
        },
    )
}

pub fn read_managed_secret(
    profile_store: &ProfileStore,
    profile_name: &str,
    backend: CredentialBackend,
) -> Result<Option<Vec<u8>>> {
    match backend {
        CredentialBackend::File => {
            let path = profile_store
                .profile_dir(Tool::Antigravity, profile_name)
                .join(SECRET_FILE);
            if !optional_regular_profile_file(&path)? {
                return Ok(None);
            }
            profile_store
                .read_file(Tool::Antigravity, profile_name, SECRET_FILE)
                .map(Some)
        }
        CredentialBackend::SystemKeyring => {
            secure_store::read_profile_secret(Tool::Antigravity, profile_name)
        }
    }
}

pub fn persist_managed_secret(
    profile_store: &ProfileStore,
    profile_name: &str,
    backend: CredentialBackend,
    secret: &[u8],
) -> Result<()> {
    match backend {
        CredentialBackend::File => {
            profile_store.write_file(Tool::Antigravity, profile_name, SECRET_FILE, secret)
        }
        CredentialBackend::SystemKeyring => {
            secure_store::write_profile_secret(Tool::Antigravity, profile_name, secret)
        }
    }
}

pub fn live_credentials_snapshot_for_import(user_home: &Path) -> Result<Option<LiveSnapshot>> {
    let snapshot = capture_live_snapshot(user_home)?;
    let has_credential = match snapshot.credential_source {
        LiveCredentialSource::Keyring => snapshot.keyring_secret.is_some(),
        LiveCredentialSource::HeadlessFile => {
            headless_token_from_files(&snapshot.app_files).is_some()
        }
    };
    if !has_credential {
        return Ok(None);
    }
    Ok(Some(snapshot))
}

pub fn capture_live_snapshot(user_home: &Path) -> Result<LiveSnapshot> {
    let keyring_ref = default_live_keyring_ref();
    let mut app_files =
        read_live_dir_excluding(&live_app_dir(user_home), Some(HEADLESS_TOKEN_FILE))?;
    let (credential_source, keyring_secret) =
        match super::system_keyring::read_generic_password_state(
            &keyring_ref.service,
            Some(&keyring_ref.account),
        )? {
            super::system_keyring::GenericPasswordRead::Found(secret) => {
                (LiveCredentialSource::Keyring, Some(secret))
            }
            super::system_keyring::GenericPasswordRead::Missing => {
                (LiveCredentialSource::Keyring, None)
            }
            super::system_keyring::GenericPasswordRead::Unavailable(detail) => {
                if !cfg!(target_os = "linux") {
                    bail!(detail);
                }
                if let Some(token) = read_validated_live_headless_token(user_home)? {
                    app_files.insert(HEADLESS_TOKEN_FILE.to_owned(), token);
                }
                (LiveCredentialSource::HeadlessFile, None)
            }
        };
    Ok(LiveSnapshot {
        credential_source,
        keyring_secret,
        keyring_ref,
        app_files,
        shared_files: read_live_dir(&live_shared_dir(user_home))?,
    })
}

fn headless_token_from_files(files_map: &BTreeMap<String, Vec<u8>>) -> Option<&[u8]> {
    files_map
        .get(HEADLESS_TOKEN_FILE)
        .filter(|bytes| !bytes.is_empty())
        .map(Vec::as_slice)
}

#[cfg(target_os = "linux")]
fn read_validated_live_headless_token(user_home: &Path) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let path = live_app_dir(user_home).join(HEADLESS_TOKEN_FILE);
    let initial_metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not stat {}", path.display()));
        }
    };
    if initial_metadata.file_type().is_symlink() || !initial_metadata.file_type().is_file() {
        return Err(InvalidLiveHeadlessToken(format!(
            "refusing Antigravity headless token that is not a regular file: {}",
            path.display()
        ))
        .into());
    }

    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(InvalidLiveHeadlessToken(format!(
                "refusing symlinked Antigravity headless token: {}",
                path.display()
            ))
            .into());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not securely open {}", path.display()));
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect opened token {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(InvalidLiveHeadlessToken(format!(
            "refusing Antigravity headless token that is not a regular file: {}",
            path.display()
        ))
        .into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(InvalidLiveHeadlessToken(format!(
            "permissions on {} are too broad (got {:04o}, expected 0600)",
            path.display(),
            mode
        ))
        .into());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(InvalidLiveHeadlessToken(format!(
            "refusing Antigravity headless token not owned by the current user: {}",
            path.display()
        ))
        .into());
    }

    let mut token = Vec::new();
    file.read_to_end(&mut token)
        .with_context(|| format!("could not read opened token {}", path.display()))?;
    if token.is_empty() {
        return Err(InvalidLiveHeadlessToken(format!(
            "Antigravity headless token is empty: {}",
            path.display()
        ))
        .into());
    }
    Ok(Some(token))
}

#[cfg(not(target_os = "linux"))]
fn read_validated_live_headless_token(_user_home: &Path) -> Result<Option<Vec<u8>>> {
    bail!("Antigravity headless file authentication is supported on Linux only")
}

fn read_live_dir(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    read_live_dir_excluding(dir, None)
}

fn read_live_dir_excluding(
    dir: &Path,
    excluded_file: Option<&str>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    if !dir.exists() {
        return Ok(BTreeMap::new());
    }
    let mut files_map = BTreeMap::new();
    for file in files::list_regular_files_recursive(dir)? {
        let relative = file.file_name.to_string_lossy().into_owned();
        if excluded_file == Some(relative.as_str()) {
            continue;
        }
        let bytes = fs::read(&file.path)
            .with_context(|| format!("could not read {}", file.path.display()))?;
        files_map.insert(relative, bytes);
    }
    Ok(files_map)
}

struct ProfileOverwriteSnapshot {
    files: Vec<(String, Vec<u8>)>,
    secure_secret: Option<Vec<u8>>,
    secure_backend_was_tracked: bool,
}

impl ProfileOverwriteSnapshot {
    fn capture(
        profile_store: &ProfileStore,
        config_store: &ConfigStore,
        profile_name: &str,
    ) -> Result<Self> {
        let config = config_store.load()?;
        let files = files::list_regular_files_recursive(
            &profile_store.profile_dir(Tool::Antigravity, profile_name),
        )?
        .into_iter()
        .map(|file| {
            let bytes = fs::read(&file.path)
                .with_context(|| format!("could not read {}", file.path.display()))?;
            Ok((file.file_name.to_string_lossy().into_owned(), bytes))
        })
        .collect::<Result<Vec<_>>>()?;
        let secure_backend_was_tracked = config
            .profiles_for(Tool::Antigravity)
            .get(profile_name)
            .map(|meta| meta.credential_backend)
            == Some(CredentialBackend::SystemKeyring);
        let secure_secret = if secure_backend_was_tracked {
            secure_store::read_profile_secret(Tool::Antigravity, profile_name)?
        } else {
            None
        };
        Ok(Self {
            files,
            secure_secret,
            secure_backend_was_tracked,
        })
    }

    fn restore(
        &self,
        profile_store: &ProfileStore,
        profile_name: &str,
        touched_backend: CredentialBackend,
    ) -> Result<()> {
        if profile_store.exists(Tool::Antigravity, profile_name) {
            profile_store.delete(Tool::Antigravity, profile_name)?;
        }
        profile_store.create(Tool::Antigravity, profile_name)?;
        for (filename, bytes) in &self.files {
            profile_store.write_file(Tool::Antigravity, profile_name, filename, bytes)?;
        }

        if touched_backend == CredentialBackend::SystemKeyring || self.secure_backend_was_tracked {
            secure_store::delete_profile_secret(Tool::Antigravity, profile_name)?;
        }
        if let Some(secret) = &self.secure_secret {
            secure_store::write_profile_secret(Tool::Antigravity, profile_name, secret)?;
        }
        Ok(())
    }
}

pub fn write_profile_snapshot(
    profile_store: &ProfileStore,
    config_store: &ConfigStore,
    profile_name: &str,
    label: Option<String>,
    backend: CredentialBackend,
    snapshot: &LiveSnapshot,
    overwrite_existing: bool,
) -> Result<()> {
    let overwrite_snapshot = if overwrite_existing {
        Some(ProfileOverwriteSnapshot::capture(
            profile_store,
            config_store,
            profile_name,
        )?)
    } else {
        None
    };
    let result = write_profile_snapshot_inner(
        profile_store,
        config_store,
        profile_name,
        label,
        backend,
        snapshot,
        overwrite_existing,
    );
    match (result, overwrite_snapshot) {
        (Err(error), Some(overwrite_snapshot)) => {
            if let Err(rollback_error) =
                overwrite_snapshot.restore(profile_store, profile_name, backend)
            {
                return Err(error.context(format!(
                    "failed to restore overwritten Antigravity profile: {rollback_error:#}"
                )));
            }
            Err(error)
        }
        (result, _) => result,
    }
}

fn write_profile_snapshot_inner(
    profile_store: &ProfileStore,
    config_store: &ConfigStore,
    profile_name: &str,
    label: Option<String>,
    backend: CredentialBackend,
    snapshot: &LiveSnapshot,
    overwrite_existing: bool,
) -> Result<()> {
    let credential = match snapshot.credential_source {
        LiveCredentialSource::Keyring => snapshot.keyring_secret.as_deref().with_context(|| {
            "no Antigravity keyring credential found. Sign in with 'agy' first, then retry."
        })?,
        LiveCredentialSource::HeadlessFile => {
            validate_headless_profile_backend(backend)?;
            headless_token_from_files(&snapshot.app_files).with_context(|| {
                "no Antigravity headless token found. Sign in with 'agy' first, then retry."
            })?
        }
    };

    if let Some(existing) = identity::existing_antigravity_oauth_profile_for_live_secret(
        profile_store,
        config_store,
        Some(credential),
    )? {
        if existing != profile_name {
            bail!(
                "An Antigravity OAuth profile for this account already exists as '{}'.\n  \
                 Use that profile or remove it before saving another alias.",
                existing
            );
        }
    }

    persist_profile_credential_source(profile_store, profile_name, snapshot.credential_source)?;
    if snapshot.credential_source == LiveCredentialSource::Keyring {
        persist_profile_keyring_ref(profile_store, profile_name, &snapshot.keyring_ref)?;
        persist_managed_secret(profile_store, profile_name, backend, credential)?;
    }

    clear_profile_subtree(profile_store, profile_name, APP_PREFIX)?;
    clear_profile_subtree(profile_store, profile_name, SHARED_PREFIX)?;
    persist_profile_tree(profile_store, profile_name, APP_PREFIX, &snapshot.app_files)?;
    persist_profile_tree(
        profile_store,
        profile_name,
        SHARED_PREFIX,
        &snapshot.shared_files,
    )?;

    if snapshot.credential_source == LiveCredentialSource::HeadlessFile {
        remove_optional_profile_file(profile_store, profile_name, KEYRING_METADATA_FILE)?;
        remove_optional_profile_file(profile_store, profile_name, SECRET_FILE)?;
    }

    identity::ensure_unique_oauth_identity(
        profile_store,
        config_store,
        Tool::Antigravity,
        profile_name,
        backend,
    )?;

    let meta = ProfileMeta {
        added_at: Utc::now(),
        auth_method: AuthMethod::OAuth,
        credential_backend: backend,
        label,
    };
    if overwrite_existing {
        config_store.upsert_profile(Tool::Antigravity, profile_name, meta)?;
    } else {
        config_store.add_profile(Tool::Antigravity, profile_name, meta)?;
    }
    if snapshot.credential_source == LiveCredentialSource::HeadlessFile {
        let _ = secure_store::delete_profile_secret(Tool::Antigravity, profile_name);
    }
    Ok(())
}

fn validate_headless_profile_backend(backend: CredentialBackend) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("Antigravity headless file authentication is supported on Linux only");
    }
    if backend != CredentialBackend::File {
        bail!(
            "Antigravity's native headless file authentication requires --credential-backend file"
        );
    }
    Ok(())
}

fn remove_optional_profile_file(
    profile_store: &ProfileStore,
    profile_name: &str,
    filename: &str,
) -> Result<()> {
    let path = profile_store
        .profile_dir(Tool::Antigravity, profile_name)
        .join(filename);
    if !optional_regular_profile_file(&path)? {
        return Ok(());
    }
    fs::remove_file(&path).with_context(|| format!("could not delete {}", path.display()))
}

fn optional_regular_profile_file(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("could not stat {}", path.display()));
        }
    };
    if !metadata.file_type().is_file() {
        bail!("refusing non-regular profile file: {}", path.display());
    }
    Ok(true)
}

fn clear_profile_subtree(
    profile_store: &ProfileStore,
    profile_name: &str,
    prefix: &str,
) -> Result<()> {
    let dir = profile_store
        .profile_dir(Tool::Antigravity, profile_name)
        .join(prefix);
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("could not delete {}", dir.display()))?;
    }
    Ok(())
}

fn persist_profile_tree(
    profile_store: &ProfileStore,
    profile_name: &str,
    prefix: &str,
    files_map: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for (relative, bytes) in files_map {
        let stored = format!("{prefix}/{relative}");
        profile_store.write_file(Tool::Antigravity, profile_name, &stored, bytes)?;
    }
    Ok(())
}

pub fn apply_live_credentials(
    profile_store: &ProfileStore,
    profile_name: &str,
    backend: CredentialBackend,
    user_home: &Path,
) -> Result<()> {
    match read_profile_credential_source(profile_store, profile_name)? {
        LiveCredentialSource::Keyring => {
            let keyring_ref = read_profile_keyring_ref(profile_store, profile_name)?;
            let Some(secret) = read_managed_secret(profile_store, profile_name, backend)? else {
                bail!(
                    "managed Antigravity credential is missing for profile '{}'",
                    profile_name
                );
            };
            super::system_keyring::read_generic_password(
                &keyring_ref.service,
                Some(&keyring_ref.account),
            )
            .context(
                "cannot apply an Antigravity keyring-backed profile while the OS keyring is unavailable",
            )?;

            let changes = build_apply_transaction(profile_store, profile_name, user_home)?;
            crate::live_apply::apply_transaction(changes)?;
            super::system_keyring::upsert_generic_password(
                &keyring_ref.service,
                &keyring_ref.account,
                &secret,
            )
        }
        LiveCredentialSource::HeadlessFile => {
            validate_headless_profile_backend(backend)?;
            ensure_keyring_unavailable_for_headless_profile()?;
            let token_path = profile_store
                .profile_dir(Tool::Antigravity, profile_name)
                .join(STORED_HEADLESS_TOKEN_FILE);
            profile_store.check_permissions(&token_path)?;
            let token = profile_store.read_file(
                Tool::Antigravity,
                profile_name,
                STORED_HEADLESS_TOKEN_FILE,
            )?;
            if token.is_empty() {
                bail!(
                    "managed Antigravity headless token is empty for profile '{}'",
                    profile_name
                );
            }
            let changes = build_apply_transaction(profile_store, profile_name, user_home)?;
            crate::live_apply::apply_transaction(changes)
        }
    }
}

fn ensure_keyring_unavailable_for_headless_profile() -> Result<()> {
    let keyring_ref = default_live_keyring_ref();
    match super::system_keyring::read_generic_password_state(
        &keyring_ref.service,
        Some(&keyring_ref.account),
    )? {
        super::system_keyring::GenericPasswordRead::Unavailable(_) => Ok(()),
        super::system_keyring::GenericPasswordRead::Found(_)
        | super::system_keyring::GenericPasswordRead::Missing => {
            bail!(
                "refusing to apply an Antigravity headless-file profile while the OS keyring is accessible; capture or use a keyring-backed profile on this session"
            )
        }
    }
}

fn build_apply_transaction(
    profile_store: &ProfileStore,
    profile_name: &str,
    user_home: &Path,
) -> Result<Vec<LiveFileChange>> {
    let source = read_profile_credential_source(profile_store, profile_name)?;
    let mut stored_app = profile_tree_map(profile_store, profile_name, APP_PREFIX)?;
    if source == LiveCredentialSource::Keyring {
        stored_app.remove(HEADLESS_TOKEN_FILE);
    }
    let stored_shared = profile_tree_map(profile_store, profile_name, SHARED_PREFIX)?;
    let mut changes = Vec::new();
    changes.extend(sync_dir_to_live(
        &stored_app,
        &live_app_dir(user_home),
        &read_live_dir(&live_app_dir(user_home))?,
        source == LiveCredentialSource::HeadlessFile,
    ));
    changes.extend(sync_dir_to_live(
        &stored_shared,
        &live_shared_dir(user_home),
        &read_live_dir(&live_shared_dir(user_home))?,
        false,
    ));
    Ok(changes)
}

fn sync_dir_to_live(
    stored: &BTreeMap<String, Vec<u8>>,
    live_root: &Path,
    live: &BTreeMap<String, Vec<u8>>,
    rewrite_headless_token: bool,
) -> Vec<LiveFileChange> {
    let mut changes = Vec::new();
    for (relative, bytes) in stored {
        let live_bytes = live.get(relative);
        if live_bytes != Some(bytes) || (rewrite_headless_token && relative == HEADLESS_TOKEN_FILE)
        {
            changes.push(LiveFileChange::write(
                live_root.join(relative),
                bytes.clone(),
            ));
        }
    }
    for relative in live.keys() {
        if !stored.contains_key(relative) {
            changes.push(LiveFileChange::delete(live_root.join(relative)));
        }
    }
    changes
}

fn profile_tree_map(
    profile_store: &ProfileStore,
    profile_name: &str,
    prefix: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let root = profile_store
        .profile_dir(Tool::Antigravity, profile_name)
        .join(prefix);
    if !root.exists() {
        return Ok(BTreeMap::new());
    }
    let mut files_map = BTreeMap::new();
    for file in files::list_regular_files_recursive(&root)? {
        let relative = file.file_name.to_string_lossy().into_owned();
        let stored = format!("{prefix}/{relative}");
        let bytes = profile_store.read_file(Tool::Antigravity, profile_name, &stored)?;
        files_map.insert(relative, bytes);
    }
    Ok(files_map)
}

pub fn live_state_matches(
    profile_store: &ProfileStore,
    profile_name: &str,
    backend: CredentialBackend,
    user_home: &Path,
) -> Result<bool> {
    let source = read_profile_credential_source(profile_store, profile_name)?;
    let live_app = match source {
        LiveCredentialSource::Keyring => {
            let keyring_ref = read_profile_keyring_ref(profile_store, profile_name)?;
            let managed_secret = read_managed_secret(profile_store, profile_name, backend)?;
            let live_secret = super::system_keyring::read_generic_password(
                &keyring_ref.service,
                Some(&keyring_ref.account),
            )?;
            if managed_secret != live_secret {
                return Ok(false);
            }
            read_live_dir_excluding(&live_app_dir(user_home), Some(HEADLESS_TOKEN_FILE))?
        }
        LiveCredentialSource::HeadlessFile => {
            if validate_headless_profile_backend(backend).is_err() {
                return Ok(false);
            }
            if ensure_keyring_unavailable_for_headless_profile().is_err() {
                return Ok(false);
            }
            let mut app_files =
                read_live_dir_excluding(&live_app_dir(user_home), Some(HEADLESS_TOKEN_FILE))?;
            let token = match read_validated_live_headless_token(user_home) {
                Ok(Some(token)) => token,
                Ok(None) | Err(_) => return Ok(false),
            };
            app_files.insert(HEADLESS_TOKEN_FILE.to_owned(), token);
            app_files
        }
    };
    let mut stored_app = profile_tree_map(profile_store, profile_name, APP_PREFIX)?;
    if source == LiveCredentialSource::Keyring {
        stored_app.remove(HEADLESS_TOKEN_FILE);
    }
    Ok(stored_app == live_app
        && profile_tree_map(profile_store, profile_name, SHARED_PREFIX)?
            == read_live_dir(&live_shared_dir(user_home))?)
}

pub fn sync_profile_from_live_if_same_identity(
    profile_store: &ProfileStore,
    profile_name: &str,
    backend: CredentialBackend,
    user_home: &Path,
) -> Result<bool> {
    let snapshot = match live_credentials_snapshot_for_import(user_home) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return Ok(false),
        Err(error) if error.downcast_ref::<InvalidLiveHeadlessToken>().is_some() => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let profile_source = read_profile_credential_source(profile_store, profile_name)?;
    if snapshot.credential_source != profile_source {
        return Ok(false);
    };
    let live_credential = match snapshot.credential_source {
        LiveCredentialSource::Keyring => snapshot.keyring_secret.as_deref(),
        LiveCredentialSource::HeadlessFile => headless_token_from_files(&snapshot.app_files),
    };
    let managed_credential = match profile_source {
        LiveCredentialSource::Keyring => read_managed_secret(profile_store, profile_name, backend)?,
        LiveCredentialSource::HeadlessFile => {
            let token_path = profile_store
                .profile_dir(Tool::Antigravity, profile_name)
                .join(STORED_HEADLESS_TOKEN_FILE);
            if optional_regular_profile_file(&token_path)? {
                Some(profile_store.read_file(
                    Tool::Antigravity,
                    profile_name,
                    STORED_HEADLESS_TOKEN_FILE,
                )?)
            } else {
                None
            }
        }
    };
    let (Some(live_credential), Some(managed_credential)) = (live_credential, managed_credential)
    else {
        return Ok(false);
    };
    let managed_identity =
        identity::resolve_antigravity_identity_from_json_bytes(&managed_credential)?;
    let live_identity = identity::resolve_antigravity_identity_from_json_bytes(live_credential)?;
    if managed_identity.is_none() || managed_identity != live_identity {
        return Ok(false);
    }
    if profile_source == LiveCredentialSource::Keyring {
        persist_profile_keyring_ref(profile_store, profile_name, &snapshot.keyring_ref)?;
        persist_managed_secret(profile_store, profile_name, backend, live_credential)?;
    }
    clear_profile_subtree(profile_store, profile_name, APP_PREFIX)?;
    clear_profile_subtree(profile_store, profile_name, SHARED_PREFIX)?;
    persist_profile_tree(profile_store, profile_name, APP_PREFIX, &snapshot.app_files)?;
    persist_profile_tree(
        profile_store,
        profile_name,
        SHARED_PREFIX,
        &snapshot.shared_files,
    )?;
    Ok(true)
}

pub fn add_oauth_with_backend(
    profile_store: &ProfileStore,
    config_store: &ConfigStore,
    profile_name: &str,
    label: Option<String>,
    agy_bin: &Path,
    backend: CredentialBackend,
) -> Result<()> {
    let user_home = dirs::home_dir().context("could not determine home directory")?;
    let before = capture_live_snapshot(&user_home)?;
    let mut child = Command::new(agy_bin)
        .spawn()
        .with_context(|| format!("could not launch {}", agy_bin.display()))?;
    let status = child.wait_timeout(OAUTH_TIMEOUT)?.unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        std::process::ExitStatus::from_raw(1 << 8)
    });
    if !status.success() {
        bail!(
            "Antigravity login did not complete successfully.\n  \
             Complete login in the agy session, then retry 'aisw add antigravity {}'.",
            profile_name
        );
    }
    let after = capture_live_snapshot(&user_home)?;
    if before.credential_source == after.credential_source
        && before.keyring_secret == after.keyring_secret
        && before.app_files == after.app_files
        && before.shared_files == after.shared_files
    {
        bail!(
            "Antigravity login did not produce any new managed state.\n  \
             If agy already signed into the desired account, use 'aisw add antigravity {} --from-live' instead.",
            profile_name
        );
    }

    profile_store.create(Tool::Antigravity, profile_name)?;
    let result = write_profile_snapshot(
        profile_store,
        config_store,
        profile_name,
        label,
        backend,
        &after,
        false,
    );
    if result.is_err() {
        let _ = profile_store.delete(Tool::Antigravity, profile_name);
        if backend == CredentialBackend::SystemKeyring {
            let _ = secure_store::delete_profile_secret(Tool::Antigravity, profile_name);
        }
    }
    result
}

pub fn restore_live_state_after_oauth_add(
    snapshot: Option<LiveSnapshot>,
    user_home: &Path,
) -> Result<()> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    restore_snapshot_to_live(&snapshot, user_home)
}

pub fn restore_snapshot_to_live(snapshot: &LiveSnapshot, user_home: &Path) -> Result<()> {
    let changes = {
        let mut app_files = snapshot.app_files.clone();
        if snapshot.credential_source == LiveCredentialSource::Keyring {
            app_files.remove(HEADLESS_TOKEN_FILE);
        }
        let mut changes = Vec::new();
        changes.extend(sync_dir_to_live(
            &app_files,
            &live_app_dir(user_home),
            &read_live_dir(&live_app_dir(user_home))?,
            snapshot.credential_source == LiveCredentialSource::HeadlessFile,
        ));
        changes.extend(sync_dir_to_live(
            &snapshot.shared_files,
            &live_shared_dir(user_home),
            &read_live_dir(&live_shared_dir(user_home))?,
            false,
        ));
        changes
    };
    crate::live_apply::apply_transaction(changes)?;
    match snapshot.credential_source {
        LiveCredentialSource::HeadlessFile => Ok(()),
        LiveCredentialSource::Keyring => match snapshot.keyring_secret.as_deref() {
            Some(secret) => super::system_keyring::upsert_generic_password(
                &snapshot.keyring_ref.service,
                &snapshot.keyring_ref.account,
                secret,
            ),
            None => super::system_keyring::delete_generic_password(
                &snapshot.keyring_ref.service,
                &snapshot.keyring_ref.account,
            ),
        },
    }
}

pub fn emit_shell_env() {}

fn persist_profile_keyring_ref(
    profile_store: &ProfileStore,
    profile_name: &str,
    keyring_ref: &KeyringRef,
) -> Result<()> {
    let bytes = serde_json::to_vec(keyring_ref).context("could not serialize keyring metadata")?;
    profile_store.write_file(
        Tool::Antigravity,
        profile_name,
        KEYRING_METADATA_FILE,
        &bytes,
    )
}

fn persist_profile_credential_source(
    profile_store: &ProfileStore,
    profile_name: &str,
    source: LiveCredentialSource,
) -> Result<()> {
    let bytes =
        serde_json::to_vec(&source).context("could not serialize Antigravity auth source")?;
    profile_store.write_file(Tool::Antigravity, profile_name, AUTH_SOURCE_FILE, &bytes)
}

fn read_profile_credential_source(
    profile_store: &ProfileStore,
    profile_name: &str,
) -> Result<LiveCredentialSource> {
    let path = profile_store
        .profile_dir(Tool::Antigravity, profile_name)
        .join(AUTH_SOURCE_FILE);
    if !optional_regular_profile_file(&path)? {
        return Ok(LiveCredentialSource::Keyring);
    }
    let bytes = profile_store.read_file(Tool::Antigravity, profile_name, AUTH_SOURCE_FILE)?;
    serde_json::from_slice(&bytes).context("could not parse Antigravity auth source metadata")
}

pub fn read_profile_keyring_ref(
    profile_store: &ProfileStore,
    profile_name: &str,
) -> Result<KeyringRef> {
    let bytes = profile_store.read_file(Tool::Antigravity, profile_name, KEYRING_METADATA_FILE)?;
    serde_json::from_slice(&bytes).context("could not parse Antigravity keyring metadata")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableKeyringRef {
    service: String,
    account: String,
}

impl serde::Serialize for KeyringRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableKeyringRef {
            service: self.service.clone(),
            account: self.account.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for KeyringRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = SerializableKeyringRef::deserialize(deserializer)?;
        Ok(Self {
            service: value.service,
            account: value.account,
        })
    }
}

trait WaitTimeoutExt {
    fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<std::process::ExitStatus>>;
}

impl WaitTimeoutExt for std::process::Child {
    fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<std::process::ExitStatus>> {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use tempfile::tempdir;

    use super::*;
    use crate::config::ConfigStore;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn write_live_state(user_home: &Path, secret: &[u8]) {
        fs::create_dir_all(live_app_dir(user_home).join("cache")).unwrap();
        fs::create_dir_all(live_shared_dir(user_home).join("projects")).unwrap();
        fs::write(
            live_app_dir(user_home).join("settings.json"),
            br#"{"theme":"terminal"}"#,
        )
        .unwrap();
        fs::write(
            live_app_dir(user_home).join("cache").join("projects.json"),
            br#"{"current":"repo"}"#,
        )
        .unwrap();
        fs::write(
            live_shared_dir(user_home).join("hooks.json"),
            br#"{"hooks":[]}"#,
        )
        .unwrap();
        fs::write(
            live_shared_dir(user_home)
                .join("projects")
                .join("repo.json"),
            br#"{"mode":"plan"}"#,
        )
        .unwrap();
        super::super::system_keyring::upsert_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            secret,
        )
        .unwrap();
    }

    #[test]
    fn capture_and_apply_round_trip_file_backend() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let home = temp.path().join("home");
        let user_home = temp.path().join("user");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&user_home).unwrap();
        let profile_store = ProfileStore::new(&home);
        let config_store = ConfigStore::new(&home);

        write_live_state(&user_home, br#"{"email":"work@example.com"}"#);
        let snapshot = capture_live_snapshot(&user_home).unwrap();
        profile_store.create(Tool::Antigravity, "work").unwrap();
        write_profile_snapshot(
            &profile_store,
            &config_store,
            "work",
            None,
            CredentialBackend::File,
            &snapshot,
            false,
        )
        .unwrap();

        fs::write(
            live_app_dir(&user_home).join("settings.json"),
            br#"{"theme":"light"}"#,
        )
        .unwrap();
        super::super::system_keyring::upsert_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            br#"{"email":"other@example.com"}"#,
        )
        .unwrap();

        apply_live_credentials(&profile_store, "work", CredentialBackend::File, &user_home)
            .unwrap();
        assert!(
            live_state_matches(&profile_store, "work", CredentialBackend::File, &user_home)
                .unwrap()
        );
    }

    #[test]
    fn classify_profile_is_shared_live_oauth() {
        let temp = tempdir().unwrap();
        let profile_store = ProfileStore::new(temp.path());
        let classification = classify_profile(
            &profile_store,
            "work",
            AuthMethod::OAuth,
            CredentialBackend::File,
        )
        .unwrap();
        assert_eq!(
            classification,
            AntigravityAuthClassification::OauthSharedLiveKeyring
        );
    }

    #[test]
    fn live_credentials_snapshot_returns_none_when_live_state_is_empty() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let user_home = temp.path().join("user");
        fs::create_dir_all(&user_home).unwrap();

        let snapshot = live_credentials_snapshot_for_import(&user_home).unwrap();
        assert!(snapshot.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn keyring_capture_excludes_a_stale_headless_token() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let user_home = temp.path().join("user");
        fs::create_dir_all(&user_home).unwrap();
        write_live_state(&user_home, br#"{"email":"work@example.com"}"#);
        let token_path = live_app_dir(&user_home).join(HEADLESS_TOKEN_FILE);
        fs::write(&token_path, br#"{"email":"stale@example.com"}"#).unwrap();
        files::set_permissions_600(&token_path).unwrap();

        let snapshot = capture_live_snapshot(&user_home).unwrap();

        assert_eq!(snapshot.credential_source, LiveCredentialSource::Keyring);
        assert!(!snapshot.app_files.contains_key(HEADLESS_TOKEN_FILE));
    }

    #[test]
    fn write_profile_snapshot_system_keyring_backend_stores_secret_outside_profile_dir() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let home = temp.path().join("home");
        let user_home = temp.path().join("user");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&user_home).unwrap();

        let profile_store = ProfileStore::new(&home);
        let config_store = ConfigStore::new(&home);
        write_live_state(&user_home, br#"{"email":"work@example.com"}"#);
        let snapshot = capture_live_snapshot(&user_home).unwrap();

        profile_store.create(Tool::Antigravity, "work").unwrap();
        write_profile_snapshot(
            &profile_store,
            &config_store,
            "work",
            None,
            CredentialBackend::SystemKeyring,
            &snapshot,
            false,
        )
        .unwrap();

        assert!(!profile_store
            .profile_dir(Tool::Antigravity, "work")
            .join(SECRET_FILE)
            .exists());
        assert_eq!(
            read_managed_secret(&profile_store, "work", CredentialBackend::SystemKeyring)
                .unwrap()
                .unwrap(),
            br#"{"email":"work@example.com"}"#
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_overwrite_restores_the_complete_previous_profile() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let profile_store = ProfileStore::new(&home);
        let config_store = ConfigStore::new(&home);

        profile_store.create(Tool::Antigravity, "work").unwrap();
        persist_profile_credential_source(&profile_store, "work", LiveCredentialSource::Keyring)
            .unwrap();
        persist_profile_keyring_ref(&profile_store, "work", &default_live_keyring_ref()).unwrap();
        persist_managed_secret(
            &profile_store,
            "work",
            CredentialBackend::File,
            br#"{"email":"old@example.com"}"#,
        )
        .unwrap();
        profile_store
            .write_file(
                Tool::Antigravity,
                "work",
                "app/settings.json",
                br#"{"theme":"old"}"#,
            )
            .unwrap();
        profile_store
            .write_file(
                Tool::Antigravity,
                "work",
                "shared/project.json",
                br#"{"project":"old"}"#,
            )
            .unwrap();
        config_store
            .add_profile(
                Tool::Antigravity,
                "work",
                ProfileMeta {
                    added_at: Utc::now(),
                    auth_method: AuthMethod::OAuth,
                    credential_backend: CredentialBackend::File,
                    label: Some("old".to_owned()),
                },
            )
            .unwrap();
        fs::create_dir(home.join("config.json.tmp")).unwrap();

        let mut app_files = BTreeMap::new();
        app_files.insert(
            HEADLESS_TOKEN_FILE.to_owned(),
            br#"{"email":"new@example.com"}"#.to_vec(),
        );
        app_files.insert("settings.json".to_owned(), br#"{"theme":"new"}"#.to_vec());
        let mut shared_files = BTreeMap::new();
        shared_files.insert("project.json".to_owned(), br#"{"project":"new"}"#.to_vec());
        let snapshot = LiveSnapshot {
            credential_source: LiveCredentialSource::HeadlessFile,
            keyring_ref: default_live_keyring_ref(),
            keyring_secret: None,
            app_files,
            shared_files,
        };

        let error = write_profile_snapshot(
            &profile_store,
            &config_store,
            "work",
            None,
            CredentialBackend::File,
            &snapshot,
            true,
        )
        .unwrap_err();

        assert!(error.to_string().contains("config.json.tmp"));
        assert_eq!(
            read_profile_credential_source(&profile_store, "work").unwrap(),
            LiveCredentialSource::Keyring
        );
        assert_eq!(
            read_profile_keyring_ref(&profile_store, "work").unwrap(),
            default_live_keyring_ref()
        );
        assert_eq!(
            read_managed_secret(&profile_store, "work", CredentialBackend::File)
                .unwrap()
                .unwrap(),
            br#"{"email":"old@example.com"}"#
        );
        assert_eq!(
            profile_store
                .read_file(Tool::Antigravity, "work", "app/settings.json")
                .unwrap(),
            br#"{"theme":"old"}"#
        );
        assert_eq!(
            profile_store
                .read_file(Tool::Antigravity, "work", "shared/project.json")
                .unwrap(),
            br#"{"project":"old"}"#
        );
        assert!(!profile_store
            .profile_dir(Tool::Antigravity, "work")
            .join(STORED_HEADLESS_TOKEN_FILE)
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn optional_profile_files_reject_dangling_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let profile_store = ProfileStore::new(&home);
        profile_store.create(Tool::Antigravity, "work").unwrap();
        let profile_dir = profile_store.profile_dir(Tool::Antigravity, "work");

        let auth_source = profile_dir.join(AUTH_SOURCE_FILE);
        symlink("missing-auth-source.json", &auth_source).unwrap();
        let source_error = read_profile_credential_source(&profile_store, "work").unwrap_err();
        assert!(source_error
            .to_string()
            .contains("refusing non-regular profile file"));

        fs::remove_file(&auth_source).unwrap();
        let keyring_metadata = profile_dir.join(KEYRING_METADATA_FILE);
        symlink("missing-keyring.json", &keyring_metadata).unwrap();
        let removal_error =
            remove_optional_profile_file(&profile_store, "work", KEYRING_METADATA_FILE)
                .unwrap_err();
        assert!(removal_error
            .to_string()
            .contains("refusing non-regular profile file"));
    }

    #[test]
    fn sync_profile_from_live_if_same_identity_updates_managed_snapshot() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let home = temp.path().join("home");
        let user_home = temp.path().join("user");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&user_home).unwrap();

        let profile_store = ProfileStore::new(&home);
        let config_store = ConfigStore::new(&home);
        write_live_state(
            &user_home,
            br#"{"email":"work@example.com","token":"live"}"#,
        );
        let snapshot = capture_live_snapshot(&user_home).unwrap();

        profile_store.create(Tool::Antigravity, "work").unwrap();
        write_profile_snapshot(
            &profile_store,
            &config_store,
            "work",
            None,
            CredentialBackend::File,
            &snapshot,
            false,
        )
        .unwrap();

        fs::write(
            live_app_dir(&user_home).join("settings.json"),
            br#"{"theme":"light"}"#,
        )
        .unwrap();
        super::super::system_keyring::upsert_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            br#"{"email":"work@example.com","token":"new-live"}"#,
        )
        .unwrap();

        let synced = sync_profile_from_live_if_same_identity(
            &profile_store,
            "work",
            CredentialBackend::File,
            &user_home,
        )
        .unwrap();

        assert!(synced);
        assert_eq!(
            read_managed_secret(&profile_store, "work", CredentialBackend::File)
                .unwrap()
                .unwrap(),
            br#"{"email":"work@example.com","token":"new-live"}"#
        );
        assert_eq!(
            profile_store
                .read_file(Tool::Antigravity, "work", "app/settings.json")
                .unwrap(),
            br#"{"theme":"light"}"#
        );
    }

    #[test]
    fn restore_snapshot_to_live_removes_stale_files_and_deletes_secret() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let user_home = temp.path().join("user");
        fs::create_dir_all(&user_home).unwrap();
        write_live_state(&user_home, br#"{"email":"work@example.com"}"#);

        restore_snapshot_to_live(
            &LiveSnapshot {
                credential_source: LiveCredentialSource::Keyring,
                keyring_ref: default_live_keyring_ref(),
                keyring_secret: None,
                app_files: BTreeMap::new(),
                shared_files: BTreeMap::new(),
            },
            &user_home,
        )
        .unwrap();

        assert!(read_live_dir(&live_app_dir(&user_home)).unwrap().is_empty());
        assert!(read_live_dir(&live_shared_dir(&user_home))
            .unwrap()
            .is_empty());
        assert!(super::super::system_keyring::read_generic_password(
            KEYRING_SERVICE,
            Some(KEYRING_ACCOUNT),
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn live_state_matches_returns_false_when_live_secret_differs() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let home = temp.path().join("home");
        let user_home = temp.path().join("user");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&user_home).unwrap();

        let profile_store = ProfileStore::new(&home);
        let config_store = ConfigStore::new(&home);
        write_live_state(&user_home, br#"{"email":"work@example.com"}"#);
        let snapshot = capture_live_snapshot(&user_home).unwrap();

        profile_store.create(Tool::Antigravity, "work").unwrap();
        write_profile_snapshot(
            &profile_store,
            &config_store,
            "work",
            None,
            CredentialBackend::File,
            &snapshot,
            false,
        )
        .unwrap();

        super::super::system_keyring::upsert_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            br#"{"email":"other@example.com"}"#,
        )
        .unwrap();

        assert!(
            !live_state_matches(&profile_store, "work", CredentialBackend::File, &user_home)
                .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_live_state_mismatches_are_soft_failures() {
        use std::os::unix::fs::PermissionsExt;

        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_UNAVAILABLE", Path::new("1"));
        let home = temp.path().join("home");
        let user_home = temp.path().join("user");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(live_app_dir(&user_home)).unwrap();

        let token = br#"{"email":"work@example.com"}"#;
        let token_path = live_app_dir(&user_home).join(HEADLESS_TOKEN_FILE);
        fs::write(&token_path, token).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();

        let profile_store = ProfileStore::new(&home);
        let config_store = ConfigStore::new(&home);
        let snapshot = capture_live_snapshot(&user_home).unwrap();
        profile_store.create(Tool::Antigravity, "work").unwrap();
        write_profile_snapshot(
            &profile_store,
            &config_store,
            "work",
            None,
            CredentialBackend::File,
            &snapshot,
            false,
        )
        .unwrap();

        assert!(!live_state_matches(
            &profile_store,
            "work",
            CredentialBackend::SystemKeyring,
            &user_home,
        )
        .unwrap());

        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            !live_state_matches(&profile_store, "work", CredentialBackend::File, &user_home,)
                .unwrap()
        );
        assert!(!sync_profile_from_live_if_same_identity(
            &profile_store,
            "work",
            CredentialBackend::File,
            &user_home,
        )
        .unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_sync_skips_when_managed_token_is_missing() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_UNAVAILABLE", Path::new("1"));
        let home = temp.path().join("home");
        let user_home = temp.path().join("user");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(live_app_dir(&user_home)).unwrap();

        let token_path = live_app_dir(&user_home).join(HEADLESS_TOKEN_FILE);
        fs::write(&token_path, br#"{"email":"work@example.com"}"#).unwrap();
        files::set_permissions_600(&token_path).unwrap();

        let profile_store = ProfileStore::new(&home);
        profile_store.create(Tool::Antigravity, "work").unwrap();
        persist_profile_credential_source(
            &profile_store,
            "work",
            LiveCredentialSource::HeadlessFile,
        )
        .unwrap();

        assert!(!sync_profile_from_live_if_same_identity(
            &profile_store,
            "work",
            CredentialBackend::File,
            &user_home,
        )
        .unwrap());
    }

    #[test]
    fn capture_live_snapshot_preserves_nested_relative_paths() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let _keyring = EnvVarGuard::set("AISW_KEYRING_TEST_DIR", temp.path());
        let user_home = temp.path().join("user");
        fs::create_dir_all(live_app_dir(&user_home).join("profiles/work")).unwrap();
        fs::create_dir_all(live_shared_dir(&user_home).join("repos/work")).unwrap();

        fs::write(
            live_app_dir(&user_home).join("profiles/work/settings.json"),
            br#"{"theme":"dark"}"#,
        )
        .unwrap();
        fs::write(
            live_shared_dir(&user_home).join("repos/work/settings.json"),
            br#"{"mode":"plan"}"#,
        )
        .unwrap();
        super::super::system_keyring::upsert_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            br#"{"email":"work@example.com"}"#,
        )
        .unwrap();

        let snapshot = capture_live_snapshot(&user_home).unwrap();
        let app_files = snapshot
            .app_files
            .iter()
            .map(|(path, bytes)| (path.replace('\\', "/"), bytes.as_slice()))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            app_files.get("profiles/work/settings.json").copied(),
            Some(br#"{"theme":"dark"}"#.as_slice())
        );
        let shared_files = snapshot
            .shared_files
            .iter()
            .map(|(path, bytes)| (path.replace('\\', "/"), bytes.as_slice()))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            shared_files.get("repos/work/settings.json").copied(),
            Some(br#"{"mode":"plan"}"#.as_slice())
        );
    }

    #[test]
    fn profile_tree_map_preserves_nested_duplicate_basenames() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let profile_store = ProfileStore::new(&home);
        profile_store.create(Tool::Antigravity, "work").unwrap();

        profile_store
            .write_file(
                Tool::Antigravity,
                "work",
                "app/profiles/work/settings.json",
                br#"{"theme":"dark"}"#,
            )
            .unwrap();
        profile_store
            .write_file(
                Tool::Antigravity,
                "work",
                "app/profiles/personal/settings.json",
                br#"{"theme":"light"}"#,
            )
            .unwrap();

        let stored = profile_tree_map(&profile_store, "work", APP_PREFIX).unwrap();
        assert_eq!(stored.len(), 2);
        let stored = stored
            .iter()
            .map(|(path, bytes)| (path.replace('\\', "/"), bytes.as_slice()))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            stored.get("profiles/work/settings.json").copied(),
            Some(br#"{"theme":"dark"}"#.as_slice())
        );
        assert_eq!(
            stored.get("profiles/personal/settings.json").copied(),
            Some(br#"{"theme":"light"}"#.as_slice())
        );
    }
}
