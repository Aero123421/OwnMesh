//! OAuth 2.1 / device enrollment client for the OwnMesh CLI (§5-CLI).
//!
//! Contract mirrors `packages/control-plane` (cp-04):
//! - Authorization Code + PKCE S256 with loopback callback (RFC 7636 / OAuth 2.1)
//! - Device Authorization Grant (RFC 8628)
//! - Device enroll challenge/proof + revoke
//!
//! Secrets (refresh token, device key) live in `ownmesh-identity` keychain stores.
//! Access tokens are obtained on demand via refresh and never written to config.

mod callback;
mod device_api;
mod oauth;
mod pkce;
mod session;

#[allow(unused_imports)]
pub use device_api::{
    enroll_device, list_devices, revoke_device, rotate_local_device_key, DeviceInfo, EnrollResult,
};
#[allow(unused_imports)]
pub use oauth::{
    exchange_authorization_code, login_browser_pkce, login_device_code, refresh_access_token,
    revoke_token, BrowserLoginOpts, DeviceCodeStart, TokenSet, DEFAULT_SCOPES,
};
#[allow(unused_imports)]
pub use session::{
    clear_session_secrets, load_access_token, open_secret_store, resolve_issuer, save_token_set,
    AuthSession, SessionPaths, DEFAULT_CLIENT_ID, PREFERRED_CALLBACK_PORT,
};

#[cfg(test)]
mod tests;
