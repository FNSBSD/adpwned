#![allow(dead_code)]

// Flags and their values are from http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm
pub(crate) const UAC_ACCOUNT_DISABLE: u32 = 2;
pub(crate) const UAC_HOMEDIR_REQUIRED: u32 = 8;
pub(crate) const UAC_LOCKOUT: u32 = 16;
pub(crate) const UAC_PASSWD_NOTREQD: u32 = 32;
pub(crate) const UAC_PASSWD_CANT_CHANGE: u32 = 64;
pub(crate) const UAC_ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 128;
pub(crate) const UAC_NORMAL_ACCOUNT: u32 = 512;
pub(crate) const UAC_INTERDOMAIN_TRUST_ACCOUNT: u32 = 2048;
pub(crate) const UAC_WORKSTATION_TRUST_ACCOUNT: u32 = 4096;
pub(crate) const UAC_SERVER_TRUST_ACCOUNT: u32 = 8192;
pub(crate) const UAC_DONT_EXPIRE_PASSWD: u32 = 65536;
pub(crate) const UAC_MNS_LOGON_ACCOUNT: u32 = 131072;
pub(crate) const UAC_SMARTCARD_REQUIRED: u32 = 262144;
pub(crate) const UAC_TRUSTED_FOR_DELEGATION: u32 = 524288;
pub(crate) const UAC_NOT_DELEGATED: u32 = 1048576;
pub(crate) const UAC_USE_DES_KEY_ONLY: u32 = 2097152;
pub(crate) const UAC_DONT_REQUIRE_PREAUTH: u32 = 4194304;
pub(crate) const UAC_PASSWORD_EXPIRED: u32 = 8388608;
pub(crate) const UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: u32 = 16777216;
pub(crate) const UAC_NO_AUTH_DATA_REQUIRED: u32 = 33554432;
pub(crate) const UAC_PARTIAL_SECRETS_ACCOUNT: u32 = 67108864;
