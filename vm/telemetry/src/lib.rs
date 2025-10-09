// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Contains definitions used for logging certain interesting operations around
//! VM provisioning.

#![forbid(unsafe_code)]

/// Operation types for VM provisioning telemetry.
#[derive(Debug)]
pub enum LogOpType {
    /// Formatting a VMGS file.
    VmgsProvision,
    /// Beginning callback to agent to get GSP data.
    BeginGspCallback,
    /// Ending callback to agent to get GSP data.
    GspCallback,
    /// Beginning VMGS file decryption.
    BeginDecryptVmgs,
    /// Ending VMGS file decryption.
    DecryptVmgs,
    /// Converting VMGS file from GSP-by-ID to GSP Key encryption.
    ConvertEncryptionType,
    /// Beginning derivation of vTPM primary keys.
    BeginVtpmKeysProvision,
    /// Ending derivation of vTPM primary keys.
    VtpmKeysProvision,
    /// Beginning callback to obtain AK certificate.
    BeginAkCertProvision,
    /// Ending callback to obtain AK certificate.
    AkCertProvision,
    /// Beginning write to TPM NVRAM index.
    BeginNvWrite,
    /// Ending write to TPM NVRAM index.
    NvWrite,
    /// Beginning read from TPM NVRAM index.
    BeginNvRead,
    /// Ending read from TPM NVRAM index.
    NvRead,
}
