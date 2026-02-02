// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VMGS format extensions and extra contents.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

use inspect::Inspect;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Inspect)]
#[serde(rename_all = "lowercase")]
pub enum VmgsProvisioner {
    Unknown,
    HCL,
    OpenHCL,
    CpsVmgstoolCVM,
    CpsVmgstoolTVM,
    HclPostProvisioning,
}

#[derive(Debug, Clone, Serialize, Deserialize, Inspect)]
#[serde(rename_all = "lowercase")]
pub enum VmgsProvisioningReason {
    Empty,
    Failure,
    Request,
}

#[derive(Debug, Serialize, Deserialize, Inspect)]
pub struct VmgsProvisioningMarker {
    pub provisioner: VmgsProvisioner,
    pub reason: Option<VmgsProvisioningReason>,
    pub tpm_version: String,
    pub tpm_nvram_size: usize,
    pub akcert_size: usize,
    pub akcert_attrs: String,
    pub hcl_version: String,
}
