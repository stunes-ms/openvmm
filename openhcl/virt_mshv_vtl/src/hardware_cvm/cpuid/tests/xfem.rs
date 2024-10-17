// Copyright (C) Microsoft Corporation. All rights reserved.

//! Tests for the extended state enumeration subleaves. Many of the expected
//! results were generated by printing values from the OS repo equivalent
//! version.
use super::super::*;
use super::*;
use x86defs::snp::HvPspCpuidLeaf;
use x86defs::snp::HvPspCpuidPage;
use x86defs::snp::HV_PSP_CPUID_LEAF_COUNT_MAX;
use zerocopy::FromZeroes;

/// Tests that xfem results put into page 0 are ignored
#[test]
fn extended_state_enumeration_wrong_page() {
    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];

    for i in 0..2 {
        pages[0].count += 1;
        pages[0].cpuid_leaf_info[i as usize] = HvPspCpuidLeaf {
            eax_in: CpuidFunction::ExtendedStateEnumeration.0,
            ecx_in: i,
            xfem_in: 0,
            xss_in: 0,
            eax_out: 0,
            ebx_out: 0,
            ecx_out: 0,
            edx_out: 0,
            reserved_z: 0,
        };

        // Value should come from page 1
        pages[1].count += 1;
        pages[1].cpuid_leaf_info[i as usize] = HvPspCpuidLeaf {
            eax_in: CpuidFunction::ExtendedStateEnumeration.0,
            ecx_in: i,
            xfem_in: 0,
            xss_in: 0,
            eax_out: 0xffffffff,
            ebx_out: 0xffffffff,
            ecx_out: 0xffffffff,
            edx_out: 0xffffffff,
            reserved_z: 0,
        };
    }

    fill_required_leaves(&mut pages, None);

    let cpuid = CpuidResults::new(CpuidResultsIsolationType::Snp {
        cpuid_pages: pages.as_slice().as_bytes(),
    })
    .unwrap();

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
        CpuidResult {
            eax: u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK)
                | xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
            ebx: 0xffffffff,
            ecx: 0x240,
            edx: 0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
        CpuidResult {
            eax: 0xb,
            ebx: 0xffffffff,
            ecx: 0x1800,
            edx: 0
        }
    );
}

/// Test xfem logic using values provided to the HCL of an SNP VM
#[test]
fn real_xfem() {
    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];

    pages[0].count += 1;
    pages[0].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedFeatures.0,
        ecx_in: 0x0,
        xfem_in: 0x0,
        xss_in: 0x0,
        eax_out: 0x0,
        ebx_out: 0x219c05a9,
        ecx_out: 0x400684,
        edx_out: 0x0,
        reserved_z: 0x0,
    };

    // TODO: these were taken from an HCL-based SNP guest before the latest
    // CPUID changes. An update is needed.
    pages[1].count += 1;
    pages[1].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0x0,
        xfem_in: 0x3,
        xss_in: 0x0,
        eax_out: 0x7,
        ebx_out: 0x240,
        ecx_out: 0x340,
        edx_out: 0x0,
        reserved_z: 0x0,
    };

    pages[1].count += 1;
    pages[1].cpuid_leaf_info[1] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0x1,
        xfem_in: 0x3,
        xss_in: 0x0,
        eax_out: 0xf,
        ebx_out: 0x240,
        ecx_out: 0x1800,
        edx_out: 0x0,
        reserved_z: 0x0,
    };

    pages[1].count += 1;
    pages[1].cpuid_leaf_info[2] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0x2,
        xfem_in: 0x3,
        xss_in: 0x0,
        eax_out: 0x100,
        ebx_out: 0x240,
        ecx_out: 0x0,
        edx_out: 0x0,
        reserved_z: 0x0,
    };

    pages[1].count += 1;
    pages[1].cpuid_leaf_info[3] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0xb,
        xfem_in: 0x3,
        xss_in: 0x0,
        eax_out: 0x10,
        ebx_out: 0x0,
        ecx_out: 0x1,
        edx_out: 0x0,
        reserved_z: 0x0,
    };

    pages[1].count += 1;
    pages[1].cpuid_leaf_info[4] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0xc,
        xfem_in: 0x3,
        xss_in: 0x0,
        eax_out: 0x18,
        ebx_out: 0x0,
        ecx_out: 0x1,
        edx_out: 0x0,
        reserved_z: 0x0,
    };

    fill_required_leaves(&mut pages, None);

    let cpuid = CpuidResults::new(CpuidResultsIsolationType::Snp {
        cpuid_pages: pages.as_slice().as_bytes(),
    })
    .unwrap();

    // results generated from running the HCL implementation
    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
        CpuidResult {
            eax: 0x7,
            ebx: 0x240,
            ecx: 0x340,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
        CpuidResult {
            eax: 0xb,
            ebx: 0x240,
            ecx: 0x1800,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 2),
        CpuidResult {
            eax: 0x100,
            ebx: 0x240,
            ecx: 0x0,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0xb),
        CpuidResult {
            eax: 0x10,
            ebx: 0x0,
            ecx: 0x1,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0xc),
        CpuidResult {
            eax: 0x18,
            ebx: 0x0,
            ecx: 0x1,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
        CpuidResult {
            eax: 0x0,
            ebx: 0x219c05a9,
            ecx: 0x400684,
            edx: 0x0
        }
    );
}

/// Runs a fake extended state enumeration test. Fills in all subleaves based on
/// the given subleaf 0 and 1 masks and eax values, and validates that all
/// subleaves that are not allowed are zeroed. All other subleaves should be
/// validated by the caller.
fn run_fake_xfem_test(
    subleaf0_mask_low: u32,
    subleaf1_eax: u32,
    subleaf1_mask_low: u32,
    adjustable_leaf_eax: u32,
    validation_fn: impl FnOnce(&CpuidResults),
) {
    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];
    pages[0].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedFeatures.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0,
        ebx_out: 0,
        ecx_out: 0xffffffff,
        edx_out: 0,
        reserved_z: 0,
    };
    pages[0].count += 1;

    pages[1].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf0_mask_low,
        ebx_out: 0x0,
        ecx_out: 0xffffffff,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    pages[1].cpuid_leaf_info[1] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 1,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf1_eax,
        ebx_out: 0xffffffff,
        ecx_out: subleaf1_mask_low,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    // Have this skip ExtendedStateEnumeration so that it doesn't put in
    // duplicates, freeing up space to test for higher subleaf values.
    fill_required_leaves(
        &mut pages,
        Some(vec![CpuidFunction::ExtendedStateEnumeration].as_slice()),
    );

    let allowed_subleaf = |index: u32| {
        // All other leaves should be filtered out
        (1u64 << index)
            & (u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64
                | xsave::XSAVE_SUPERVISOR_FEATURE_CET)
            != 0
    };

    for i in 2..=MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF {
        let next_index = pages[1].count as usize;
        if next_index < HV_PSP_CPUID_LEAF_COUNT_MAX {
            if allowed_subleaf(i) {
                // These are the only leaves that are allowed right now. Tests
                // will use the masks in subleaves 0 and 1 to adjust whether
                // these leaves get included or not.
                pages[1].cpuid_leaf_info[next_index] = HvPspCpuidLeaf {
                    eax_in: CpuidFunction::ExtendedStateEnumeration.0,
                    ecx_in: i,
                    xfem_in: 0,
                    xss_in: 0,
                    eax_out: adjustable_leaf_eax,
                    ebx_out: 1 << (i % 32), // Have different values here to mess with the xsave size
                    ecx_out: 0xffffffff,
                    edx_out: 0xffffffff,
                    reserved_z: 0,
                };
            } else {
                // make eax and ebx obviously large to test it doesn't
                // affect xsave size
                pages[1].cpuid_leaf_info[next_index] = HvPspCpuidLeaf {
                    eax_in: CpuidFunction::ExtendedStateEnumeration.0,
                    ecx_in: i,
                    xfem_in: 0,
                    xss_in: 0,
                    eax_out: 0xffffffff,
                    ebx_out: 0xffffffff,
                    ecx_out: 0xffffffff,
                    edx_out: 0xffffffff,
                    reserved_z: 0,
                };
            }
            pages[1].count += 1;
        }
    }

    let cpuid = CpuidResults::new(CpuidResultsIsolationType::Snp {
        cpuid_pages: pages.as_slice().as_bytes(),
    })
    .unwrap();

    validation_fn(&cpuid);

    for i in 2..(MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF + 1) {
        // These should get masked out
        if !allowed_subleaf(i) {
            assert_eq!(
                cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                ZERO_CPUID_RESULT
            );
        }
    }
}

#[test]
fn xfem_baseline() {
    // mask in everything
    let xsave_mask_low = 0xffffffff;
    let xss_mask_low = 0xffffffff;

    let validation = |cpuid: &CpuidResults| {
        // expected results generated from running it through the HCL's
        // implementation
        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0x1a405fe6,
                edx: 0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
            CpuidResult {
                eax: u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK)
                    | xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
                ebx: 0x0,
                ecx: 0x240,
                edx: 0x0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
            CpuidResult {
                eax: 0xb,
                ebx: 0xffffffff,
                ecx: xsave::XSAVE_SUPERVISOR_FEATURE_CET as u32,
                edx: 0x0
            }
        );

        for i in 0..64 {
            if (1 << i) & u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64 != 0 {
                println!("testing extended state enumeration subleaf {i}");
                assert_eq!(
                    cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                    CpuidResult {
                        eax: 0xff,
                        ebx: 1 << (i % 32),
                        ecx: 0xffffffff,
                        edx: 0xffffffff
                    }
                );
            }
        }

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_U
            ),
            CpuidResult {
                eax: 0xff,
                ebx: 0x800,
                ecx: 0xffffffff,
                edx: 0xffffffff
            }
        );

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_S
            ),
            CpuidResult {
                eax: 0xff,
                ebx: 0x1000,
                ecx: 0xffffffff,
                edx: 0xffffffff
            }
        );
    };

    run_fake_xfem_test(xsave_mask_low, 0xffffffff, xss_mask_low, 0xff, validation);
}

#[test]
fn xfem_cet() {
    // making this all 1s will test that the CET indices get filtered out
    let xsave_mask_low = 0xffffffff;

    // zero CET bits to check they get suppressed
    let xss_mask_low = !(xsave::XSAVE_SUPERVISOR_FEATURE_CET as u32);

    // make xsave_s and xsave_c true so that the xss mask is considered
    let xss_eax = 0xffffffff;

    let validation = |cpuid: &CpuidResults| {
        // expected results generated from running it through the HCL's
        // implementation
        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0x1a405f66,
                edx: 0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
            CpuidResult {
                eax: u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK)
                    | xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
                ebx: 0x0,
                ecx: 0x240,
                edx: 0x0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
            CpuidResult {
                eax: 0xb,
                ebx: 0xffffffff,
                ecx: 0x0,
                edx: 0x0
            }
        );

        for i in 0..64 {
            if (1 << i) & u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64 != 0 {
                assert_eq!(
                    cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                    CpuidResult {
                        eax: 0xff,
                        ebx: 1 << (i % 32),
                        ecx: 0xffffffff,
                        edx: 0xffffffff
                    }
                );
            }
        }

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_U
            ),
            ZERO_CPUID_RESULT
        );

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_S
            ),
            ZERO_CPUID_RESULT
        );
    };

    run_fake_xfem_test(xsave_mask_low, xss_eax, xss_mask_low, 0xff, validation);
}

#[test]
fn xfem_xsave_mask() {
    let xsave_mask_low = 0xffffffff;

    // make 0 to check that xsave keeps the leaves it cares about
    let xss_mask_low = 0;

    // test the mask capabilities, so xsave_s and xsave_c should be 1
    let subleaf1_eax = 0xffffffff;

    let validation = |cpuid: &CpuidResults| {
        // expected results generated from running it through the HCL's
        // implementation
        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0x1a405f66,
                edx: 0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
            CpuidResult {
                eax: u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK)
                    | xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
                ebx: 0x0,
                ecx: 0x240,
                edx: 0x0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
            CpuidResult {
                eax: 0xb,
                ebx: 0xffffffff,
                ecx: 0x0,
                edx: 0x0
            }
        );

        for i in 0..64 {
            if (1 << i) & u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64 != 0 {
                assert_eq!(
                    cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                    CpuidResult {
                        eax: 0xff,
                        ebx: 1 << (i % 32),
                        ecx: 0xffffffff,
                        edx: 0xffffffff
                    }
                );
            }
        }

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_U
            ),
            ZERO_CPUID_RESULT
        );

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_S
            ),
            ZERO_CPUID_RESULT
        );
    };

    run_fake_xfem_test(xsave_mask_low, subleaf1_eax, xss_mask_low, 0xff, validation);
}

#[test]
fn xfem_xss_mask() {
    // zero to check that the xss mask keeps in its subleaves
    let xsave_mask_low = 0;

    let xss_mask_low = 0xffffffff;

    // test the mask capabilities, so xsave_s and xsave_c should be 1
    let subleaf1_eax = 0xffffffff;

    let validation = |cpuid: &CpuidResults| {
        // expected results generated from running it through the HCL's
        // implementation
        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0x1a405fe6,
                edx: 0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
            CpuidResult {
                eax: xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
                ebx: 0x0,
                ecx: 0x240,
                edx: 0x0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
            CpuidResult {
                eax: 0xb,
                ebx: 0xffffffff,
                ecx: xsave::XSAVE_SUPERVISOR_FEATURE_CET as u32,
                edx: 0x0
            }
        );

        for i in 0..64 {
            if (1 << i) & u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64 != 0 {
                assert_eq!(
                    cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                    ZERO_CPUID_RESULT
                );
            }
        }

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_U
            ),
            CpuidResult {
                eax: 0xff,
                ebx: 0x800,
                ecx: 0xffffffff,
                edx: 0xffffffff
            }
        );

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_S
            ),
            CpuidResult {
                eax: 0xff,
                ebx: 0x1000,
                ecx: 0xffffffff,
                edx: 0xffffffff
            }
        );
    };

    run_fake_xfem_test(xsave_mask_low, subleaf1_eax, xss_mask_low, 0xff, validation);
}

#[test]
fn xfem_masked_out() {
    // zero both to check that the subleaf gets removed
    let subleaf_mask_low = 0;

    // make xsave_s and xsave_c 1 to test xss mask
    let subleaf1_eax = 0xffffffff;

    let validation = |cpuid: &CpuidResults| {
        // expected results generated from running it through the HCL's
        // implementation
        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0x1a405f66,
                edx: 0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
            CpuidResult {
                eax: xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
                ebx: 0x0,
                ecx: 0x240,
                edx: 0x0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
            CpuidResult {
                eax: 0xb,
                ebx: 0xffffffff,
                ecx: 0x0,
                edx: 0x0
            }
        );

        for i in 0..64 {
            if (1 << i) & u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64 != 0 {
                assert_eq!(
                    cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                    ZERO_CPUID_RESULT
                );
            }
        }

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_U
            ),
            ZERO_CPUID_RESULT
        );

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_S
            ),
            ZERO_CPUID_RESULT
        );
    };

    run_fake_xfem_test(
        subleaf_mask_low,
        subleaf1_eax,
        subleaf_mask_low,
        0xff,
        validation,
    );
}

#[test]
fn xfem_xsave_cs() {
    // for xsave, making this all 1s will test that the CET indices get filtered out
    // for xss, all 1s will test that the eax value is what matters here
    let subleaf_mask_low = 0xffffffff;

    // zero xsave_s and xsave_c to check that the CET leaves get removed
    let subleaf1_eax = !u32::from(
        cpuid::ExtendedStateEnumerationSubleaf1Eax::new()
            .with_xsave_s(true)
            .with_xsave_c(true),
    );

    let validation = |cpuid: &CpuidResults| {
        // expected results generated from running it through the HCL's
        // implementation
        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0x1a405f66,
                edx: 0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
            CpuidResult {
                eax: u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK)
                    | xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
                ebx: 0x0,
                ecx: 0x240,
                edx: 0x0
            }
        );

        assert_eq!(
            cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
            CpuidResult {
                eax: 0x1,
                ebx: 0xffffffff,
                ecx: 0x0,
                edx: 0x0
            }
        );

        for i in 0..64 {
            if (1 << i) & u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK) as u64 != 0 {
                assert_eq!(
                    cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, i),
                    CpuidResult {
                        eax: 0xff,
                        ebx: 1 << (i % 32),
                        ecx: 0xffffffff,
                        edx: 0xffffffff
                    }
                );
            }
        }

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_U
            ),
            ZERO_CPUID_RESULT
        );

        assert_eq!(
            cpuid.registered_result(
                CpuidFunction::ExtendedStateEnumeration,
                xsave::XSAVE_SUPERVISOR_FEATURE_INDEX_CET_S
            ),
            ZERO_CPUID_RESULT
        );
    };

    run_fake_xfem_test(
        subleaf_mask_low,
        subleaf1_eax,
        subleaf_mask_low,
        0xff,
        validation,
    );
}

#[test]
fn xfem_bounds() {
    let subleaf_mask_low = 0xffffffff;

    // make xsave_s and xsave_c 1 to test xss mask
    let subleaf1_eax = 0xffffffff;

    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];
    pages[0].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedFeatures.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0,
        ebx_out: 0,
        ecx_out: 0xffffffff,
        edx_out: 0,
        reserved_z: 0,
    };
    pages[0].count += 1;

    pages[1].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf_mask_low,
        ebx_out: 0x0, // offset
        ecx_out: 0xffffffff,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    pages[1].cpuid_leaf_info[1] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 1,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf1_eax,
        ebx_out: 0xffffffff,
        ecx_out: subleaf_mask_low,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    pages[1].cpuid_leaf_info[2] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0xffffffff,
        ebx_out: 0xffffffff,
        ecx_out: 0xffffffff,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    pages[1].cpuid_leaf_info[3] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF + 1,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0xffffffff,
        ebx_out: 0xffffffff,
        ecx_out: 0xffffffff,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    fill_required_leaves(&mut pages, None);

    let cpuid = CpuidResults::new(CpuidResultsIsolationType::Snp {
        cpuid_pages: pages.as_slice().as_bytes(),
    })
    .unwrap();

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedFeatures, 0),
        CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0x1a405fe6,
            edx: 0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 0),
        CpuidResult {
            eax: u32::from(XSAVE_ADDITIONAL_SUBLEAF_MASK)
                | xsave::X86X_XSAVE_LEGACY_FEATURES as u32,
            ebx: 0x0,
            ecx: 0x240,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(CpuidFunction::ExtendedStateEnumeration, 1),
        CpuidResult {
            eax: 0xb,
            ebx: 0xffffffff,
            ecx: xsave::XSAVE_SUPERVISOR_FEATURE_CET as u32,
            edx: 0x0
        }
    );

    assert_eq!(
        cpuid.registered_result(
            CpuidFunction::ExtendedStateEnumeration,
            MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF
        ),
        ZERO_CPUID_RESULT
    );

    assert_eq!(
        cpuid.registered_result(
            CpuidFunction::ExtendedStateEnumeration,
            MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF + 1
        ),
        ZERO_CPUID_RESULT
    );
}

#[test]
fn xfem_missing_subleaf0() {
    let subleaf_mask_low = 0xffffffff;
    let subleaf1_eax = 0xffffffff;

    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];
    pages[0].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedFeatures.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0,
        ebx_out: 0,
        ecx_out: 0xffffffff,
        edx_out: 0,
        reserved_z: 0,
    };
    pages[0].count += 1;

    pages[1].cpuid_leaf_info[1] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 1,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf1_eax,
        ebx_out: 0xffffffff,
        ecx_out: subleaf_mask_low,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    fill_required_leaves(
        &mut pages,
        Some(vec![CpuidFunction::ExtendedStateEnumeration].as_slice()),
    );

    assert!(matches!(
        CpuidResults::new(CpuidResultsIsolationType::Snp {
            cpuid_pages: pages.as_slice().as_bytes(),
        }),
        Err(CpuidResultsError::MissingRequiredResult(
            CpuidFunction::ExtendedStateEnumeration,
            Some(0)
        ))
    ));
}

#[test]
fn xfem_missing_subleaf1() {
    let subleaf_mask_low = 0xffffffff;

    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];
    pages[0].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedFeatures.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0,
        ebx_out: 0,
        ecx_out: 0xffffffff,
        edx_out: 0,
        reserved_z: 0,
    };
    pages[0].count += 1;

    pages[1].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf_mask_low,
        ebx_out: 0x0, // offset
        ecx_out: 0xffffffff,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    fill_required_leaves(
        &mut pages,
        Some(vec![CpuidFunction::ExtendedStateEnumeration].as_slice()),
    );

    assert!(matches!(
        CpuidResults::new(CpuidResultsIsolationType::Snp {
            cpuid_pages: pages.as_slice().as_bytes(),
        }),
        Err(CpuidResultsError::MissingRequiredResult(
            CpuidFunction::ExtendedStateEnumeration,
            Some(1)
        ))
    ));
}

#[test]
fn xfem_missing_additional_subleaf() {
    let subleaf_mask_low = 0xffffffff;
    let subleaf1_eax = 0xffffffff;

    let mut pages = vec![HvPspCpuidPage::new_zeroed(), HvPspCpuidPage::new_zeroed()];
    pages[0].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedFeatures.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: 0,
        ebx_out: 0,
        ecx_out: 0xffffffff,
        edx_out: 0,
        reserved_z: 0,
    };
    pages[0].count += 1;

    pages[1].cpuid_leaf_info[0] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 0,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf_mask_low,
        ebx_out: 0x0, // offset
        ecx_out: 0xffffffff,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    pages[1].cpuid_leaf_info[1] = HvPspCpuidLeaf {
        eax_in: CpuidFunction::ExtendedStateEnumeration.0,
        ecx_in: 1,
        xfem_in: 0,
        xss_in: 0,
        eax_out: subleaf1_eax,
        ebx_out: 0xffffffff,
        ecx_out: subleaf_mask_low,
        edx_out: 0xffffffff, // high mask
        reserved_z: 0,
    };
    pages[1].count += 1;

    fill_required_leaves(
        &mut pages,
        Some(vec![CpuidFunction::ExtendedStateEnumeration].as_slice()),
    );

    assert!(matches!(
        CpuidResults::new(CpuidResultsIsolationType::Snp {
            cpuid_pages: pages.as_slice().as_bytes(),
        }),
        Err(CpuidResultsError::MissingRequiredResult(
            CpuidFunction::ExtendedStateEnumeration,
            Some(2)
        ))
    ));
}