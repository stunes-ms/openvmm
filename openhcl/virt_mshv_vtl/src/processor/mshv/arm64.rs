// Copyright (C) Microsoft Corporation. All rights reserved.

//! Aarch64 Processor support for Microsoft hypervisor-backed partitions.

#![cfg(guest_arch = "aarch64")]

type VpRegisterName = HvArm64RegisterName;

use super::super::private::BackingParams;
use super::super::signal_mnf;
use super::super::vp_state;
use super::super::vp_state::UhVpStateAccess;
use super::super::BackingPrivate;
use super::super::UhRunVpError;
use crate::processor::UhEmulationState;
use crate::processor::UhHypercallHandler;
use crate::processor::UhProcessor;
use crate::Error;
use crate::HypervisorBacked;
use aarch64defs::Cpsr64;
use aarch64emu::AccessCpuState;
use aarch64emu::InterceptState;
use hcl::ioctl;
use hcl::ioctl::aarch64::MshvArm64;
use hcl::ioctl::ProcessorRunner;
use hvdef::hypercall;
use hvdef::HvAarch64PendingEvent;
use hvdef::HvArm64RegisterName;
use hvdef::HvArm64ResetType;
use hvdef::HvDeliverabilityNotificationsRegister;
use hvdef::HvMapGpaFlags;
use hvdef::HvMessageType;
use hvdef::HvRegisterValue;
use hvdef::Vtl;
use inspect::Inspect;
use inspect::InspectMut;
use inspect_counters::Counter;
use virt::aarch64::vp;
use virt::aarch64::vp::AccessVpState;
use virt::io::CpuIo;
use virt::state::HvRegisterState;
use virt::state::StateElement;
use virt::VpHaltReason;
use virt::VpIndex;
use virt_support_aarch64emu::emulate;
use virt_support_aarch64emu::emulate::EmuCheckVtlAccessError;
use virt_support_aarch64emu::emulate::EmuTranslateError;
use virt_support_aarch64emu::emulate::EmuTranslateResult;
use virt_support_aarch64emu::emulate::EmulatorSupport;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// The current CPU register state. Some of the fields are updated by the emulator.
#[derive(Debug, Default, Clone, Inspect, PartialEq)]
pub struct CpuState {
    /// X0-x30.
    #[inspect(iter_by_index)]
    x: [u64; 31],
    // Q0-Q31
    #[inspect(skip)]
    q: [u128; 32],

    pc: Option<u64>,
    sp: Option<u64>,
    cpsr: Option<u64>,
    x18_valid: bool,
}

impl CpuState {
    /// Get current state after an intercept.
    pub fn sync(&mut self, runner: &ProcessorRunner<'_, MshvArm64>) {
        self.x = runner.cpu_context().x;
        self.q = runner.cpu_context().q;
        self.pc = None;
        self.sp = None;
        self.cpsr = None;
        self.x18_valid = false;
    }
}

/// A backing for hypervisor-backed partitions (non-isolated and
/// software-isolated).
#[derive(InspectMut)]
pub struct HypervisorBackedArm64 {
    #[inspect(with = "|x| inspect::AsHex(u64::from(*x))")]
    deliverability_notifications: HvDeliverabilityNotificationsRegister,
    #[inspect(with = "|x| inspect::AsHex(u64::from(*x))")]
    next_deliverability_notifications: HvDeliverabilityNotificationsRegister,
    stats: ProcessorStatsArm64,
    cpu_state: CpuState,
}

#[derive(Inspect, Default)]
struct ProcessorStatsArm64 {
    mmio: Counter,
    unaccepted_gpa: Counter,
    hypercall: Counter,
    synic_deliverable: Counter,
}

impl BackingPrivate for HypervisorBackedArm64 {
    type HclBacking = MshvArm64;

    type BackingShared = ();

    fn new_shared_state(
        _params: crate::processor::BackingSharedParams<'_>,
    ) -> Result<Self::BackingShared, Error> {
        Ok(())
    }

    fn new(params: BackingParams<'_, '_, Self>) -> Result<Self, Error> {
        vp::Registers::at_reset(&params.partition.caps, params.vp_info);
        let _ = (params.runner, &params.backing_shared);
        Ok(Self {
            deliverability_notifications: Default::default(),
            next_deliverability_notifications: Default::default(),
            stats: Default::default(),
            cpu_state: CpuState::default(),
        })
    }

    fn init(_this: &mut UhProcessor<'_, Self>) {}

    type StateAccess<'p, 'a> = UhVpStateAccess<'a, 'p, Self> where Self: 'a + 'p, 'p: 'a;

    fn access_vp_state<'a, 'p>(
        this: &'a mut UhProcessor<'p, Self>,
        vtl: Vtl,
    ) -> Self::StateAccess<'p, 'a> {
        UhVpStateAccess::new(this, vtl)
    }

    async fn run_vp(
        this: &mut UhProcessor<'_, Self>,
        dev: &impl CpuIo,
        _stop: &mut virt::StopVp<'_>,
    ) -> Result<(), VpHaltReason<UhRunVpError>> {
        if this.backing.deliverability_notifications
            != this.backing.next_deliverability_notifications
        {
            let notifications = this.backing.next_deliverability_notifications;
            tracing::trace!(?notifications, "setting notifications");
            this.runner
                .set_vp_register(
                    VpRegisterName::DeliverabilityNotifications,
                    u64::from(notifications).into(),
                )
                .expect("requesting deliverability is not a fallable operation");
            this.backing.deliverability_notifications =
                this.backing.next_deliverability_notifications;
        }

        let intercepted = this
            .runner
            .run()
            .map_err(|e| VpHaltReason::Hypervisor(UhRunVpError::Run(e)))?;

        if intercepted {
            let stat = match this.runner.exit_message().header.typ {
                HvMessageType::HvMessageTypeUnmappedGpa
                | HvMessageType::HvMessageTypeGpaIntercept => {
                    this.handle_mmio_exit(dev).await?;
                    &mut this.backing.stats.mmio
                }
                HvMessageType::HvMessageTypeUnacceptedGpa => {
                    this.handle_unaccepted_gpa_intercept(dev).await?;
                    &mut this.backing.stats.unaccepted_gpa
                }
                HvMessageType::HvMessageTypeHypercallIntercept => {
                    this.handle_hypercall_exit(dev)?;
                    &mut this.backing.stats.hypercall
                }
                HvMessageType::HvMessageTypeSynicSintDeliverable => {
                    this.handle_synic_deliverable_exit();
                    &mut this.backing.stats.synic_deliverable
                }
                HvMessageType::HvMessageTypeArm64ResetIntercept => {
                    let message = hvdef::HvArm64ResetInterceptMessage::ref_from_prefix(
                        this.runner.exit_message().payload(),
                    )
                    .unwrap();
                    match message.reset_type {
                        HvArm64ResetType::POWER_OFF => return Err(VpHaltReason::PowerOff),
                        HvArm64ResetType::REBOOT => return Err(VpHaltReason::Reset),
                        ty => unreachable!("unknown reset type: {:#x?}", ty),
                    }
                }
                reason => unreachable!("unknown exit reason: {:#x?}", reason),
            };
            stat.increment();
        }
        Ok(())
    }

    fn poll_apic(
        _this: &mut UhProcessor<'_, Self>,
        _vtl: Vtl,
        _scan_irr: bool,
    ) -> Result<bool, UhRunVpError> {
        Ok(true)
    }

    fn request_extint_readiness(this: &mut UhProcessor<'_, Self>) {
        this.backing
            .next_deliverability_notifications
            .set_interrupt_notification(true);
    }

    fn request_untrusted_sint_readiness(this: &mut UhProcessor<'_, Self>, sints: u16) {
        this.backing
            .next_deliverability_notifications
            .set_sints(this.backing.next_deliverability_notifications.sints() | sints);
    }

    /// The VTL that was running when the VP exited into VTL2, with the
    /// exception of a successful vtl switch, where it will return the VTL
    /// that will run on VTL 2 exit.
    fn last_vtl(_this: &UhProcessor<'_, Self>) -> Vtl {
        // TODO ARM64
        Vtl::Vtl0
    }

    /// Copies shared registers (per VSM TLFS spec) from the last VTL to
    /// the target VTL that will become active.
    fn switch_vtl_state(_this: &mut UhProcessor<'_, Self>, _target_vtl: Vtl) {
        unreachable!("vtl switching should be managed by the hypervisor");
    }

    fn inspect_extra(_this: &mut UhProcessor<'_, Self>, _resp: &mut inspect::Response<'_>) {}
}

impl UhProcessor<'_, HypervisorBackedArm64> {
    fn handle_synic_deliverable_exit(&mut self) {
        let message = hvdef::HvArm64SynicSintDeliverableMessage::ref_from_prefix(
            self.runner.exit_message().payload(),
        )
        .unwrap();

        tracing::trace!(
            deliverable_sints = message.deliverable_sints,
            "sint deliverable"
        );

        self.backing.deliverability_notifications.set_sints(
            self.backing.deliverability_notifications.sints() & !message.deliverable_sints,
        );

        // This is updated by `deliver_synic_messages below`, so clear it here.
        self.backing.next_deliverability_notifications.set_sints(0);

        // These messages are always VTL0, as VTL1 does not own any VMBUS channels.
        self.deliver_synic_messages(Vtl::Vtl0, message.deliverable_sints);
    }

    fn handle_hypercall_exit(
        &mut self,
        bus: &impl CpuIo,
    ) -> Result<(), VpHaltReason<UhRunVpError>> {
        let message = hvdef::HvArm64HypercallInterceptMessage::ref_from_prefix(
            self.runner.exit_message().payload(),
        )
        .unwrap();

        tracing::trace!(msg = %format_args!("{:x?}", message), "hypercall");

        let guest_memory = self.last_vtl_gm();
        let smccc_convention = message.immediate == 0;

        let handler = UhHypercallHandler {
            vp: self,
            bus,
            trusted: false,
        };
        UhHypercallHandler::MSHV_DISPATCHER.dispatch(
            guest_memory,
            hv1_hypercall::Arm64RegisterIo::new(handler, false, smccc_convention),
        );

        Ok(())
    }

    async fn handle_mmio_exit(
        &mut self,
        dev: &impl CpuIo,
    ) -> Result<(), VpHaltReason<UhRunVpError>> {
        let message = hvdef::HvArm64MemoryInterceptMessage::ref_from_prefix(
            self.runner.exit_message().payload(),
        )
        .unwrap();
        // tracing::trace!(msg = %format_args!("{:x?}", message), "mmio");

        self.backing.cpu_state.sync(&self.runner);
        let intercept_state = InterceptState {
            instruction_bytes: message.instruction_bytes,
            instruction_byte_count: message.instruction_byte_count,
            gpa: Some(message.guest_physical_address),
            syndrome: aarch64defs::EsrEl2::from(message.syndrome),
            interruption_pending: message.header.execution_state.interruption_pending(),
        };

        self.emulate(dev, &intercept_state).await?;
        Ok(())
    }

    async fn handle_unaccepted_gpa_intercept(
        &mut self,
        dev: &impl CpuIo,
    ) -> Result<(), VpHaltReason<UhRunVpError>> {
        let gpa = hvdef::HvArm64MemoryInterceptMessage::ref_from_prefix(
            self.runner.exit_message().payload(),
        )
        .unwrap()
        .guest_physical_address;

        if self.partition.is_gpa_lower_vtl_ram(gpa) {
            // The host may have moved the page to an unaccepted state, so fail
            // here. This does not apply to VTL 2 memory - for unaccepted pages,
            // the intercept goes to host VTL0.
            //
            // Note: SGX memory should be included in this check, so if SGX is
            // no longer included in the lower_vtl_memory_layout, make sure the
            // appropriate changes are reflected here.
            Err(VpHaltReason::InvalidVmState(
                UhRunVpError::UnacceptedMemoryAccess(gpa),
            ))
        } else {
            // TODO SNP: for hardware isolation, if the intercept is due to a guest
            // error, inject a machine check
            self.handle_mmio_exit(dev).await?;
            Ok(())
        }
    }
}

impl AccessCpuState for UhProcessor<'_, HypervisorBackedArm64> {
    fn commit(&mut self) {
        let mut expensive_regs = Vec::with_capacity(3);
        if self.backing.cpu_state.x18_valid {
            expensive_regs.push((HvArm64RegisterName::X18, self.x(18)));
        }
        if self.backing.cpu_state.pc.is_some() {
            expensive_regs.push((HvArm64RegisterName::XPc, self.pc()));
        }
        if self.backing.cpu_state.sp.is_some() {
            expensive_regs.push((HvArm64RegisterName::XSp, self.sp()));
        }
        self.runner.set_vp_registers(expensive_regs).unwrap();
        self.runner.cpu_context_mut().x = self.backing.cpu_state.x;
        self.runner.cpu_context_mut().q = self.backing.cpu_state.q;
    }

    fn x(&mut self, index: u8) -> u64 {
        assert!(index < 31);
        if index == 18 && !self.backing.cpu_state.x18_valid {
            let reg_val = self
                .runner
                .get_vp_register(HvArm64RegisterName::X18)
                .expect("register query should not fail");
            self.backing.cpu_state.x[18] = reg_val.as_u64();
            self.backing.cpu_state.x18_valid = true;
        }
        self.backing.cpu_state.x[index as usize]
    }

    fn update_x(&mut self, index: u8, data: u64) {
        assert!(index < 31);
        self.backing.cpu_state.x[index as usize] = data;
        if index == 18 {
            self.backing.cpu_state.x18_valid = true;
        }
    }

    fn q(&self, index: u8) -> u128 {
        assert!(index < 32);
        self.backing.cpu_state.q[index as usize]
    }

    fn update_q(&mut self, index: u8, data: u128) {
        assert!(index < 32);
        self.backing.cpu_state.q[index as usize] = data;
    }

    fn d(&self, index: u8) -> u64 {
        (self.q(index) & 0xffffffff_ffffffff) as u64
    }

    fn update_d(&mut self, index: u8, data: u64) {
        self.update_q(index, data as u128);
    }

    fn h(&self, index: u8) -> u32 {
        (self.d(index) & 0xffffffff) as u32
    }

    fn update_h(&mut self, index: u8, data: u32) {
        self.update_q(index, data as u128);
    }

    fn s(&self, index: u8) -> u16 {
        (self.h(index) & 0xffff) as u16
    }

    fn update_s(&mut self, index: u8, data: u16) {
        self.update_q(index, data as u128);
    }

    fn b(&self, index: u8) -> u8 {
        (self.s(index) & 0xff) as u8
    }

    fn update_b(&mut self, index: u8, data: u8) {
        self.update_q(index, data as u128);
    }

    fn sp(&mut self) -> u64 {
        if self.backing.cpu_state.sp.is_none() {
            let reg_val = self
                .runner
                .get_vp_register(HvArm64RegisterName::XSp)
                .expect("register query should not fail");
            self.backing.cpu_state.sp = Some(reg_val.as_u64());
        }
        self.backing.cpu_state.sp.unwrap()
    }

    fn update_sp(&mut self, data: u64) {
        self.backing.cpu_state.sp = Some(data);
    }

    fn fp(&mut self) -> u64 {
        self.x(29)
    }

    fn update_fp(&mut self, data: u64) {
        self.update_x(29, data)
    }

    fn lr(&mut self) -> u64 {
        self.x(30)
    }

    fn update_lr(&mut self, data: u64) {
        self.update_x(30, data)
    }

    fn pc(&mut self) -> u64 {
        if self.backing.cpu_state.pc.is_none() {
            let reg_val = self
                .runner
                .get_vp_register(HvArm64RegisterName::XPc)
                .expect("register query should not fail");
            self.backing.cpu_state.pc = Some(reg_val.as_u64());
        }
        self.backing.cpu_state.pc.unwrap()
    }

    fn update_pc(&mut self, data: u64) {
        self.backing.cpu_state.pc = Some(data);
    }

    fn cpsr(&mut self) -> Cpsr64 {
        if self.backing.cpu_state.cpsr.is_none() {
            let reg_val = self
                .runner
                .get_vp_register(HvArm64RegisterName::Cpsr)
                .expect("register query should not fail");
            self.backing.cpu_state.cpsr = Some(reg_val.as_u64());
        }
        Cpsr64::from(self.backing.cpu_state.cpsr.unwrap())
    }
}

impl<T: CpuIo> EmulatorSupport for UhEmulationState<'_, '_, T, HypervisorBacked> {
    type Error = UhRunVpError;

    fn vp_index(&self) -> VpIndex {
        self.vp.vp_index()
    }

    fn physical_address(&self) -> Option<u64> {
        let message = self.vp.runner.exit_message();
        match message.header.typ {
            HvMessageType::HvMessageTypeGpaIntercept
            | HvMessageType::HvMessageTypeUnmappedGpa
            | HvMessageType::HvMessageTypeUnacceptedGpa => {
                let message =
                    hvdef::HvArm64MemoryInterceptMessage::ref_from_prefix(message.payload())
                        .unwrap();
                Some(message.guest_physical_address)
            }
            _ => None,
        }
    }

    fn initial_gva_translation(&self) -> Option<emulate::InitialTranslation> {
        if (self.vp.runner.exit_message().header.typ != HvMessageType::HvMessageTypeGpaIntercept)
            && (self.vp.runner.exit_message().header.typ != HvMessageType::HvMessageTypeUnmappedGpa)
            && (self.vp.runner.exit_message().header.typ
                != HvMessageType::HvMessageTypeUnacceptedGpa)
        {
            return None;
        }

        let message = hvdef::HvArm64MemoryInterceptMessage::ref_from_prefix(
            self.vp.runner.exit_message().payload(),
        )?;

        if !message.memory_access_info.gva_gpa_valid() {
            tracing::trace!(?message.guest_virtual_address, ?message.guest_physical_address, "gva gpa not valid {:?}", self.vp.runner.exit_message().payload());
            return None;
        }

        let translate_mode = emulate::TranslateMode::try_from(message.header.intercept_access_type)
            .expect("unexpected intercept access type");

        tracing::trace!(?message.guest_virtual_address, ?message.guest_physical_address, ?translate_mode, "initial translation");

        Some(emulate::InitialTranslation {
            gva: message.guest_virtual_address,
            gpa: message.guest_physical_address,
            translate_mode,
        })
    }

    fn interruption_pending(&self) -> bool {
        self.interruption_pending
    }

    fn check_vtl_access(
        &mut self,
        gpa: u64,
        mode: emulate::TranslateMode,
    ) -> Result<(), EmuCheckVtlAccessError<Self::Error>> {
        // Underhill currently doesn't set VTL 2 protections against execute exclusively, it removes
        // all permissions from a page. So for VTL 1, no need to check the permissions; if VTL 1
        // doesn't have permissions to a page, Underhill should appropriately fail when it tries
        // to read or write to that page on VTL 1's behalf.
        //
        // For VTL 0, the alias map guards for read and write permissions, so only check VTL execute
        // permissions. Because VTL 2 will not restrict execute exclusively, only VTL 1 execute
        // permissions need to be checked and therefore only check permissions if VTL 1 is allowed.
        //
        // Note: the restriction to VTL 1 support also means that for WHP, which doesn't support VTL 1
        // the HvCheckSparseGpaPageVtlAccess hypercall--which is unimplemented in whp--will never be made.
        if mode == emulate::TranslateMode::Execute
            && self.vp.last_vtl() == Vtl::Vtl0
            && self.vp.vtl1_supported()
        {
            // Should always be called after translate gva with the tlb lock flag
            debug_assert!(self.vp.is_tlb_locked(Vtl::Vtl2, self.vp.last_vtl()));

            let cpsr: Cpsr64 = self
                .vp
                .runner
                .get_vp_register(HvArm64RegisterName::SpsrEl2)
                .map_err(UhRunVpError::EmulationState)?
                .as_u64()
                .into();

            let flags = if cpsr.el() == 0 {
                HvMapGpaFlags::new().with_user_executable(true)
            } else {
                HvMapGpaFlags::new().with_kernel_executable(true)
            };

            let access_result = self
                .vp
                .partition
                .hcl
                .check_vtl_access(gpa, Vtl::Vtl0, flags)
                .map_err(|e| EmuCheckVtlAccessError::Hypervisor(UhRunVpError::VtlAccess(e)))?;

            if let Some(ioctl::CheckVtlAccessResult { vtl, denied_flags }) = access_result {
                return Err(EmuCheckVtlAccessError::AccessDenied { vtl, denied_flags });
            };
        }

        Ok(())
    }

    fn translate_gva(
        &mut self,
        gva: u64,
        mode: emulate::TranslateMode,
    ) -> Result<Result<EmuTranslateResult, EmuTranslateError>, Self::Error> {
        let mut control_flags = hypercall::TranslateGvaControlFlagsArm64::new();
        match mode {
            emulate::TranslateMode::Read => control_flags.set_validate_read(true),
            emulate::TranslateMode::Write => {
                control_flags.set_validate_read(true);
                control_flags.set_validate_write(true);
            }
            emulate::TranslateMode::Execute => control_flags.set_validate_execute(true),
        };

        // The translation will be used, so set the appropriate page table bits
        // (the access/dirty bit).
        //
        // Prevent flushes in order to make sure that translation of this GVA
        // remains usable until the VP is resumed back to direct execution.
        control_flags.set_set_page_table_bits(true);
        control_flags.set_tlb_flush_inhibit(true);

        // In case we're not running ring 0, check privileges against VP state
        // as of when the original intercept came in - since the emulator
        // doesn't support instructions that change ring level, the ring level
        // will remain the same as it was in the VP state as of when the
        // original intercept came in. The privilege exempt flag should
        // not be set.
        assert!(!control_flags.pan_clear());

        // Do the translation using the current VTL.
        control_flags.set_input_vtl(self.vp.last_vtl().into());

        match self
            .vp
            .partition
            .hcl
            .translate_gva_to_gpa(gva, control_flags)
            .map_err(|e| UhRunVpError::TranslateGva(ioctl::Error::TranslateGvaToGpa(e)))?
        {
            Ok(ioctl::TranslateResult {
                gpa_page,
                overlay_page,
            }) => Ok(Ok(EmuTranslateResult {
                gpa: (gpa_page << hvdef::HV_PAGE_SHIFT) + (gva & (hvdef::HV_PAGE_SIZE - 1)),
                overlay_page: Some(overlay_page),
            })),
            Err(ioctl::aarch64::TranslateErrorAarch64 { code }) => Ok(Err(EmuTranslateError {
                code: hypercall::TranslateGvaResultCode(code),
                event_info: None,
            })),
        }
    }

    fn inject_pending_event(&mut self, event_info: HvAarch64PendingEvent) {
        let regs = [(
            HvArm64RegisterName::PendingEvent0,
            u128::from_ne_bytes(event_info.as_bytes().try_into().unwrap()),
        )];

        let last_vtl = self.vp.last_vtl();
        self.vp
            .runner
            .set_vp_registers_hvcall(last_vtl, regs)
            .expect("set_vp_registers hypercall for setting pending event should not fail");
    }

    fn check_monitor_write(&self, gpa: u64, bytes: &[u8]) -> bool {
        self.vp
            .partition
            .monitor_page
            .check_write(gpa, bytes, |connection_id| {
                signal_mnf(self.devices, connection_id)
            })
    }

    fn is_gpa_mapped(&self, gpa: u64, write: bool) -> bool {
        self.vp.partition.is_gpa_mapped(gpa, write)
    }
}

impl<'a, 'b, T: CpuIo> AccessCpuState for UhEmulationState<'a, 'b, T, HypervisorBacked> {
    fn commit(&mut self) {
        self.vp.commit()
    }
    fn x(&mut self, index: u8) -> u64 {
        self.vp.x(index)
    }
    fn update_x(&mut self, index: u8, data: u64) {
        self.vp.update_x(index, data)
    }
    fn q(&self, index: u8) -> u128 {
        self.vp.q(index)
    }
    fn update_q(&mut self, index: u8, data: u128) {
        self.vp.update_q(index, data)
    }
    fn d(&self, index: u8) -> u64 {
        self.vp.d(index)
    }
    fn update_d(&mut self, index: u8, data: u64) {
        self.vp.update_d(index, data)
    }
    fn h(&self, index: u8) -> u32 {
        self.vp.h(index)
    }
    fn update_h(&mut self, index: u8, data: u32) {
        self.vp.update_h(index, data)
    }
    fn s(&self, index: u8) -> u16 {
        self.vp.s(index)
    }
    fn update_s(&mut self, index: u8, data: u16) {
        self.vp.update_s(index, data)
    }
    fn b(&self, index: u8) -> u8 {
        self.vp.b(index)
    }
    fn update_b(&mut self, index: u8, data: u8) {
        self.vp.update_b(index, data)
    }
    fn sp(&mut self) -> u64 {
        self.vp.sp()
    }
    fn update_sp(&mut self, data: u64) {
        self.vp.update_sp(data)
    }
    fn fp(&mut self) -> u64 {
        self.vp.fp()
    }
    fn update_fp(&mut self, data: u64) {
        self.vp.update_fp(data)
    }
    fn lr(&mut self) -> u64 {
        self.vp.lr()
    }
    fn update_lr(&mut self, data: u64) {
        self.vp.update_lr(data)
    }
    fn pc(&mut self) -> u64 {
        self.vp.pc()
    }
    fn update_pc(&mut self, data: u64) {
        self.vp.update_pc(data)
    }
    fn cpsr(&mut self) -> Cpsr64 {
        self.vp.cpsr()
    }
}

impl<T: CpuIo> UhHypercallHandler<'_, '_, T, HypervisorBackedArm64> {
    const MSHV_DISPATCHER: hv1_hypercall::Dispatcher<Self> = hv1_hypercall::dispatcher!(
        Self,
        [
            hv1_hypercall::HvPostMessage,
            hv1_hypercall::HvSignalEvent,
            hv1_hypercall::HvRetargetDeviceInterrupt,
            hv1_hypercall::HvX64StartVirtualProcessor,
            hv1_hypercall::HvGetVpIndexFromApicId,
        ]
    );
}

impl<T: CpuIo> hv1_hypercall::RetargetDeviceInterrupt
    for UhHypercallHandler<'_, '_, T, HypervisorBackedArm64>
{
    fn retarget_interrupt(
        &mut self,
        device_id: u64,
        address: u64,
        data: u32,
        params: &hv1_hypercall::HvInterruptParameters<'_>,
    ) -> hvdef::HvResult<()> {
        self.retarget_virtual_interrupt(
            device_id,
            address,
            data,
            params.vector,
            params.multicast,
            params.target_processors,
        )
    }
}

trait ToVpRegisterName: 'static + Copy + std::fmt::Debug {
    fn to_vp_reg_name(self) -> VpRegisterName;
}

impl ToVpRegisterName for VpRegisterName {
    fn to_vp_reg_name(self) -> VpRegisterName {
        self
    }
}

impl UhVpStateAccess<'_, '_, HypervisorBackedArm64> {
    fn set_register_state<T, R: ToVpRegisterName, const N: usize>(
        &mut self,
        regs: &T,
    ) -> Result<(), vp_state::Error>
    where
        T: HvRegisterState<R, N>,
    {
        let names = regs.names().map(|r| r.to_vp_reg_name());
        let mut values = [HvRegisterValue::new_zeroed(); N];
        regs.get_values(values.iter_mut());
        self.vp
            .runner
            .set_vp_registers(names.iter().copied().zip(values))
            .map_err(vp_state::Error::SetRegisters)?;
        Ok(())
    }

    fn get_register_state<T, R: ToVpRegisterName, const N: usize>(
        &mut self,
    ) -> Result<T, vp_state::Error>
    where
        T: HvRegisterState<R, N>,
    {
        let mut regs = T::default();
        let names = regs.names().map(|r| r.to_vp_reg_name());
        let mut values = [HvRegisterValue::new_zeroed(); N];
        self.vp
            .runner
            .get_vp_registers(&names, &mut values)
            .map_err(vp_state::Error::GetRegisters)?;

        regs.set_values(values.into_iter());
        Ok(regs)
    }

    /// Get the system VP registers on the current VP.
    pub fn get_system_registers(&mut self) -> Result<vp::SystemRegisters, vp_state::Error> {
        self.get_register_state()
    }

    /// Set the system VP registers on the current VP.
    pub fn set_system_registers(
        &mut self,
        regs: &vp::SystemRegisters,
    ) -> Result<(), vp_state::Error> {
        self.set_register_state(regs)
    }
}

impl AccessVpState for UhVpStateAccess<'_, '_, HypervisorBackedArm64> {
    type Error = vp_state::Error;

    fn caps(&self) -> &virt::PartitionCapabilities {
        &self.vp.partition.caps
    }

    fn commit(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn registers(&mut self) -> Result<vp::Registers, Self::Error> {
        self.get_register_state()
    }

    fn set_registers(&mut self, value: &vp::Registers) -> Result<(), Self::Error> {
        self.set_register_state(value)
    }

    fn system_registers(&mut self) -> Result<vp::SystemRegisters, Self::Error> {
        self.get_system_registers()
    }

    fn set_system_registers(&mut self, value: &vp::SystemRegisters) -> Result<(), Self::Error> {
        self.set_system_registers(value)
    }
}

mod save_restore {
    use super::HypervisorBackedArm64;
    use super::UhProcessor;
    use anyhow::anyhow;
    use hvdef::HvArm64RegisterName;
    use hvdef::HvInternalActivityRegister;
    use virt::Processor;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    mod state {
        use mesh::payload::Protobuf;
        use vmcore::save_restore::SavedStateRoot;

        #[derive(Protobuf, SavedStateRoot)]
        #[mesh(package = "underhill.partition")]
        pub struct ProcessorSavedState {
            #[mesh(1)]
            pub(super) x: [u64; 31],
            #[mesh(2)]
            pub(super) q: [u128; 32],
            #[mesh(3)]
            pub(super) startup_suspend: bool,
        }
    }

    impl SaveRestore for UhProcessor<'_, HypervisorBackedArm64> {
        type SavedState = state::ProcessorSavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            // Ensure all async requests are reflected in the saved state.
            self.flush_async_requests()
                .map_err(|err| SaveError::Other(err.into()))?;

            let internal_activity = self
                .runner
                .get_vp_register(HvArm64RegisterName::InternalActivityState)
                .map_err(|err| {
                    SaveError::Other(anyhow!("unable to query startup suspend: {}", err))
                })?;
            let startup_suspend =
                HvInternalActivityRegister::from(internal_activity.as_u64()).startup_suspend();
            let state = state::ProcessorSavedState {
                x: self.runner.cpu_context().x,
                q: self.runner.cpu_context().q,
                startup_suspend,
            };

            Ok(state)
        }

        fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
            self.runner.cpu_context_mut().x = state.x;
            self.runner.cpu_context_mut().q = state.q;
            if state.startup_suspend {
                let reg = u64::from(HvInternalActivityRegister::new().with_startup_suspend(true));
                self.runner
                    .set_vp_registers([(HvArm64RegisterName::InternalActivityState, reg)])
                    .map_err(|err| {
                        RestoreError::Other(anyhow!(
                            "unable to set internal activity register: {}",
                            err
                        ))
                    })?;
            }

            Ok(())
        }
    }
}