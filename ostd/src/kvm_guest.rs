use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    intrinsics::atomic_cxchg_relaxed_relaxed,
    str,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use bitflags::bitflags;
use ostd_pod::Pod;
use x86::{
    cpuid::{cpuid, native_cpuid::cpuid_count},
    msr::wrmsr,
};
use xarray::ItemEntry;

use crate::{
    cpu_local, early_println,
    mm::{kspace::vaddr_to_paddr, paddr_to_vaddr, Vaddr},
};

// cpu_local! {
//     static KVM_APIC_EOI: AtomicU64 = AtomicU64::new(0);
// }

static KVM_APIC_EOI: AtomicU32 = AtomicU32::new(0);

const KVM_MSR_ENABLED: u64 = 1;

const MSR_KVM_EOI_EN: u32 = 0x4b564d04;
const MSR_KVM_POLL_CONTROL: u32 = 0x4b564d05;

pub unsafe fn kvm_guest_cpu_init() {
    if !is_kvm_guest() {
        early_println!("not kvm guest");
        return;
    }

    get_kvm_features();

    // let kvm_apic_eoi_va = unsafe { KVM_APIC_EOI.as_ptr() } as Vaddr;
    let kvm_apic_eoi_va = KVM_APIC_EOI.as_ptr() as Vaddr;
    early_println!("va = 0x{:x}", kvm_apic_eoi_va);
    let pa = kvm_apic_eoi_va - 0xffff_ffff_8000_0000;
    // let pa = vaddr_to_paddr(kvm_apic_eoi_va);

    early_println!("pa = 0x{:x}", pa);
    assert!(pa % 4 == 0);

    wrmsr(MSR_KVM_EOI_EN, pa as u64 | KVM_MSR_ENABLED);
}

pub unsafe fn kvm_guest_apic_eoi_write() -> bool {
    let old_value = KVM_APIC_EOI.load(Ordering::Relaxed);
    if old_value != 0 {
        early_println!("old_value = {}", KVM_APIC_EOI.load(Ordering::Relaxed));
    }
    KVM_APIC_EOI
        .compare_exchange(1, 0, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    // (*KVM_APIC_EOI.as_ptr()).compare_exchange(1, 0, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

pub unsafe fn is_kvm_guest() -> bool {
    const KVM_CPUID_SIGNATURE: u32 = 0x40000000;
    let cpu_id = cpuid!(KVM_CPUID_SIGNATURE);
    let Ok(s1) = str::from_utf8(cpu_id.ebx.as_bytes()) else {
        return false;
    };

    let Ok(s2) = str::from_utf8(cpu_id.ecx.as_bytes()) else {
        return false;
    };

    let Ok(s3) = str::from_utf8(cpu_id.edx.as_bytes()) else {
        return false;
    };

    early_println!("s1 = [{}],  s2 = [{}], s3 = [{}]", s1, s2, s3);
    // KVM signature: "KVMKVMKVM\0\0\0"
    s1 == "KVMK" && s2 == "VMKV" && s3 == "M\0\0\0"
}

pub unsafe fn get_kvm_features() -> KvmCpuidFeatures {
    const KVM_CPUID_FEATURES: u32 = 0x40000001;
    let cpu_id = cpuid!(KVM_CPUID_FEATURES);
    early_println!("0b{:b}", cpu_id.eax);
    early_println!("0b{:b}", cpu_id.ebx);
    let features = KvmCpuidFeatures::from_bits_truncate(cpu_id.eax);
    early_println!("features = {:?}", features);
    features
}

bitflags! {
    struct KvmCpuidFeatures: u32 {
        const KVM_FEATURE_CLOCKSOURCE = 1 << 0;
        const KVM_FEATURE_NOP_IO_DELAY	= 1 << 1;
        const KVM_FEATURE_MMU_OP	=	1 << 2;
        const KVM_FEATURE_CLOCKSOURCE2    =    1 << 3;
        const KVM_FEATURE_ASYNC_PF	= 1 <<	4;
        const KVM_FEATURE_STEAL_TIME	=	1<<5;
        const KVM_FEATURE_PV_EOI		= 1<<6;
        const KVM_FEATURE_PV_UNHALT		= 1<<7;
        const KVM_FEATURE_PV_TLB_FLUSH	= 1 <<9;
        const KVM_FEATURE_ASYNC_PF_VMEXIT	= 1<<10;
        const KVM_FEATURE_PV_SEND_IPI	= 1<<11;
        const KVM_FEATURE_POLL_CONTROL	=1 <<12;
        const KVM_FEATURE_PV_SCHED_YIELD	=1 <<13;
        const KVM_FEATURE_ASYNC_PF_INT	=1 <<14;
        const KVM_FEATURE_MSI_EXT_DEST_ID	=1 << 15;
        const KVM_FEATURE_HC_MAP_GPA_RANGE	=1 << 16;
        const KVM_FEATURE_MIGRATION_CONTROL	=1 <<17;
    }
}
