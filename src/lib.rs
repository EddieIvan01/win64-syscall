#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::ffi::{c_void, CStr};
use core::mem::offset_of;
use core::ptr;
pub use win64_syscall_macros::compile_time_hash;
use zero_xxhash::hash64;

use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows_sys::Win32::System::Threading::PEB;
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("only supports x64 syscall");

pub static mut SSN_MAP: Vec<(u64, u32)> = Vec::new();

pub static mut SYSCALL_INSTRUCTION_ADDR: usize = 0;

const SEED: u64 = 0x1f2f3f4f;

const SYSCALL_INSTRUCTION_OFFSET: isize = 0x12;

// 0f05 syscall
// c3   ret
const SYSCALL_INSTRUCTION: [u8; 3] = [0x0f, 0x05, 0xc3];

unsafe fn get_ntdll_base() -> *mut c_void {
    let mut peb: *const PEB;
    asm!("
        mov {:r}, gs:[60h]",
        out(reg) peb,
    );

    let ldr = &*(*peb).Ldr;
    let entry = (*ldr.InMemoryOrderModuleList.Flink)
        .Flink
        .cast::<u8>()
        .offset(-(offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as isize))
        .cast::<LDR_DATA_TABLE_ENTRY>();

    (*entry).DllBase
}

unsafe fn get_eat<'a>(base: *mut c_void) -> &'a IMAGE_EXPORT_DIRECTORY {
    let opt_hdr = &(*(base
        .offset((*base.cast::<IMAGE_DOS_HEADER>()).e_lfanew as isize)
        .cast::<IMAGE_NT_HEADERS64>()))
    .OptionalHeader;

    &*base
        .offset(
            opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as isize,
        )
        .cast::<IMAGE_EXPORT_DIRECTORY>()
}

pub unsafe fn init_ssns() -> Vec<(u64, u32)> {
    let base = get_ntdll_base();
    let eat = get_eat(get_ntdll_base());

    let name_tbl_ptr = base.offset(eat.AddressOfNames as isize) as *const u32;
    let ord_tbl = base.offset(eat.AddressOfNameOrdinals as isize) as *const u16;
    let addr_tbl = base.offset(eat.AddressOfFunctions as isize) as *const u32;

    let mut syscall_addrs = Vec::new();
    let mut syscall_instruction_addr_init = false;

    let mut nt_bytes = [0_u8; 64];
    nt_bytes[0] = b'N';
    nt_bytes[1] = b't';

    for i in 0..eat.NumberOfNames as isize {
        let s_ptr = base.offset(name_tbl_ptr.offset(i).read_unaligned() as isize);
        if s_ptr.cast::<[u8; 2]>().read() != [b'Z', b'w'] {
            continue;
        }

        let fname = CStr::from_ptr(s_ptr.cast());
        let addr = base.offset(
            addr_tbl
                .offset(ord_tbl.offset(i).read_unaligned() as isize)
                .read_unaligned() as isize,
        );

        if !syscall_instruction_addr_init
            && addr
                .offset(SYSCALL_INSTRUCTION_OFFSET)
                .cast::<[u8; 3]>()
                .read()
                == SYSCALL_INSTRUCTION
        {
            syscall_instruction_addr_init = true;
            SYSCALL_INSTRUCTION_ADDR = addr.offset(0x12) as usize;
        }

        let zw_bytes = fname.to_bytes();

        ptr::copy_nonoverlapping(
            zw_bytes.as_ptr().offset(2),
            nt_bytes.as_mut_ptr().offset(2),
            zw_bytes.len() - 2,
        );

        syscall_addrs.push((
            hash64::xxhash64(zw_bytes, SEED),
            hash64::xxhash64(&nt_bytes[..zw_bytes.len()], SEED),
            addr,
        ));
    }

    syscall_addrs.sort_by(|a, b| a.2.cmp(&b.2));

    let mut ret = syscall_addrs
        .into_iter()
        .enumerate()
        .flat_map(|(ssn, (zw_hash, nt_hash, _))| {
            [(zw_hash, ssn as u32), (nt_hash, ssn as u32)].into_iter()
        })
        .collect::<Vec<_>>();

    ret.sort_by(|a, b| a.0.cmp(&b.0));
    ret
}

#[macro_export]
macro_rules! syscall {
    (@count) => (0_usize);
    (@count $_:tt $($s:tt)*) => (1_usize + $crate::syscall!(@count $($s)*));

    (@null $_:tt) => ("");

    (@prepare_bind_regs $ssn:tt) => ($crate::syscall!(@do_syscall $ssn 0 0 0 0));
    (@prepare_bind_regs $ssn:tt $a1:tt) => ($crate::syscall!(@do_syscall $ssn $a1 0 0 0));
    (@prepare_bind_regs $ssn:tt $a1:tt $a2:tt) => ($crate::syscall!(@do_syscall $ssn $a1 $a2 0 0));
    (@prepare_bind_regs $ssn:tt $a1:tt $a2:tt $a3:tt) => ($crate::syscall!(@do_syscall $ssn $a1 $a2 $a3 0));
    (@prepare_bind_regs $ssn:tt $a1:tt $a2:tt $a3:tt $a4:tt) => ($crate::syscall!(@do_syscall $ssn $a1 $a2 $a3 $a4));
    (@prepare_bind_regs $ssn:tt $a1:tt $a2:tt $a3:tt $a4:tt $($stacks:tt)*) => {
        $crate::syscall!(@prepare_bind_stack $ssn $a1 $a2 $a3 $a4 [$($stacks)*])
    };

    (@prepare_bind_stack $ssn:tt $a1:tt $a2:tt $a3:tt $a4:tt [$head:tt $($tail:tt)*] $($reversed:tt)*) => {
        $crate::syscall!(@prepare_bind_stack $ssn $a1 $a2 $a3 $a4 [$($tail)*] $head $($reversed)*);
    };
    (@prepare_bind_stack $ssn:tt $a1:tt $a2:tt $a3:tt $a4:tt [] $($reversed:tt)*) => {
        $crate::syscall!(@do_syscall $ssn $a1 $a2 $a3 $a4 $($reversed)*);
    };

    (@do_syscall $ssn:tt $a1:tt $a2:tt $a3:tt $a4:tt $($stacks:tt)*) => {
        core::arch::asm!(
            $("push {:r}", $crate::syscall!(@null $stacks),)*
            // shadow store
            "sub rsp, 0x20",
            "call rcx",
            "add rsp, r12",
            $(in(reg) $stacks,)*
            inlateout("eax") $ssn => $ssn,
            inout("r10") $a1 => _,
            inout("rdx") $a2 => _,
            inout("r8") $a3 => _,
            inout("r9") $a4 => _,
            in("r12") 0x20 + $crate::syscall!(@count $($stacks)*) * 8,

            // Any registers not specified as outputs must have the same
            // value upon exiting the asm block as they had on entry,
            // otherwise behavior is undefined.
            //
            // `syscall` instruction clobber rcx and r11
            // rcx <- rip, r11 <- rflags
            inout("rcx") $crate::SYSCALL_INSTRUCTION_ADDR => _,
            out("r11") _,
        );
    };

    ($func:ident($($args:expr$(,)?)*)) => {{
        if $crate::SSN_MAP.is_empty() {
            $crate::SSN_MAP = $crate::init_ssns();
        }

        let mut ssn = $crate::SSN_MAP[$crate::SSN_MAP.binary_search_by(|probe| {
            probe.0.cmp(&$crate::compile_time_hash!($func))
        }).unwrap()].1;
        $crate::syscall!(@prepare_bind_regs ssn $($args)*);

        ssn as i32
    }};
}
