## win64-syscall

Windows x64 indirect syscall lib for maldev with no_std supporting.

## Features

1. Directly set up registers and stack arguments, so there's no need to define function signatures.
2. Resolve SSN by sorting syscall stubs' address.
3. Perform indirect syscall via the first unhooked syscall stub.
4. Hash the syscall name at compile time.
5. Support #[no_std], for shellcode developing.

## Example

```rust
fn main() {
    let mut addr = 0 as *const core::ffi::c_void;
    let mut size = 4096_usize;

    let ntstatus = unsafe {
        win64_syscall::syscall!(NtAllocateVirtualMemory(
            usize::MAX,
            &mut addr,
            0_usize,
            &mut size,
            0x1000_u32 | 0x2000,
            0x40_u32,
        ))
    };

    println!("ntstatus: 0x{:x}\nRWX page: {:?}", ntstatus, addr);
}
```

Macro expanded:

```rust
fn main() {
    let mut addr = 0 as *const core::ffi::c_void;
    let mut size = 4096_usize;

    let ntstatus = unsafe {
        if ::win64_syscall::SSN_MAP.is_empty() {
            ::win64_syscall::SSN_MAP = ::win64_syscall::init_ssns();
        }

        let mut ssn = ::win64_syscall::SSN_MAP[::win64_syscall::SSN_MAP.binary_search_by(|probe| { 
            probe.0.cmp(&0xc0fc337ad2eff571_u64) 
        }).unwrap()].1;

        core::arch::asm!(
            "push {0:r}",
            "push {1:r}",
            "sub rsp, 0x20",
            "call rcx",
            "add rsp, r12",

            in(reg) 0x40_u32,
            in(reg) 0x1000_u32 | 0x2000,
            inlateout("eax") ssn => ssn,
            inout("r10") usize::MAX => _,
            inout("rdx") &mut addr => _,
            inout("r8") 0_usize => _,
            inout("r9") &mut size => _,
            in("r12") 0x20 + (1_usize + (1_usize + 0_usize)) * 8,
            inout("rcx") ::win64_syscall::SYSCALL_INSTRUCTION_ADDR => _,
            out("r11") _
        );
        ssn as i32
    };

    println!("ntstatus: 0x{:x}\nRWX page: {:?}", ntstatus, addr);
}
```