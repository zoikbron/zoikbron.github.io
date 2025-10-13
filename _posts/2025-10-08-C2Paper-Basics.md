---
title: Building a C2 Framework - Basics
date: 2025-10-08 12:00:00 -500
categories: [malware development,red team,offensive tooling]
tags: [Rust,C2,pentesting,career,tips,tricks]
image:
  path: /assets/img/posts/c2/CoverC2.png
  alt: C2 Logo
---
## What I needed to start this project

> I recommend that anyone following this already has some level of experience with C and Windows Internals. While I’ll explain many of the concepts as we go, it’s important to have a general understanding of what we’re dealing with and why. I won’t go too deep into low-level specifics, but I’ll provide enough context to help you connect the dots.
{: .prompt-tip }

### Setting Up Rust

To begin, we’ll need to install Rust and its toolchain. I’ll be using the nightly version since it provides access to experimental features such as asm!.

You can find installation instructions on the official Rust pages:

[Rustup Installation Guide](https://forge.rust-lang.org/infra/other-installation-methods.html)

[Rust Main Page](https://rust-lang.org/tools/install)

For this setup, I’m using Windows — since we’ll be working with executables, the Windows API, and system-level interactions, it’s much easier to compile, test, and debug directly on this platform.

Once you’ve installed the rustup manager, proceed to install the Rust nightly toolchain.

```powershell
C:\Program Files\Microsoft Visual Studio\2022\Community>rustup toolchain install nightly
info: syncing channel updates for 'nightly-x86_64-pc-windows-msvc'
info: latest update on 2025-10-09, rust version 1.92.0-nightly (b6f0945e4 2025-10-08)
info: downloading component 'rust-src'
info: downloading component 'cargo'
info: downloading component 'clippy'
info: downloading component 'rust-docs'
 20.4 MiB /  20.4 MiB (100 %)   9.7 MiB/s in  2s
info: downloading component 'rust-std'
 20.8 MiB /  20.8 MiB (100 %)   9.8 MiB/s in  2s
info: downloading component 'rustc'
 68.3 MiB /  68.3 MiB (100 %)  12.3 MiB/s in  6s
info: downloading component 'rustfmt'
info: removing previous version of component 'rust-src'
info: removing previous version of component 'cargo'
info: removing previous version of component 'clippy'
info: removing previous version of component 'rust-docs'
info: removing previous version of component 'rust-std'
info: removing previous version of component 'rustc'
info: removing previous version of component 'rustfmt'
info: installing component 'rust-src'
info: installing component 'cargo'
info: installing component 'clippy'
info: installing component 'rust-docs'
 20.4 MiB /  20.4 MiB (100 %)   2.9 MiB/s in  7s
info: installing component 'rust-std'
 20.8 MiB /  20.8 MiB (100 %)  15.1 MiB/s in  1s
info: installing component 'rustc'
 68.3 MiB /  68.3 MiB (100 %)  15.8 MiB/s in  4s
info: installing component 'rustfmt'

  nightly-x86_64-pc-windows-msvc updated - rustc 1.92.0-nightly (b6f0945e4 2025-10-08) (from rustc 1.88.0-nightly (b45dd71d1 2025-04-30))

info: checking for self-update
info: downloading self-update
```
Later on, we’ll need to test ```COFF files``` / ```Beacon Object Files```, so it’s necessary to have a C compiler and the Windows SDK for access to the required headers.

The most straightforward way especially if you’re working on Windows is to install Visual Studio, which provides everything you need, including the MSVC compiler, Windows SDK, and proper build tools for compiling and testing native code.
![MSVC](/assets/img/posts/c2/basics/MSVC.png)

## Let's get into it

The first step was to understand how to translate or use Windows structures in Rust.

There are generally two approaches to this:

- Using the [windows](https://microsoft.github.io/windows-docs-rs) crate — this provides bindings for Windows APIs and structures. However, in some cases, this approach might not be ideal, as it introduces linkages and imports that can be easily tracked during execution.

- Manually defining structures — this gives full control over what gets included. Often, the predefined structures in the Windows crate are incomplete, and you might need access to “reserved” fields or undocumented members.

When that happens, you can rely on unofficial documentation to find the full definitions, or use tools like WinDbg to inspect memory layouts, determine offsets, and reconstruct the structures you need directly in Rust.

Let's begin with this conversion table from windows primitives to rust primitives

| Windows primitives| Rust primitives |
|---|---|
|CHAR| u8 or i8 |
|UCHAR|u8|
|SHORT|i16|
|USHORT| u16|
|DWORD| u32|
|DWORDLONG|u64|
|DWORD64|u64|
|DWORD32| u32|
|WORD| u16|
|LONG| i32|
|ULONG| u32|
|PVOID HANDLE|*const c_void *mut c_void |
|LPCSTR| *const u8 or i8 |
|LPWSTR| *const u8..u16..i8..i16 |
{: .display}
>These are not all the primitives but pretty much all we need for structure convertions.

I'll wanted to start directly with Server Side things, but there is some basics that I will explain first related to the client/implant side code.
### Process Enviroment Block
Let's use this concept to explain Malware Development basics and the same time some tips & tricks for developing these stuff in Rust. The ```Process Environment Block``` (PEB) is a user-mode structure that contains crucial information about a running process.
It holds details such as:

- Loaded modules (DLLs)

- Command-line arguments and environment variables

- Parent process information

- Process heap and subsystem data

With access to the PEB, we can enumerate loaded modules, inspect or modify process parameters, and even manipulate internal state for advanced use cases like injection or evasion.

![PEB](/assets/img/posts/c2/basics/PEB.png)

![Process Info](/assets/img/posts/c2/basics/Process.png)

![Modules](/assets/img/posts/c2/basics/Modules.png)

Given how central this structure is, it makes a great example for hands-on exploration.
Let’s start by checking the official documentation for the PEB structure and then look at how we can represent and use the struct in Rust.

[MSDN winternl.h](https://learn.microsoft.com/es-es/windows/win32/api/winternl/ns-winternl-peb)

##### #[repr(C)]
```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```
A translation of this can look like:

```rust
#[repr(C)]
pub struct PEB {
  pub Reserved1: [u8; 2],
  pub BeingDebugged: u8,
  pub Reserved2: u8,
  pub Reserved3: *const c_void,
  pub ImageBaseAddress: *const c_void,
  pub Ldr: *const PEB_LDR_DATA,
  pub ProcessParameters: RTL_USER_PROCESS_PARAMETERS,
  pub Reserved4: [*const c_void; 3],
  pub AtlThunkSListPtr: *const c_void,
  pub Reserved5: *const c_void,
  pub Reserved6: u32,
  pub Reserved7: *const c_void,
  pub Reserved8: u32,
  pub AtlThunkSListPtr32: u32,
  pub Reserved9: [*const c_void; 45],
  pub Reserved10: [u8; 96],
  pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
  pub Reserved11: [u8; 128],
  pub Reserved12: *const c_void,
  pub SessionId: u32
}
```
> Notice how first you need to make sure the struct will be represented as c struct with #[repr(c)]
{: .prompt-info}

##### #[repr(C,packed)]
By default, Rust may insert padding bytes between fields in a struct to align them efficiently for the CPU. For example, if you have a u8 followed by a u32, Rust will add 3 bytes of padding between them so that the u32 starts on a 4-byte boundary.
However, when you are working with binary layouts that must match exactly what’s in memory (like C structs, Windows PE structures, or file headers), any padding ruins the layout.

```#[repr(packed)]``` tells the compiler:

>“Do not insert any padding, pack the fields exactly in the order and size I define.”

Is very useful when dealing with sequetials structs in PE formats like the IMAGE SYMBOL table

Here an example:

[COFF Symbol Table](https://wiki.osdev.org/COFF#Symbol_Table)
```c
struct IMAGE_SYMBOL
{
	char		n_name[8];	/* Symbol Name */
	long		n_value;	/* Value of Symbol */
	short		n_scnum;	/* Section Number */
	unsigned short	n_type;		/* Symbol Type */
	char		n_sclass;	/* Storage Class */
	char		n_numaux;	/* Auxiliary Count */
}
```

```rust
#[repr(C,packed)]
pub struct IMAGE_SYMBOL
{
pub	n_name: NameSymbol,	/* Symbol Name */
pub	n_value: u32,	/* Value of Symbol */
pub	n_scnum:  i16,	/* Section Number */
pub	n_type: u16,		/* Symbol Type */
pub	n_sclass:	u8, /* Storage Class */
pub	n_numaux:	u8, /* Auxiliary Count */
}

pub union NameSymbol{
   pub s_name: [u8; 8],
   pub offsets: Offsets

}
```

With packed structures we may encounter unaligned pointers, rust gave us the read,read_unaligned functions for dereferencing and reading pointers & write, write_unaligned for dereferencing and writing pointers.

In some occassions we will need to use ```read_unaligned``` and ```write_unaligned``` due to packed structs or relocation implementations.

```rust
let addend = core::ptr::read_unaligned(reloc_location) as i32;
let reloc_value = (symbol_value as isize - (reloc_location as isize + 4) + addend as isize ) as i32;
core::ptr::write_unaligned(reloc_location, reloc_value);
```
### Rust assembly
For accessing the PEB information we need to read certain register, ```gs[0x60]``` in x64 and ```fs[0x30]``` in x86.
```rust
fn __readgsqword(offset: u64) -> u64{
    let out: u64;
    unsafe {asm!(
        "mov {}, gs:[{}]",
        out(reg) out,
        in(reg) offset,
    );
}
    return out;
   
}
```
This gives us a pointer to the PEB structure, which provides access to internal process information.
With this, we can implement our own versions of functions like ```GetModuleHandle``` and ```GetProcAddress```.

GetModuleHandle works by traversing the ```PEB_LDR_DATA``` and its linked list of ```LDR_DATA_TABLE_ENTRY``` structures, where information about all loaded modules (DLLs) is stored.
```rust
let MyPeb: *const PEB = __readgsqword(0x60) as *const PEB;
let pLDR: &PEB_LDR_DATA = unsafe{ &*(*MyPeb).Ldr};

let List: &LIST_ENTRY = &(*pLDR).InMemoryOrderModuleList;

let pFirst: &LIST_ENTRY = unsafe {&*(*List).Flink};

let mut iterator: &LIST_ENTRY = pFirst;
let lsize: usize = 16; //LIST_ENTRY size
while iterator != List{

let pEntry: *const LDR_DATA_TABLE_ENTRY = ((iterator as *const LIST_ENTRY) as usize - lsize) as *const LDR_DATA_TABLE_ENTRY;

unsafe {  
let toutf8: String = match (*pEntry).BaseDllName.to_string(){
        Some(utf8) => utf8,
        None => return None
};
if toutf8.to_uppercase() ==  ModuleName.unwrap_or_default().to_uppercase(){
  let current_module_addr: (*pEntry).DllBase as usize;
}

}
iterator = unsafe{&*(*iterator).Flink};
}
```
By walking this list, we can easily locate the base address of any loaded module. Once we have that, we can decide what to do next, such as caching module addresses for faster lookups or dynamically loading missing modules with LoadLibrary when needed. This is pretty much a GetModuleHandle implementation.

This approach provides a deeper understanding of how Windows internally manages process modules and can be especially useful in low-level development, malware analysis, or implementing stealthier alternatives to the standard API.

### PE Format
Here some great documentation about PE Format:

- [MSDN Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

- [Corkami repository](https://github.com/corkami/pics/tree/master/binary)

Let's start dissecting the PE 64-bit Format

![Corkami PE 101 pic](/assets/img/posts/c2/basics/pe101-64.png)

#### PE Layout
A Portable Executable (PE) image is conceptually divided into two parts:

1. Headers — metadata used by the Windows loader to map and initialize the image correctly in memory. Headers include the ```IMAGE_DOS_HEADER```, ```IMAGE_NT_HEADERS``` (FileHeader + OptionalHeader), and the section table. The Optional Header also contains the DataDirectory array (exports, imports, relocations, resources, etc.).

2. Sections — the actual code and data regions (e.g., ```.text```, ```.rdata```, ```.data```, ```.rsrc```) that the loader places into memory according to the information in the headers.

Understanding these two parts is essential when building custom loaders: the headers tell you how Windows expects the image to be arranged, and the sections contain the bytes that must be copied, relocated, and protected accordingly.

#### Why this matters for loaders

When implementing an in-memory loader (or any manual loader), you must:

- Parse the PE headers to determine image base, section layout, and required protections.

- Allocate memory for the image and copy each section to the correct virtual address (or apply relocations if loading at a different base).

- Apply the appropriate memory protections (read, write, execute) per section.

- Resolve imports (walk the Import Directory and locate target functions) or implement lazy/alternative resolution.

- Locate and parse the Export Directory (from the ```DataDirectory[EXPORT]```) to enumerate exported functions and their RVAs.

By following the same semantic steps as the native Windows loader, your in-memory loader can execute a module without writing it to disk.


|Structure / Field| What to read / compute| Result / Purpose|
|---|:---:|:---:|
|DOS_HEADER->e_magic| "MZ"| DOS_HEADER_SIGNATURE|
|DOS_HEADER->e_lfanew| Base + e_lfanew| IMAGE_NT_HEADER|
|NT_HEADER->Signature| "PE"| NT_HEADER_SIGNATURE |
|IMAGE_NT_HEADER->Optional_Header| Get a reference (&)| IMAGE_OPTIONAL_HEADER |
|OptionalHeader->DataDirectory|  Base + DataDirectory[0].VirtualAddress | EXPORT_DIRECTORY|
{: .display}

##### DataDirectory Entries

| Value | Name | Meaning |
|:------:|------|---------|
| 0 | IMAGE_DIRECTORY_ENTRY_EXPORT | Export directory |
| 1 | IMAGE_DIRECTORY_ENTRY_IMPORT | Import directory |
| 2 | IMAGE_DIRECTORY_ENTRY_RESOURCE | Resource directory |
| 3 | IMAGE_DIRECTORY_ENTRY_EXCEPTION | Exception directory |
| 4 | IMAGE_DIRECTORY_ENTRY_SECURITY | Security directory |
| 5 | IMAGE_DIRECTORY_ENTRY_BASERELOC | Base relocation table |
| 6 | IMAGE_DIRECTORY_ENTRY_DEBUG | Debug directory |
| 7 | IMAGE_DIRECTORY_ENTRY_ARCHITECTURE | Architecture-specific data |
| 8 | IMAGE_DIRECTORY_ENTRY_GLOBALPTR | The relative virtual address of global pointer |
| 9 | IMAGE_DIRECTORY_ENTRY_TLS | Thread local storage directory |
| 10 | IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG | Load configuration directory |
| 11 | IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT | Bound import directory |
| 12 | IMAGE_DIRECTORY_ENTRY_IAT | Import address table |
| 13 | IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT | Delay import table |
| 14 | IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR | COM descriptor table |
{: .display}

Using tools like ```PE-Bear``` we can see it more visually

![DataDirectory](/assets/img/posts/c2/basics/PE-BEAR-DAA.png)

Inside the export directories we have a few fields for resolving functions locations.

```rust
pName = unsafe { RVA(address,ppe.export_directory.as_ref().AddressOfNames as usize) as *const u32};
pOrdinals = unsafe { RVA(address , ppe.export_directory.as_ref().AddressOfNameOrdinals as usize) as *const u16};
pFuncs = unsafe { RVA(address , ppe.export_directory.as_ref().AddressOfFunctions as usize) as *const u32 };
```

#### Resolving Exported Functions by Name

When parsing a module’s Export Directory, there are two main approaches to resolve exported functions:

1. By name — matching the function’s string identifier.

2. By ordinal — directly using its numerical position (faster but less readable).

In this example, we’ll focus on resolving exports by name, as it’s the most common and human-readable method.

##### Understanding the relationship between arrays

The ```IMAGE_EXPORT_DIRECTORY``` structure defines three key arrays:

|Field|	Type	|Description|
|---|---|---|
|AddressOfFunctions|	*const u32	|Array of RVAs to exported functions.|
|AddressOfNames|	*const u32	|Array of RVAs to ASCII strings containing exported function names.|
|AddressOfNameOrdinals|	*const u16	|Array of indexes (ordinals) that map each name to the correct function RVA.|

These arrays are correlated by index, meaning that the same index used in ```AddressOfNames``` and ```AddressOfNameOrdinals``` refers to the same export entry.

```func_address = module_base + pFuncs[ordinal_index];```

This manual resolution process effectively replicates what ```GetProcAddress``` does internally, allowing you to locate function addresses directly from the module’s memory image, a key technique when implementing custom or reflective loaders.

So implementing this could something like this:

```rust
for n in 0..number_of_names{
            let funcname = core::ffi::CStr::from_ptr((address + *pName.add(n as usize) as usize) as *const i8);
            let str = funcname.to_str().unwrap();
            if str == ProcName {
                
            let funcaddr : *const c_void = (address + *pFuncs.add(*pOrdinals.add(n as usize) as usize) as usize) as *const c_void;
                let funcaddr = match get_forwarder(address ,ddirectory_va,ddirectory_size,funcaddr){
                    Ok(p)=>p,
                    Err(_)=>funcaddr
                };
            }
          }
```
Sometimes, while parsing the export table, you’ll encounter forwarder strings. These indicate that the exported function isn’t actually implemented in the current module, but instead forwarded to another one.
In such cases, the function name will point to a string in the format:

```
MODULE_NAME.FUNCTION_NAME (NTDLL.RtlAllocateHeap)
```
This means that to resolve the function, you must locate the target module (e.g., ```ntdll.dll```) and then retrieve the address of the specified function from it.

However, we won’t go into the details of forwarder resolution here, as it follows a similar process to the one we’ve already covered.

Well this all for this post, here is cover everything we need at first to understading later explanations especially when creating our own ```COFF Loader```.


#### Conclusions

We covered several topics related to Windows internals and loader mechanisms—essential foundations for understanding how to interact with pointers, Windows primitives, and C-style APIs in Rust. These concepts are crucial for anyone working close to the system level, especially in areas such as exploit development, malware analysis, or custom tooling.

We will revisit many of these concepts later, particularly when diving into Reflective Loaders and COFF Loaders, where this knowledge will become directly applicable.

Key Takeaways

- Rust provides a safer alternative to traditional C/C++ for systems programming while still offering full control over memory and low-level constructs.

- Understanding how Windows manages memory, handles, and native APIs is critical for developing loaders, injectors, or any form of advanced post-exploitation tooling.

- Interfacing Rust with Windows APIs often requires unsafe blocks, but doing so responsibly allows precise control without sacrificing reliability.

- Concepts like FFI (Foreign Function Interface), pointer manipulation, and structure alignment are vital when bridging Rust code with C-based Windows APIs.

- A solid grasp of these fundamentals enables researchers to write, efficient, and maintainable tools for red teaming, reverse engineering, and system-level automation.













