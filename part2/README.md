# Part-2: Guarding GOT segment against AW attempt (40 pt)

## Problem Statement

In regular execution environment, without having PINTOOL layer in between, a process would first make a call to \_dl_runtime_resolve\*() from glibc to implement lazy loading. However, as you run your target process inside the PINTOOL context, PINTOOL framework implements its own custom loader using dynamic linking library to avoid conflict with its own library. It is obvious the PINTOOL framework and its target process both need basic libraries, including glibc and can’t be shared one another. Consider the call tracek (backtrace) from regular exuection and PINTOOL execution.

- Regular execution (capture by GDB)

```
 ► f 0   0x7ffff7deef11 _dl_runtime_resolve_xsavec+1
   f 1         0x400986 read_func+18
   f 2         0x400b08 input_func+14
   f 3         0x400b48 main+51
   f 4   0x7ffff7a2d840 __libc_start_main+240
```

- PINTOOL execution (capture by PIN_Backtrace())

```
0x7f3671e6eb47 : _dl_rtld_di_serinfo
0x7f3671e76f8a : _dl_find_dso_for_object
0x4009d4 : read_func
0x400b08 : input_func
0x400b48 : main
0x7f365e497840 : __libc_start_main
0x4007e9 : _start
```

You can consider \_dl_rtld_di_serinfo() as a legitimate access to the GOT entry to be white-listed. Therefore any overwrite attempts outside the \_dl_rtld_di_serinfo() function context we consider to be a suspicious event to raise the alarm and stop the execution of the process. To implement the solution, you must instrument memory write instructions and check their destinations at runtime. In case the memory address falls inside the range of GOT section, you need to trace back function call history and confirm the instruction is called from a legitimate function.

Your pintool should detect 0-aw0-64 and 1-aw-64 to its minimum while it can run regular program (e.g., /bin/\*) with no complaints.

## Compilation and Execution

- Run the script `run.sh` for compiling the `script.cpp`. Script also runs the compiled executable on /bin/ls.

  ```
  sh run.sh
  ```

  Sample output is as below:

  ```
  make: 'obj-intel64/script.so' is up to date.
  6-aw0-64  7-aw1-64  7_exploit.py  exploit.py  Makefile	obj-intel64  run.sh  script.cpp  script.out  Writing
  Range: 0x21fc50 - 0x21ffc0
  ```

- Now run the python exploit. To run it use `sh run2.sh`

  - Example:

    ```
    sh run2.sh
    ```

    - Output:

```
[*] '/home/vxd240001/home/unit3-2/part2/6-aw0-64'
  Arch:     amd64-64-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  [+] Starting local process '/usr/local/pin/pin': pid 2643
  [*] Switching to interactive mode

  [*] Got EOF while reading in interactive
  $ ls
  [*] Process '/usr/local/pin/pin' stopped with exit code 100 (pid 2643)
  [*] Got EOF while sending in interactive
  Range: 0x602018 - 0x602068
  [ALERT] Suspicious GOT overwrite attempt at 602028
```

## Write-up

- To get the GOT Range we can reuse the code in part 1.

```
// GOT range: You will need to initialize these with actual values
ADDRINT GOT_Start = 0x0;
ADDRINT GOT_End = 0x0;

// Function to find GOT addresses using ELFIO
bool findGOTAddresses(const std::string &elfFile) {
    ELFIO::elfio reader;

    // Load ELF data
    if (!reader.load(elfFile)) {
        OutFile << "Can't find or process ELF file " << elfFile << std::endl;
        return false;
    }

    // Locate .rela.plt section
    ELFIO::section* rela_plt = nullptr;
    for (const auto& sec : reader.sections) {
        if (sec->get_name() == ".rela.plt") {
            rela_plt = sec.get();
            break;
        }
    }

    if (rela_plt == nullptr) {
        OutFile << "Could not find .rela.plt section." << std::endl;
        return false;
    }

    // Create a relocation section accessor
    ELFIO::relocation_section_accessor reloc(reader, rela_plt);

    // Variables to hold relocation information
    ELFIO::Elf64_Addr offset = 0;
    ELFIO::Elf64_Addr symbol_value;
    std::string symbol_name;
    ELFIO::Elf_Word type;
    ELFIO::Elf_Sxword addend;

    // Calculate GOT range
    ELFIO::Elf64_Addr got_min = std::numeric_limits<ELFIO::Elf64_Addr>::max();
    ELFIO::Elf64_Addr got_max = 0;

    for (unsigned int i = 0; i < reloc.get_entries_num(); ++i) {
        reloc.get_entry(i, offset, symbol_value, symbol_name, type, addend, addend);
        got_min = std::min(got_min, offset);
        got_max = std::max(got_max, offset);
    }

    GOT_Start = got_min;
    GOT_End = got_max;

    return true;
}
```

- After calculating GOT, we traverse the instructions which checks if the instruction is writing memory or not and if it is it calls `CheckMemoryWrite` function.

```
VOID Instruction(INS ins, VOID* v) {
    UINT32 operandCount = INS_MemoryOperandCount(ins);

    for (UINT32 x = 0; x < operandCount; x++) {
        if (INS_MemoryOperandIsWritten(ins,x)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckMemoryWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, x, IARG_END);
        }
    }

    return;
}
```

- Using `CheckMemoryWrite`, we can figure out whether the program is writing in GOT or not. If it is then we check using routine functions if its being written by functions starting with '_dl_'. If it's not, then break out of the application as its doing arbitary write on got.

```
VOID CheckMemoryWrite(ADDRINT inst_ptr, ADDRINT memoryAddress) {
    // Check if memory write targets the GOT section
    if (memoryAddress >= GOT_Start && memoryAddress <= GOT_End) {
	PIN_LockClient();
	RTN rtn = RTN_FindByAddress(inst_ptr);


	if(RTN_Valid(rtn) && RTN_Name(rtn).rfind("_dl_", 0) == 0) {
		PIN_UnlockClient();
		return;
	}

	PIN_UnlockClient();
	OutFile << "[ALERT] Suspicious GOT overwrite attempt at " << std::hex << memoryAddress << std::endl;
	PIN_ExitApplication(100);
    }

   return;
}
```

