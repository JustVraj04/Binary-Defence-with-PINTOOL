# Part-1: Find relocatable entries using ELFIO library (20 pt)

## Problem Statement

To protect the Global Offet Table (GOT) from being overwritten by the attacker, you first need to identify the section and memory address range. In this part, you will extend ELFIO to get a list of GOT entries and their address (Relocation Offset). We expect you to implement readelf -reloc so that list of GOT entries and their address at runtime.

For a given binary, readelf -reloc[1] will give you the following output.

```
$ readelf --relocs /tmp/8-fs-aw-64

....

Relocation section '.rela.plt' at offset 0x4e0 contains 11 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000601040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000601048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000601050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 getegid@GLIBC_2.2.5 + 0
000000601058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
000000601060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 open@GLIBC_2.2.5 + 0
000000601068  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
kjee@ctf-vm1.syssec.utdallas.edu:/home/kjee $
```

And we expect your implement should work as follows,

```
$ ./part1 /tmp/8-fs-aw-64

GOT range: 0x000000601018 ~ 000000601068

Offset          Symbol name
---------------------------------
000000601018    putchar
000000601020    puts
000000601028    __stack_chk_fail
...
000000601068    exit
```

Please ELFIO tutorial code regarding how to use ELFIO and readelf.c source to confirm how to find relocs entries and get their addresses.

## Compilation and Execution

- Run the script `run.sh` for compiling the `script.cpp`

  ```
  sh run.sh
  ```

- Now use binary file to count the got range of the said binary file.

  ```
  ./script ./<elf-file>
  ```

- Example:

  ```
  ./script ./7-aw1-64
  ```

  - Output:

  ```
  vxd240001@ctf-vm2:~/home/unit3-2/part1$ ./script ./7-aw1-64
  GOT range: 0x000000602018 ~ 0x000000602078
  Offset          Symbol name
  ---------------------------------
  000000602018    puts
  000000602020    __stack_chk_fail
  000000602028    printf
  000000602030    read
  000000602038    __libc_start_main
  000000602040    fgets
  000000602048    memcpy
  000000602050    prctl
  000000602058    fflush
  000000602060    __isoc99_sscanf
  000000602068    getegid
  000000602070    setregid
  000000602078    fwrite
  ```

  ```
  vxd240001@ctf-vm2:~/home/unit3-2/part1$ readelf --relocs ./7-aw1-64

  Relocation section '.rela.dyn' at offset 0x598 contains 3 entries:
  Offset          Info           Type           Sym. Value    Sym. Name +
  Addend
  000000601ff8  000700000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
  000000602090  000f00000005 R_X86_64_COPY     0000000000602090 stdout@GLIBC_2.2.5 + 0
  0000006020a0  001000000005 R_X86_64_COPY     00000000006020a0 stdin@GLIBC_2.2.5 + 0

  Relocation section '.rela.plt' at offset 0x5e0 contains 13 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
  000000602018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
  000000602020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
  000000602028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
  000000602030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
  000000602038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
  000000602040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.2.5 + 0
  000000602048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 memcpy@GLIBC_2.14 + 0
  000000602050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
  000000602058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 fflush@GLIBC_2.2.5 + 0
  000000602060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 __isoc99_sscanf@GLIBC_2.7 + 0
  000000602068  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 getegid@GLIBC_2.2.5 + 0
  000000602070  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
  000000602078  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 fwrite@GLIBC_2.2.5 + 0
  ```

## Write-up

- The code iterates through the ELF sections to find .rela.plt, which contains relocation entries for the GOT. If this section is not found, it outputs an error. The GOT addresses and symbols are typically located within this section for dynamic linking.

```
ELFIO::section* rela_plt = nullptr;
for (auto& sec : reader.sections) {
    if (sec->get_name() == ".rela.plt") {
        rela_plt = sec.get();
        break;
    }
}
if (rela_plt == nullptr) {
    std::cerr << "Could not find .rela.plt section." << std::endl;
    return -1;
}
```

- To calculate GOT Range, intialize got_min and got_max and iterates over each relocation entry to determine the range of addresses used by GOT entries. got_min and got_max are updated based on the offset of each entry to calculate the lowest and highest GOT addresses.

```
ELFIO::Elf64_Addr got_min = std::numeric_limits<ELFIO::Elf64_Addr>::max();
ELFIO::Elf64_Addr got_max = 0;

for (unsigned int i = 0; i < reloc.get_entries_num(); ++i) {
    reloc.get_entry(i, offset, symbol_value, symbol_name, type, addend, additional);
    got_min = std::min(got_min, offset);
    got_max = std::max(got_max, offset);
}
```

- The program iterates over each relocation entry in .rela.plt, extracting and displaying the offset and symbol_name for each. Formatting ensures that offsets are displayed consistently with zero-padding and hexadecimal alignment, matching typical ELF formatting conventions.

```
for (unsigned int i = 0; i < reloc.get_entries_num(); ++i) {
    reloc.get_entry(i, offset, symbol_value, symbol_name, type, addend, additional);
    std::cout << std::setfill('0') << std::setw(12) <<std::hex << offset << "    " << symbol_name << std::endl;
}
```
