# Part-3: Position Independent Executable (PIE) (30 pt)

## Problem Statement

In this assignment, we build the binary with -fpie option; therefore, you no longer be able to find the GOT address range for GOT by only referring to ELF headers. You need to calculate the address at runtime referring to the base address of the section. Due to ASLR, the loader will map the .text section can be loaded to a different address every time you execute the binary.

```
$ readelf --relocs fs-no-binary-pie-64

....
Relocation section '.rela.plt' at offset 0x8a8 contains 19 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000202018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 getenv@GLIBC_2.2.5 + 0
000000202020  000300000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000202028  000500000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000202030  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fread@GLIBC_2.2.5 + 0
000000202038  000700000007 R_X86_64_JUMP_SLO 0000000000000000 write@GLIBC_2.2.5 + 0
000000202040  000800000007 R_X86_64_JUMP_SLO 0000000000000000 getpid@GLIBC_2.2.5 + 0
000000202048  000900000007 R_X86_64_JUMP_SLO 0000000000000000 fclose@GLIBC_2.2.5 + 0
000000202050  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 chdir@GLIBC_2.2.5 + 0
000000202058  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000202060  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000202068  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000202070  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000202078  001000000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000202080  001100000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
000000202088  001200000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000202090  001300000007 R_X86_64_JUMP_SLO 0000000000000000 open@GLIBC_2.2.5 + 0
000000202098  001400000007 R_X86_64_JUMP_SLO 0000000000000000 fopen@GLIBC_2.2.5 + 0
0000002020a0  001600000007 R_X86_64_JUMP_SLO 0000000000000000 getppid@GLIBC_2.2.5 + 0
```

In the part of the assignment, you need to work on two subparts.

1. Exploit AW binary built with -fPIE option (15 pt)
2. Modify / update your solution for Part-3 to handle PIE binary (20 pt)

## Compilation and Execution

- Run the script `run.sh` for compiling the `script.cpp`. Script also runs the compiled executable on /bin/ls.

  ```
  sh run.sh
  ```

  Sample output is as below:

  ```
  vxd240001@ctf-vm2:~/home/unit3-2/part3$ sh run.sh
  make: 'obj-intel64/script.so' is up to date.
  defense-tests  exploit.py  fs-code-exec-64  Makefile  obj-intel64  run2.sh  run.sh  script.cpp	script.out  Welcome
  Range: 0x55a2238b2c38 - 0x55a2238b3000
  ```

- Now run the python exploit. To run it use `sh run2.sh`

- Example:

```
sh run2.sh
```

- Output:

```
vxd240001@ctf-vm2:~/home/unit3-2/part3$ sh run2.sh
[*] '/home/vxd240001/home/unit3-2/part3/fs-code-exec-64'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/usr/local/pin/pin': pid 17064
[*] Switching to interactive mode

[*] Got EOF while reading in interactive
$ ls
[*] Process '/usr/local/pin/pin' stopped with exit code 100 (pid 17064)
[*] Got EOF while sending in interactive
Range: 0x56540e6ac2f0 - 0x56540e6ac390
[ALERT] Suspicious GOT overwrite attempt at 56540e6ac348
```

## Write-up

- The only change in this code would be how to find GOT range as binary is compiled with PIE Enabled. So we find the range dynamically using ImageLoad and .got and .got.plt section headers.

```
// GOT range
ADDRINT GOT_Start = 0x0;
ADDRINT GOT_End = 0x0;

static bool runOnce = true;
VOID ImageLoad(IMG img, VOID *v){
    if(!runOnce){
    	return;
    } else {
    	runOnce = false;
    }

    ADDRINT got_min = std::numeric_limits<ADDRINT>::max();
    ADDRINT got_max = 0;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)){
    	if(SEC_Name(sec) == ".got"){
	    ADDRINT start = SEC_Address(sec);
            ADDRINT end = start + SEC_Size(sec);
            got_min = std::min(got_min, start);
            got_max = std::max(got_max, end);
	}

	if(SEC_Name(sec) == ".got.plt"){
	    ADDRINT start = SEC_Address(sec);
            ADDRINT end = start + SEC_Size(sec);
            got_min = std::min(got_min, start);
            got_max = std::max(got_max, end);
	}
    }

    GOT_Start = got_min;
    GOT_End = got_max;

    OutFile << "Range: " << "0x" << std::hex << GOT_Start << " - " << "0x" << std::hex << GOT_End << std::endl;
    return;
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

