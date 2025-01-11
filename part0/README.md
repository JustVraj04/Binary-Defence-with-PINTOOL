# Part-0: Your first binary instrumentation (10 pt)

## Problem Statement

> Extend the inscount example and count the number of memory write instructions.

## Compilation and Execution

- Make sure to first execute run.sh.

- To count number of memory write instructions for `/bin/ls` use below shell-script:

  > sh run.sh

- Above script will run below commands.

  > make -e obj-intel64/inscount0.so  
  > pin -t obj-intel64/inscount0.so -- /bin/ls  
  > cat inscount.out

- If you want to count number of instruction for different command(after using make command), use below temlate:
  > pin -t obj-intel64/inscount0.so -- \<command to run\>  
  > cat inscount.out

## Extension of inscount example

- The example code inserts a call to docount before every instruction, no arguments are passed.
- I leverage PIN’s INS_MemoryOperandCount to determine the number of memory operands in an instruction.
- By iterating over each operand, I then apply `INS_MemoryOperandIsWritten` to filter and detect only those operands associated with memory write operations. This ensures that the tool exclusively counts memory writes, in contrast to counting all instructions.

