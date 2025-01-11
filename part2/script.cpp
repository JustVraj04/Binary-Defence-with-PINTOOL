#include <iostream>
#include <fstream>
#include <pin.H>
#include <vector>
#include <string>
#include <elfio/elfio.hpp>  // Include ELFIO for GOT information

using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

// output file
ofstream OutFile;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "script.out", "specify output file name");

// GOT range
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

// This function is called before every instruction is executed
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

// Instrument memory write instructions
VOID Instruction(INS ins, VOID* v) {
    UINT32 operandCount = INS_MemoryOperandCount(ins);

    for (UINT32 x = 0; x < operandCount; x++) {
        if (INS_MemoryOperandIsWritten(ins,x)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckMemoryWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, x, IARG_END);
        }
    }

    return;
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v) {
    OutFile.close();
    return;
}

INT32 Usage()
{
  std::cout << "This is the PIN tool to monitor GOT overwrites." << std::endl;
  std::cout << endl << KNOB_BASE::StringKnobSummary() << std::endl;
    
  return -1;
}

// Main function for the PIN tool
int main(int argc, char* argv[]) {
    OutFile.open(KnobOutputFile.Value().c_str());
    // Initialize PIN
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    // Check if there are enough arguments
    if (argc < 2) {
        OutFile << "Error: No ELF file specified." << std::endl;
        return 1;
    }

    // Extract the ELF file path
    std::string elfFile = argv[argc - 1];  // ELF file path

    // Load the ELF file and extract GOT addresses
    if (!findGOTAddresses(elfFile)) {
        OutFile << "Failed to get GOT range" << std::endl;
	return -1;
    }
    
    OutFile << "Range: " << "0x" << std::hex << GOT_Start << " - " << "0x" << std::hex << GOT_End << std::endl;
    // Register instruction instrumentation
    PIN_InitSymbols();
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

