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
    	       INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckMemoryWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_END);
        }
    }

    return;
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v) {
    OutFile.close();
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

    PIN_InitSymbols();
    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    // Register instruction instrumentation
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

