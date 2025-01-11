#include <iostream>
#include <elfio/elfio.hpp>
#include <limits>
#include <iomanip>

using namespace ELFIO;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Usage: elf_part1 <elf_file>" << std::endl;
        return 1;
    }

    // Create an elfio reader
    elfio reader;

    // Load ELF data
    if (!reader.load(argv[1])) {
        std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
        return 2;
    }

    // Locate .rela.plt section
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

    // Create a relocation section accessor
    ELFIO::relocation_section_accessor reloc(reader, rela_plt);

    // Variables to hold relocation information
    ELFIO::Elf64_Addr offset;
    ELFIO::Elf64_Addr symbol_value;
    std::string symbol_name;
    ELFIO::Elf_Word type;
    ELFIO::Elf_Sxword addend;
    ELFIO::Elf_Sxword additional;

    // Calculate GOT range
    ELFIO::Elf64_Addr got_min = std::numeric_limits<ELFIO::Elf64_Addr>::max();
    ELFIO::Elf64_Addr got_max = 0;

    for (unsigned int i = 0; i < reloc.get_entries_num(); ++i) {
        reloc.get_entry(i, offset, symbol_value, symbol_name, type, addend, additional);
        got_min = std::min(got_min, offset);
        got_max = std::max(got_max, offset);
    }

    // Print GOT range
    std::cout << "GOT range: 0x" << std::setfill('0') << std::setw(12) <<std::hex << got_min << " ~ 0x" << std::setfill('0') << std::setw(12) <<std::hex << got_max << std::endl;

    // Print the relocation entries
    std::cout << "Offset          Symbol name" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    for (unsigned int i = 0; i < reloc.get_entries_num(); ++i) {
        reloc.get_entry(i, offset, symbol_value, symbol_name, type, addend, additional);
	std::cout << std::setfill('0') << std::setw(12) <<std::hex << offset << "    " << symbol_name << std::endl;
    }

    return 0;
}
