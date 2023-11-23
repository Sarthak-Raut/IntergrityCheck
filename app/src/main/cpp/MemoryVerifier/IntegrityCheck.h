//
// Created by sarthak on 26-03-2023.
//

#include "Utils.h"

namespace  IntegrityCheck {

    enum class ReportData
    {
        NotInitialized,
        InvalidData,
        Normal
    };

    static std::vector< Section64_t > section64;
    static std::vector< Section32_t > section32;

    bool Initialize( );
    void Stop( );
    ReportData Tick( );

    void IterateLib( const ProcessLibraries_t& execute_library );
    std::vector< Section64_t > ParseLibSection64( int32_t& file_descriptor, const ProcessLibraries_t& execute_library );
    std::vector< Section32_t > ParseLibSection32( int32_t& file_descriptor, const ProcessLibraries_t& execute_library );

    namespace Efl {

        bool ReadHeader64( int32_t &file_descriptor, Elf64_Ehdr& elf_header );
        bool ReadHeader32( int32_t &file_descriptor, Elf32_Ehdr& elf_header );

        bool ReadSectionHeader64( int32_t& file_descriptor, Elf64_Ehdr& elf_header, Elf64_Shdr* address_to_store );
        bool ReadSectionHeader32( int32_t& file_descriptor, Elf32_Ehdr& elf_header, Elf32_Shdr* address_to_store );

        bool ReadSection64( int32_t& file_descriptor, Elf64_Shdr& section_header, char* address_to_store );
        bool ReadSection32( int32_t& file_descriptor, Elf32_Shdr& section_header, char* address_to_store );

        std::vector< Section64_t > GetExecutableSection64( Elf64_Ehdr& elf_header, Elf64_Shdr* section_header, char* section_name_string_table );
        std::vector< Section32_t > GetExecutableSection32( Elf32_Ehdr& elf_header, Elf32_Shdr* section_header, char* section_name_string_table );
    }

}