//
// Created by sarth on 26-03-2023.
//

#include "IntegrityCheck.h"

namespace IntegrityCheck {

    bool Initialize( ) {

        std::string applicationID = Utils::GetApplicationID( );

        std::ifstream maps( "/proc/self/maps" );
        if ( !maps.is_open( ) ) {
            LOG( "[-] Failed to open /proc/self/maps" );
            return false;
        }

        std::vector<ProcessLibraries_t> executeLibs = Utils::GetReadAndExecuteLib( maps, applicationID );
        if ( executeLibs.empty( ) ) {
            LOG( "[-] No read and execute section found" );
            return false;
        }

        for ( const auto& executeLib : executeLibs ) {
            IterateLib( executeLib  );
        }

        if ( section64.empty( ) && section32.empty( ) ) {
            LOG( "[-] Failed to iterate lib" );
            return false;
        }

        return true;
    }
    void Stop( ) {

        section64.clear( );
        section32.clear( );

    }

    ReportData Tick( ) {

        if ( section64.empty( ) && section32.empty( ) ) {
            LOG( "[-] No section found, make sure you have Initialized the function" );
            return ReportData::NotInitialized;
        }

        for( const auto& section : section64 ) {

            unsigned char sha256sum[SHA256_DIGEST_LENGTH];
            Utils::CalculateSha256(reinterpret_cast<void *>( section.base_address + section.offset ), section.size, sha256sum );

            /*unsigned long crc = crc32( 0L, Z_NULL, 0 );
            crc = crc32( crc, reinterpret_cast<unsigned char *>( section.base_address + section.offset ), section.size );
            if ( crc != section.crc ) {
                Utils::ReportData( section.name );
                return ReportData::InvalidData;
            }
            else {
                LOG( "[+] No Patches Found" );
            }*/

            if ( std::memcmp( sha256sum, section.sha256sum, SHA256_DIGEST_LENGTH ) == 0 ) {
                LOG( "[+] No Patches Found" );
            }
            else {
                Utils::ReportData( section.name );
                return ReportData::InvalidData;
            }

        }

        for( const auto& section : section32 ) {

            unsigned char sha256sum[SHA256_DIGEST_LENGTH];
            Utils::CalculateSha256(reinterpret_cast<void *>( section.base_address + section.offset ), section.size, sha256sum );

            /*unsigned long crc = crc32( 0L, Z_NULL, 0 );
            crc = crc32( crc, reinterpret_cast<unsigned char *>( section.base_address + section.offset ), section.size );
            if ( crc != section.crc ) {
                Utils::ReportData( section.name );
                return ReportData::InvalidData;
            }
            else {
                LOG( "[+] No Patches Found" );
            }*/

            if ( std::memcmp( sha256sum, section.sha256sum, SHA256_DIGEST_LENGTH ) == 0 ) {
                LOG( "[+] No Patches Found" );
            }
            else {
                Utils::ReportData( section.name );
                return ReportData::InvalidData;
            }
        }

        return ReportData::Normal;
    }

    void IterateLib( const ProcessLibraries_t& execute_library ) {

        int32_t file_descriptor;
        Elf32_Ehdr elf_header;

        file_descriptor = open( execute_library.path.c_str( ), O_RDONLY | O_SYNC );
        LOG( "Path = %s", execute_library.path.c_str( ) );
        if ( file_descriptor < 0 ) {
            LOG( "[-] Error %d Unable to open %s", file_descriptor, execute_library.path.c_str( ) );
            return;
        }

        bool bHeader = Efl::ReadHeader32( file_descriptor, elf_header );
        if ( !bHeader ) {
            LOG( "[-] Error %d Unable to parse Header", file_descriptor );
            close( file_descriptor );
            return;
        }

        //if ELF file is 64-Bit change header
        if ( elf_header.e_ident[EI_CLASS] == ELFCLASS64 ) {
            auto section_parsed = ParseLibSection64( file_descriptor, execute_library );
            section64.insert( section64.end( ), section_parsed.begin( ), section_parsed.end( ) );
        }
        else if ( elf_header.e_ident[EI_CLASS] == ELFCLASS32 ) {
            auto section_parsed = ParseLibSection32( file_descriptor, execute_library );
            section32.insert( section32.end( ), section_parsed.begin( ), section_parsed.end( ) );
        }

        close( file_descriptor );

    }
    std::vector< Section64_t > ParseLibSection64( int32_t& file_descriptor, const ProcessLibraries_t& execute_library ) {

        std::vector<Section64_t> section { };

        //read ELF header64
        Elf64_Ehdr elf_header;	/* elf-header is fixed size */
        bool bHeader = Efl::ReadHeader64( file_descriptor, elf_header );
        if ( !bHeader ) {
            LOG( "[-] Function: %s -- Error %d Unable to parse Header\n",__func__, file_descriptor );
            return section;
        }

        Elf64_Shdr section_header[elf_header.e_shentsize * elf_header.e_shnum];

        //Read execute_library header table
        bool bSectionHeader = Efl::ReadSectionHeader64( file_descriptor, elf_header, section_header );
        if ( !bSectionHeader ) {
            LOG( "[-] Function: %s -- Error %d Unable to parse execute_library header table\n",__func__, file_descriptor );
            return section;
        }

        char section_name_string_table[section_header[elf_header.e_shstrndx].sh_size];

        /* Read execute_library-header string-table */
        bool bStringTable = Efl::ReadSection64( file_descriptor, section_header[elf_header.e_shstrndx], section_name_string_table );
        if ( !bStringTable ) {
            LOG( "[-] Function: %s -- Error %d Unable to parse string table\n",__func__, file_descriptor );
            return section;
        }

        std::vector<Section64_t> execute_sections = Efl::GetExecutableSection64( elf_header, section_header, section_name_string_table );
        if ( execute_sections.empty( ) ) {
            LOG( "[-] Function: %s -- No sections with read and execute flags found\n",__func__ );
            return section;
        }

        for ( auto& executeSection : execute_sections ) {
            executeSection.crc = Utils::GenerateSha256FromFile( file_descriptor, ( off_t )executeSection.offset, executeSection.size,executeSection.sha256sum );
            executeSection.base_address = execute_library.base_address;
        }

        return execute_sections;
    }
    std::vector< Section32_t > ParseLibSection32( int32_t& file_descriptor, const ProcessLibraries_t& execute_library ) {

        std::vector<Section32_t> section { };
        //read ELF header64
        Elf32_Ehdr elf_header;	/* elf-header is fixed size */
        bool bHeader = Efl::ReadHeader32( file_descriptor, elf_header );
        if ( !bHeader ) {
            LOG( "[-] Function: %s -- Error %d Unable to parse Header\n", __func__, file_descriptor );
            return section;
        }

        Elf32_Shdr section_header[elf_header.e_shentsize * elf_header.e_shnum];

        //Read execute_library header table
        bool bSectionHeader = Efl::ReadSectionHeader32( file_descriptor, elf_header, section_header );
        if ( !bSectionHeader ) {
            LOG( "[-] Function: %s -- Error %d Unable to parse execute_library header table\n", __func__, file_descriptor );
            return section;
        }

        char section_name_string_table[section_header[elf_header.e_shstrndx].sh_size];

        /* Read execute_library-header string-table */
        bool bStringTable = Efl::ReadSection32( file_descriptor, section_header[elf_header.e_shstrndx], section_name_string_table );
        if ( !bStringTable ) {
            LOG( "[-] Function: %s -- Error %d Unable to parse string table\n", __func__, file_descriptor );
            return section;
        }

        std::vector<Section32_t> execute_sections = Efl::GetExecutableSection32( elf_header, section_header, section_name_string_table );
        if ( execute_sections.empty( ) ) {
            LOG( "[-] Function: %s -- No sections with read and execute flags found\n", __func__ );
            return section;
        }

        for ( auto& executeSection : execute_sections ) {
            executeSection.crc = Utils::GenerateSha256FromFile( file_descriptor, ( off_t )executeSection.offset, executeSection.size,executeSection.sha256sum );
            executeSection.base_address = execute_library.base_address;
        }

        return execute_sections;
    }

    namespace Efl {

        bool ReadHeader64( int32_t& file_descriptor, Elf64_Ehdr& elf_header ) {

            if ( lseek( file_descriptor, ( off_t )0, SEEK_SET ) == -1 ) {
                LOG( "[-] Function: %s -- Error seeking in file: %s", __func__, strerror( errno ) );
                return false;
            }

            if ( read( file_descriptor, ( void * )&elf_header, sizeof( Elf64_Ehdr ) ) != sizeof( Elf64_Ehdr ) ) {
                LOG( "[-] Function: %s -- Error reading from file", __func__ );
                return false;
            }

            if ( elf_header.e_ident[EI_MAG0] != ELFMAG0 ||
                 elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
                 elf_header.e_ident[EI_MAG2] != ELFMAG2 ||
                 elf_header.e_ident[EI_MAG3] != ELFMAG3 ) {
                LOG( "[-] Function: %s -- Error: not an ELF file", __func__ );
                return false;
            }

            return true;
        }
        bool ReadHeader32( int32_t& file_descriptor, Elf32_Ehdr& elf_header ) {

            if ( lseek( file_descriptor, ( off_t )0, SEEK_SET ) == -1 ) {
                LOG( "[-] Function: %s -- Error seeking in file: %s", __func__, strerror( errno ) );
                return false;
            }

            if ( read( file_descriptor, ( void * )&elf_header, sizeof( Elf32_Ehdr ) ) != sizeof( Elf32_Ehdr ) ) {
                LOG( "[-] Function: %s -- Error reading from file", __func__ );
                return false;
            }

            if ( elf_header.e_ident[EI_MAG0] != ELFMAG0 ||
                 elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
                 elf_header.e_ident[EI_MAG2] != ELFMAG2 ||
                 elf_header.e_ident[EI_MAG3] != ELFMAG3 ) {
                LOG( "[-] Function: %s -- Error: not an ELF file", __func__ );
                return false;
            }

            return true;
        }

        bool ReadSectionHeader64( int32_t& file_descriptor, Elf64_Ehdr& elf_header, Elf64_Shdr* address_to_store ) {

            if ( address_to_store == nullptr ) {
                LOG( "[-] Function: %s -- Error invalid base_address to store the header", __func__ );
                return false;
            }

            //Seek to the offset of the section header table in the file
            if ( lseek( file_descriptor, ( off_t )elf_header.e_shoff, SEEK_SET ) == -1 ) {
                LOG( "[-] Function: %s -- Error seeking in file: %s", __func__, strerror( errno ) );
                return false;
            }

            //Read the section header table from the file
            for( uint32_t i=0; i < elf_header.e_shnum; i++ ) {
                if ( read( file_descriptor, ( void * )&address_to_store[i], elf_header.e_shentsize ) != elf_header.e_shentsize ) {
                    LOG( "[-] Function: %s -- Error reading section header table from file at index %d", __func__, i );
                    return false;
                }
            }

            return true;
        }
        bool ReadSectionHeader32( int32_t& file_descriptor, Elf32_Ehdr& elf_header, Elf32_Shdr* address_to_store ) {

            if ( address_to_store == nullptr ) {
                LOG( "[-] Function: %s -- Error invalid base_address to store the header", __func__ );
                return false;
            }

            //Seek to the offset of the section header table in the file
            if ( lseek( file_descriptor, ( off_t )elf_header.e_shoff, SEEK_SET ) == -1 ) {
                LOG( "[-] Function: %s -- Error seeking in file: %s", __func__, strerror( errno ) );
                return false;
            }

            //Read the section header table from the file
            for( uint32_t i=0; i < elf_header.e_shnum; i++ ) {
                if ( read( file_descriptor, ( void * )&address_to_store[i], elf_header.e_shentsize ) != elf_header.e_shentsize ) {
                    LOG( "[-] Function: %s -- Error reading section header table from file at index %d", __func__, i );
                    return false;
                }
            }

            return true;
        }

        bool ReadSection64( int32_t& file_descriptor, Elf64_Shdr& section_header, char* address_to_store ) {

            if ( address_to_store == nullptr ) {
                LOG( "[-] Function: %s -- Error invalid base_address to store the section", __func__ );
                return false;
            }

            if ( lseek( file_descriptor, ( off_t )section_header.sh_offset, SEEK_SET ) == -1 ) {
                LOG( "[-] Function: %s -- Error seeking in file: %s", __func__, strerror( errno ) );
                return false;
            }

            if ( read( file_descriptor, ( void * )address_to_store, section_header.sh_size ) != section_header.sh_size ) {
                LOG( "[-] Function: %s -- Error reading section from file", __func__ );
                return false;
            }

            return true;
        }
        bool ReadSection32( int32_t& file_descriptor, Elf32_Shdr& section_header, char* address_to_store ) {

            if ( address_to_store == nullptr ) {
                LOG( "[-] Function: %s -- Error invalid base_address to store the section", __func__ );
                return false;
            }

            if ( lseek( file_descriptor, ( off_t )section_header.sh_offset, SEEK_SET ) == -1 ) {
                LOG( "[-] Function: %s -- Error seeking in file: %s", __func__, strerror( errno ) );
                return false;
            }

            if ( read( file_descriptor, ( void * )address_to_store, section_header.sh_size ) != section_header.sh_size ) {
                LOG( "[-] Function: %s -- Error reading section from file", __func__ );
                return false;
            }

            return true;
        }

        std::vector< Section64_t > GetExecutableSection64( Elf64_Ehdr& elf_header, Elf64_Shdr* section_header, char* section_name_string_table ) {
            std::vector<Section64_t> sectionTemp;
            for( uint32_t i = 0; i < elf_header.e_shnum; i++ ) {
                uint32_t flag = section_header[i].sh_flags;
                //SHF_EXECINSTR : Section contains executable machine instructions.
                //SHF_WRITE : Section should be writable during process execution.
                if ( ( flag & SHF_EXECINSTR ) && ( ( flag & SHF_WRITE ) == 0 ) ) {
                    /*LOG( "Section Name: %s",( section_name_string_table + section_header[i].sh_name ) );
                    LOG( "Flag = %llX", section_header[i].sh_flags );
                    LOG( "at offset\t0x%08llx\n", section_header[i].sh_offset );
                    LOG( "of size\t\t0x%08llx\n", section_header[i].sh_size );*/
                    Section64_t section {  };
                    section.name = ( section_name_string_table + section_header[i].sh_name );
                    section.size = section_header[i].sh_size;
                    section.offset = section_header[i].sh_offset;
                    section.flag = section_header[i].sh_flags;
                    sectionTemp.push_back( section );
                }
            }
            return sectionTemp;
        }
        std::vector< Section32_t > GetExecutableSection32( Elf32_Ehdr& elf_header, Elf32_Shdr* section_header, char* section_name_string_table ) {
            std::vector<Section32_t> sectionTemp;
            for( uint32_t i = 0; i < elf_header.e_shnum; i++ ) {
                uint32_t flag = section_header[i].sh_flags;
                //SHF_EXECINSTR : Section contains executable machine instructions.
                //SHF_WRITE : Section should be writable during process execution.
                if ( ( flag & SHF_EXECINSTR ) && ( ( flag & SHF_WRITE ) == 0 ) ) {
                    /*LOG( "Section Name: %s",( section_name_string_table + section_header[i].sh_name ) );
                    LOG( "Flag = %llX", section_header[i].sh_flags );
                    LOG( "at offset\t0x%08llx\n", section_header[i].sh_offset );
                    LOG( "of size\t\t0x%08llx\n", section_header[i].sh_size );*/
                    Section32_t section {  };
                    section.name = ( section_name_string_table + section_header[i].sh_name );
                    section.size = section_header[i].sh_size;
                    section.offset = section_header[i].sh_offset;
                    section.flag = section_header[i].sh_flags;
                    sectionTemp.push_back( section );
                }
            }
            return sectionTemp;
        }

    }

}
