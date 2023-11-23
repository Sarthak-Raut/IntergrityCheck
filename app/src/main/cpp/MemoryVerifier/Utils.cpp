//
// Created by sarth on 27-05-2023.
//

#include "Utils.h"

namespace Utils {

    std::string GetApplicationID(  ) {
        char path[64] = { 0 };
        char application_id[64] = { 0 };
        sprintf( path, "/proc/self/cmdline" );
        FILE *cmdline = fopen( path, "r" );
        if ( cmdline ) {
            // Read the contents of the file into the application ID buffer
            fread( application_id, sizeof( application_id ), 1, cmdline );
            fclose( cmdline );
        }
        return application_id;
    }
    // Parse a line in the /proc/self/maps file and return a tuple containing
    // the memory range and permissions of the section
    Map_t GetSectionInfo( const std::string& line ) {

        // The memory range is the first field in the line
        // ( fields are separated by one or more spaces )
        Map_t map = { 0 };

        uintptr_t start, end;
        uint64_t offset;
        unsigned int dmajor, dminor;
        uint64_t ino;
        int nread = -1;
        char path[1024] = "";

        std::size_t pos = line.find_first_of( ' ' );
        std::string permissions = line.substr( pos + 1, 4 );

        sscanf( line.c_str(  ), "%" PRIxPTR "-%" PRIxPTR " %*s %" PRIx64" %x:%x %" PRIu64 " %s %n",&start, &end, &offset, &dmajor, &dminor, &ino,&path[0], &nread );
        map.base_address = start;
        map.end_address = end;
        map.offset = offset;
        map.path = path;
        map.isExecute = permissions[2] == 'x';
        return map;
    }
    std::vector< ProcessLibraries_t > GetReadAndExecuteLib( std::ifstream& maps, const std::string& applicationID ) {

        std::vector< ProcessLibraries_t > sections;
        // Read the file line by line
        std::string line;
        while ( std::getline( maps, line ) ) {

            Map_t map = GetSectionInfo( line );
            //Check the permission of the sections
            if ( map.isExecute ) {

                ProcessLibraries_t section {  };
                section.base_address = map.base_address;
                section.size = map.end_address - map.base_address;
                section.path = map.path;

                //Check if the section belongs to our application ( You can add a better check )
                if ( section.path.find( applicationID ) != std::string::npos ) {
                    LOG( "[+] Line: %s and path : %s", line.c_str(  ),section.path.c_str(  ) );
                    sections.push_back( section );
                }
            }
        }

        return  sections;
    }

    void CalculateSha256( void* buffer, size_t bufferSize, unsigned char ( &sha256sum )[SHA256_DIGEST_LENGTH] ) {
        SHA256_CTX sha256Context;
        SHA256_Init( &sha256Context );
        SHA256_Update( &sha256Context, buffer, bufferSize );
        SHA256_Final( sha256sum, &sha256Context );
    }
    unsigned long GenerateSha256FromFile( int32_t& file_descriptor,off_t offset, size_t size, unsigned char ( &sha256sum )[SHA256_DIGEST_LENGTH] ) {

        if( lseek( file_descriptor, offset, SEEK_SET ) == -1 ) {
            LOG( "[-] Function: %s -- Error seeking in file: %s",__func__ ,strerror( errno ) );
            return 0;
        }

        char tempBuffer[size];

        if( read( file_descriptor, tempBuffer, size ) != size ) {
            LOG( "[-] Function: %s -- Error reading section from file",__func__ );
            return 0;
        }

        CalculateSha256( tempBuffer, size,sha256sum );

        unsigned long crc = crc32( 0L, Z_NULL, 0 );
        crc = crc32( crc, reinterpret_cast<unsigned char *>( tempBuffer ), size );
        return crc;

    }

    void ReportData( const std::string& name ) {
        LOG( "[X] Section data corruption found in %s",name.c_str(  ) );
    }

}