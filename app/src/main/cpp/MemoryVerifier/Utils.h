//
// Created by sarth on 27-05-2023.
//


#include "Common.h"

namespace Utils {

    std::string GetApplicationID( );
    std::vector< ProcessLibraries_t > GetReadAndExecuteLib( std::ifstream& maps, const std::string& applicationID );
    Map_t GetSectionInfo( const std::string& line );

    void CalculateSha256( void* buffer, size_t bufferSize, unsigned char (&sha256sum)[SHA256_DIGEST_LENGTH] );
    unsigned long GenerateSha256FromFile( int32_t& file_descriptor,off_t offset, size_t size, unsigned char (&sha256sum)[SHA256_DIGEST_LENGTH] );

    void ReportData( const std::string& name );

}
