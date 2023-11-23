//
// Created by sarth on 27-05-2023.
//

#include <jni.h>
#include <string>
#include <pthread.h>
#include <fstream>
#include <tuple>
#include <vector>
#include <unistd.h>
#include <elf.h>
#include <regex>
#include <dlfcn.h>
#include <string>
#include <cinttypes>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <zlib.h>
#include <android/log.h>
#include <sys/mman.h>
#include <openssl/sha.h>

#define LOG(...) ((void)__android_log_print(ANDROID_LOG_INFO, "native-lib", __VA_ARGS__))

struct ProcessLibraries_t {
    uintptr_t base_address { };
    size_t size { };
    std::string path { };
};

struct Map_t {
    uintptr_t base_address { };
    uintptr_t end_address { };
    uint64_t offset { };
    std::string path { };
    bool isExecute { };
};

struct Section64_t {
    uintptr_t base_address { };
    size_t size { };
    uint64_t offset { };
    std::string name { };
    unsigned long crc { };
    unsigned char sha256sum[SHA256_DIGEST_LENGTH];
    Elf64_Xword flag { };
};

struct Section32_t {
    uintptr_t base_address { };
    size_t size { };
    uint32_t offset { };
    std::string name { };
    unsigned long crc { };
    unsigned char sha256sum[SHA256_DIGEST_LENGTH];
    Elf32_Xword flag { };
};