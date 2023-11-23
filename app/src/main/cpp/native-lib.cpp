#include "MemoryVerifier/IntegrityCheck.h"

static int a = 5;
static int b = 3;

int add(int _a, int _b){
    return _a + _b;
}

void test(){

    auto init =  IntegrityCheck::Initialize();
    if(!init) {
        LOG("Filed To Initialize");
        return;
    }

    while(true) {
        auto response = IntegrityCheck::Tick();
        if(response == IntegrityCheck::ReportData::NotInitialized) {
            break;
        }
        if(response == IntegrityCheck::ReportData::InvalidData) {
            break;
        }

    }

    IntegrityCheck::Stop();

}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_integritycheck_MainActivity_stringFromJNI(JNIEnv* env,jobject) {
    std::string hello = "Hello from C++ " + std::to_string(add(a,b));
    //LOG( "Patch function at Address: %p",&add);
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_integritycheck_MainActivity_patchFunction(JNIEnv* env,jobject) {

    /*
    SUB             SP, SP, #0x10
    STR             W0, [SP,#0x10+var_4]
    STR             W1, [SP,#0x10+var_8]
    LDR             W8, [SP,#0x10+var_4]
    LDR             W9, [SP,#0x10+var_8]
    // Patching ************
    ADD             W0, W8, W9
    // End ************
    ADD             SP, SP, #0x10
    RET
    */
    const unsigned char addBuffer[] = {
            0xFF, 0x43, 0x00, 0xD1, 0xE0, 0x0F, 0x00, 0xB9, 0xE1, 0x0B, 0x00,
            0xB9, 0xE8, 0x0F, 0x40, 0xB9, 0xE9, 0x0B, 0x40, 0xB9, 0x00, 0x01,
            0x09, 0x0B, 0xFF, 0x43, 0x00, 0x91, 0xC0, 0x03, 0x5F, 0xD6
    };


    /*
    SUB             SP, SP, #0x10
    STR             W0, [SP,#0x10+var_4]
    STR             W1, [SP,#0x10+var_8]
    LDR             W8, [SP,#0x10+var_4]
    LDR             W9, [SP,#0x10+var_8]
    // Reverting back ************
    SUBS            W0, W8, W9
    // End ************
    ADD             SP, SP, #0x10
    RET
    */
    const unsigned char subBuffer[] = {
            0xFF, 0x43, 0x00, 0xD1, 0xE0, 0x0F, 0x00, 0xB9, 0xE1, 0x0B, 0x00,
            0xB9, 0xE8, 0x0F, 0x40, 0xB9, 0xE9, 0x0B, 0x40, 0xB9, 0x00, 0x01,
            0x09, 0x6B, 0xFF, 0x43, 0x00, 0x91, 0xC0, 0x03, 0x5F, 0xD6
    };

    int result = std::memcmp(addBuffer, reinterpret_cast<const void *>(&add), sizeof(addBuffer));
    size_t pageSize = sysconf(_SC_PAGESIZE);
    //  Calculate start and end addresses for the write.
    auto start = (uintptr_t)&add;
    uintptr_t end = start + sizeof addBuffer;
    //  Calculate start of page for mprotect.
    uintptr_t pageStart = start & -pageSize;

    //  Change memory protection.
    if (mprotect((void *) pageStart, end - pageStart,PROT_READ | PROT_WRITE | PROT_EXEC)){
        exit(EXIT_FAILURE);
    }

    if(!result){
        std::memcpy(reinterpret_cast<void *>(start), subBuffer, sizeof(subBuffer));
    }else{
        std::memcpy(reinterpret_cast<void *>(start), addBuffer, sizeof(addBuffer));
    }

    if (mprotect((void *) pageStart, end - pageStart,PROT_READ | PROT_EXEC)){
        exit(EXIT_FAILURE);
    }
    return 1;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_integritycheck_MainActivity_createThread(JNIEnv* env,jobject) {
    pthread_t t;
    pthread_create(&t, nullptr, reinterpret_cast<void *(*)(void *)>(test), nullptr);
    return 0;
}