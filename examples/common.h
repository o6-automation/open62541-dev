/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <open62541/types.h>
#include <stdio.h>
#include <errno.h>

/* sleep_ms */
#ifdef UA_ARCHITECTURE_WIN32
# include <synchapi.h>
# define sleep_ms(ms) Sleep(ms)
#else
# include <unistd.h>
# define sleep_ms(ms) usleep(ms * 1000)
#endif

/* loadFile parses the certificate file.
 *
 * @param  path               specifies the file name given in argv[]
 * @return Returns the file content after parsing */
static UA_INLINE UA_ByteString
loadFile(const char *const path) {
    UA_ByteString fileContents = UA_STRING_NULL;

    /* Open the file */
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        errno = 0; /* We read errno also from the tcp layer... */
        return fileContents;
    }

    /* Get the file length, allocate the data and read */
    if(fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        errno = 0;
        return fileContents;
    }

    long length = ftell(fp);
    if(length < 0) {
        fclose(fp);
        errno = 0;
        return fileContents;
    }

    fileContents.length = (size_t)length;
    fileContents.data = (UA_Byte *)UA_malloc(fileContents.length * sizeof(UA_Byte));
    if(fileContents.data) {
        if(fseek(fp, 0, SEEK_SET) != 0) {
            fclose(fp);
            UA_ByteString_clear(&fileContents);
            errno = 0;
            return fileContents;
        }
        size_t read = fread(fileContents.data, sizeof(UA_Byte), fileContents.length, fp);
        if(read != fileContents.length)
            UA_ByteString_clear(&fileContents);
    } else {
        fileContents.length = 0;
    }
    fclose(fp);

    return fileContents;
}

static UA_INLINE UA_StatusCode
writeFile(const char* const path, const UA_ByteString buffer) {
    FILE *fp = NULL;

    fp = fopen(path, "wb");
    if(fp == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    for(UA_UInt32 bufIndex = 0; bufIndex < buffer.length; bufIndex++) {
        int retVal = fputc(buffer.data[bufIndex], fp);
        if(retVal == EOF) {
            fclose(fp);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }

    fclose(fp);
    return UA_STATUSCODE_GOOD;
}

#ifdef UA_ENABLE_LWS
#include <open62541/server.h>

/* HTTP ConnectionManagers are registered explicitly, e.g. for the HTTP driver.
 * Without a TLS configuration, https uses the system trust store. */
static UA_INLINE UA_StatusCode
addHttpConnectionManager(UA_Server *server) {
    UA_ConnectionManager *cm = UA_ConnectionManager_new_HTTP(UA_STRING("http"), NULL);
    if(!cm)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_EventLoop *el = UA_Server_getConfig(server)->eventLoop;
    UA_StatusCode res = el->registerEventSource(el, &cm->eventSource);
    if(res != UA_STATUSCODE_GOOD)
        cm->eventSource.free(&cm->eventSource);
    return res;
}
#endif
