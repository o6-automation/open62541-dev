/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "test_helpers.h"
#include <open62541/client_config_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/log.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_default.h>

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
# include <windows.h>
#else
# include <dirent.h>
# include <limits.h>
# include <stdlib.h>
# include <sys/stat.h>
# include <unistd.h>
#endif

#define TESTING_LOGLEVEL UA_LOGLEVEL_INFO

static void
testServerNotificationCallback(UA_Server *server,
                               UA_ApplicationNotificationType type,
                               const UA_KeyValueMap payload) {
}

UA_Server * UA_Server_newForUnitTest(void) {
    UA_ServerConfig sc;
    memset(&sc, 0, sizeof(UA_ServerConfig));
    sc.logging = UA_Log_Stdout_new(TESTING_LOGLEVEL);
    UA_ServerConfig_setMinimal(&sc, 4840, NULL);
    UA_Server *server = UA_Server_newWithConfig(&sc);
    if(!server)
        return NULL;
    UA_ServerConfig *config = UA_Server_getConfig(server);
    /* Manually set the eventloop clock to the fake clock */
    config->eventLoop->dateTime_now = UA_DateTime_now_fake;
    config->eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    config->tcpReuseAddr = true;
    return server;
}

UA_Server *
UA_Server_newForUnitTestWithSecurityPolicies(UA_UInt16 portNumber,
                                             const UA_ByteString *certificate,
                                             const UA_ByteString *privateKey,
                                             const UA_ByteString *trustList,
                                             size_t trustListSize,
                                             const UA_ByteString *issuerList,
                                             size_t issuerListSize,
                                             const UA_ByteString *revocationList,
                                             size_t revocationListSize) {
    UA_ServerConfig config;
    memset(&config, 0, sizeof(UA_ServerConfig));
    config.logging = UA_Log_Stdout_new(TESTING_LOGLEVEL);
#ifdef UA_ENABLE_ENCRYPTION
    UA_ServerConfig_setDefaultWithSecurityPolicies(&config, portNumber,
                                                   certificate, privateKey,
                                                   trustList, trustListSize,
                                                   issuerList, issuerListSize,
                                                   revocationList, revocationListSize);
#endif
    config.eventLoop->dateTime_now = UA_DateTime_now_fake;
    config.eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    config.tcpReuseAddr = true;
    config.globalNotificationCallback = testServerNotificationCallback;
    return UA_Server_newWithConfig(&config);
}

#if defined(__linux__) || defined(UA_ARCHITECTURE_WIN32)
UA_Server *
UA_Server_newForUnitTestWithSecurityPolicies_Filestore(UA_UInt16 portNumber,
                                                       const UA_ByteString *certificate,
                                                       const UA_ByteString *privateKey,
                                                       const UA_String storePath) {
    UA_ServerConfig config;
    memset(&config, 0, sizeof(UA_ServerConfig));
    config.logging = UA_Log_Stdout_new(TESTING_LOGLEVEL);
#ifdef UA_ENABLE_ENCRYPTION
    UA_ServerConfig_setDefaultWithFilestore(&config, portNumber,
                                            certificate, privateKey, storePath);
#endif
    config.eventLoop->dateTime_now = UA_DateTime_now_fake;
    config.eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    config.tcpReuseAddr = true;
    config.globalNotificationCallback = testServerNotificationCallback;
    return UA_Server_newWithConfig(&config);
}
#endif /* defined(__linux__) || defined(UA_ARCHITECTURE_WIN32) */

UA_Boolean
UA_UnitTest_createTempDir(const char *prefix, char *path, size_t pathSize) {
#ifdef _WIN32
    for(int i = 0; i < 100; i++) {
        int n = snprintf(path, pathSize, "%s_%lu_%d", prefix,
                         (unsigned long)GetTickCount(), i);
        if(n < 0 || (size_t)n >= pathSize)
            return false;
        if(CreateDirectoryA(path, NULL))
            return true;
    }
    return false;
#else
    int n = snprintf(path, pathSize, "/tmp/%s_XXXXXX", prefix);
    if(n < 0 || (size_t)n >= pathSize)
        return false;
    return mkdtemp(path) != NULL;
#endif
}

void
UA_UnitTest_removeDir(const char *path) {
#ifdef _WIN32
    char search[MAX_PATH + 3];
    int n = snprintf(search, sizeof(search), "%s\\*", path);
    if(n < 0 || (size_t)n >= sizeof(search))
        return;
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search, &ffd);
    if(hFind == INVALID_HANDLE_VALUE)
        return;
    do {
        if(strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
            continue;
        char full[MAX_PATH + 1];
        n = snprintf(full, sizeof(full), "%s\\%s", path, ffd.cFileName);
        if(n < 0 || (size_t)n >= sizeof(full))
            continue;
        /* A symbolic link or junction to a directory is a reparse point with
         * the directory attribute. Remove the link, do not enter it. */
        if((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            UA_UnitTest_removeDir(full);
        else if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            RemoveDirectoryA(full);
        else
            DeleteFileA(full);
    } while(FindNextFileA(hFind, &ffd) != 0);
    FindClose(hFind);
    RemoveDirectoryA(path);
#else
    DIR *dir = opendir(path);
    if(!dir)
        return;
    struct dirent *entry;
    while((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);
        if(n < 0 || (size_t)n >= sizeof(full))
            continue;
        /* lstat does not follow a symbolic link. A link to a directory is
         * removed with unlink, its target is not entered. */
        struct stat st;
        if(lstat(full, &st) != 0)
            continue;
        if(S_ISDIR(st.st_mode))
            UA_UnitTest_removeDir(full);
        else
            unlink(full);
    }
    closedir(dir);
    rmdir(path);
#endif
}

static void
testClientNotificationCallback(UA_Client *client,
                               UA_ApplicationNotificationType type,
                               const UA_KeyValueMap payload) {
}

UA_Client *
UA_Client_newForUnitTest(void) {
    UA_ClientConfig cc;
    memset(&cc, 0, sizeof(UA_ClientConfig));
    cc.logging = UA_Log_Stdout_new(TESTING_LOGLEVEL);
    UA_ClientConfig_setDefault(&cc);
    UA_Client *client = UA_Client_newWithConfig(&cc);
    if(!client)
        return NULL;
    UA_ClientConfig *config = UA_Client_getConfig(client);
    /* Manually set the eventloop clock to the fake clock */
    config->eventLoop->dateTime_now = UA_DateTime_now_fake;
    config->eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    config->tcpReuseAddr = true;

    /* Allow username/pw w/o encryption */
    config->allowNonePolicyPassword = true;

    /* Increase the timeouts (needed for valgrind CI tests) */
    config->timeout = 10 * 60 * 1000;

    config->globalNotificationCallback = testClientNotificationCallback;

    return client;
}

UA_StatusCode
UA_ClientConfig_newForUnitTestWithEncryption(UA_ClientConfig *config,
                                             const UA_ByteString certificate,
                                             const UA_ByteString privateKey) {
    memset(config, 0, sizeof(UA_ClientConfig));
    config->logging = UA_Log_Stdout_new(TESTING_LOGLEVEL);
#ifdef UA_ENABLE_ENCRYPTION
    UA_ClientConfig_setDefaultEncryption(config, certificate, privateKey,
                                         NULL, 0, NULL, 0);
#endif
    UA_CertificateGroup_AcceptAll(&config->certificateVerification);
    config->eventLoop->dateTime_now = UA_DateTime_now_fake;
    config->eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    config->tcpReuseAddr = true;
    config->allowNonePolicyPassword = true;
    config->timeout = 10 * 60 * 1000; /* increased for valgrind CI */
    config->globalNotificationCallback = testClientNotificationCallback;
    return UA_STATUSCODE_GOOD;
}
