#pragma once
#pragma comment(lib, "crypt32.lib")
#include <tchar.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

HCERTSTORE openStore() {
    HCERTSTORE hSysStore = NULL;
    if (hSysStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,          // The store provider type
        X509_ASN_ENCODING,                               // The encoding type is
                                         // not needed
        NULL,                            // Use the default HCRYPTPROV
        CERT_SYSTEM_STORE_LOCAL_MACHINE, // Set the store location in a
                                         // registry location
        L"MY"                            // The store name as a Unicode 
                                         // string
    ))
    {
        printf("The system store was created successfully.\n");
    }
    else
    {
        printf("An error occurred during creation "
            "of the system store!\n");
        exit(1);
    }

    return hSysStore;
}