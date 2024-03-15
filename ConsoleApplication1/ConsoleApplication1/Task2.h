#pragma once
#pragma comment(lib, "crypt32.lib")
#include <tchar.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include "Store.h"
#define CERTIFICATE_BUFFER_SIZE 1024


HCERTSTORE openStore();

void Task2() {
    LPCWSTR certFile = L"C:\\cert.cer";
    HRESULT  hr = S_OK;
    BYTE     certEncoded[CERTIFICATE_BUFFER_SIZE] = { 0 };
    DWORD    certEncodedSize = 0L;
    HANDLE   certFileHandle = NULL;
    BOOL     result = FALSE;

    // open the certificate file
    certFileHandle = CreateFile(certFile,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == certFileHandle) {
        hr = HRESULT_FROM_WIN32(GetLastError());
    }

    if (SUCCEEDED(hr)) {
        // if the buffer is large enough
        //  read the certificate file into the buffer
        if (GetFileSize(certFileHandle, NULL) <= CERTIFICATE_BUFFER_SIZE) {
            result = ReadFile(certFileHandle,
                certEncoded,
                CERTIFICATE_BUFFER_SIZE,
                &certEncodedSize,
                NULL);
            if (!result) {
                // the read failed, return the error as an HRESULT
                hr = HRESULT_FROM_WIN32(GetLastError());
            }
            else {
                hr = S_OK;
            }
        }
        else {
            // The certificate file is larger than the allocated buffer.
            //  To handle this error, you could dynamically allocate
            //  the certificate buffer based on the file size returned or 
            //  use a larger static buffer.
            hr = HRESULT_FROM_WIN32(ERROR_MORE_DATA);
        }
    }
    PCCERT_CONTEXT cert = 0;
    if (SUCCEEDED(hr))
    {
        // create a certificate from the contents of the buffer
        cert = CertCreateCertificateContext(X509_ASN_ENCODING,
            certEncoded,
            certEncodedSize);
        if (!(cert)) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            CloseHandle(certFileHandle);
            hr = E_FAIL;
        }
        else {
            hr = S_OK;
        }
    }

    HCERTSTORE hCertStore = openStore();
    if (CertAddCertificateContextToStore(hCertStore, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        printf("Add certificate success!\n");
    }
    else {
        printf("Adding cert is bad\n");
    }
    // close the certificate file
    if (NULL != certFileHandle) CloseHandle(certFileHandle);
}



