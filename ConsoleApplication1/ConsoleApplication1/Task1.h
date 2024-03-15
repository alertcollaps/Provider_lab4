#pragma once
#pragma comment(lib, "crypt32.lib")
#include <tchar.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>


void MyHandleError(std::string s);
LPSTR strToLPSTR(std::string str);
int cin(std::string str);

//-------------------------------------------------------------------
//   This program use this additional #define statement. 

#define CERT_SUBJECT_NAME "This certificate user"
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
//-------------------------------------------------------------------
// This program uses the function ByteToStr to convert an array
// of BYTEs to a char string. 

void ByteToStr(
    DWORD cb,
    void* pv,
    LPSTR sz)
    //-------------------------------------------------------------------
    // Parameters passed are:
    //    pv is the array of BYTEs to be converted.
    //    cb is the number of BYTEs in the array.
    //    sz is a pointer to the string to be returned.

{
    //-------------------------------------------------------------------
    //  Declare and initialize local variables.

    BYTE* pb = (BYTE*)pv; // local pointer to a BYTE in the BYTE array
    DWORD i;               // local loop counter
    int b;                 // local variable

    //-------------------------------------------------------------------
    //  Begin processing loop.

    for (i = 0; i < cb; i++)
    {
        b = (*pb & 0xF0) >> 4;
        *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
        b = *pb & 0x0F;
        *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
        pb++;
    }
    *sz++ = 0;
}

LPSTR strToLPSTR(std::string str) {
    LPSTR lpstr = (char*)malloc((str.length() + 1));
    int i = 0;
    for (std::string::iterator it = str.begin(); it != str.end(); ++it) {
        *(lpstr + i) = *it;
        ++i;
    }
    *(lpstr + i) = 0;
    
    return lpstr;
}



void Task1(HCRYPTPROV  hCryptProv)
{
    //-------------------------------------------------------------------
    // Declare and initialize variables 

    // Declare and initialize a CERT_RDN_ATTR array.
    // In this code, only one array element is used.
    //std::string strObjId = "2.5.4.3";
    
    //DWORD MY_ENCODING_TYPE = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);
    CERT_RDN_ATTR rgNameAttr[] = {
            strToLPSTR("2.5.4.3"),                             // pszObjId 
            CERT_RDN_PRINTABLE_STRING,             // dwValueType
            strlen(CERT_SUBJECT_NAME),             // value.cbData
            (BYTE*)CERT_SUBJECT_NAME };             // value.pbData

    //-------------------------------------------------------------------
    // Declare and initialize a CERT_RDN array.
    // In this code, only one array element is used.

    CERT_RDN rgRDN[] = {
             1,                 // rgRDN[0].cRDNAttr
             &rgNameAttr[0] };   // rgRDN[0].rgRDNAttr

    //-------------------------------------------------------------------
    // Declare and initialize a CERT_NAME_INFO structure.

    CERT_NAME_INFO Name = {
               1,                  // Name.cRDN
               rgRDN };             // Name.rgRDN

    //-------------------------------------------------------------------
    // Declare and initialize all other variables and structures.

    CERT_REQUEST_INFO  CertReqInfo = {};
    CERT_NAME_BLOB  SubjNameBlob = {};
    DWORD  cbNameEncoded = {};
    BYTE* pbNameEncoded = {};
    //HCRYPTPROV  hCryptProv;
    DWORD  cbPublicKeyInfo = {};
    CERT_PUBLIC_KEY_INFO* pbPublicKeyInfo = {};
    DWORD  cbEncodedCertReqSize = {};
    CRYPT_OBJID_BLOB  Parameters = {};
    CRYPT_ALGORITHM_IDENTIFIER  SigAlg = {};
    BYTE* pbSignedEncodedCertReq = {};
    char* pSignedEncodedCertReqBlob;

    //-------------------------------------------------------------------
    //    Begin processing.

    if (CryptEncodeObject(
        MY_ENCODING_TYPE,     // Encoding type
        X509_NAME,            // Structure type
        &Name,                // Address of CERT_NAME_INFO structure
        NULL,                 // pbEncoded
        &cbNameEncoded))      // pbEncoded size
    {
        printf("The first call to CryptEncodeObject succeeded. \n");
    }
    else
    {
        MyHandleError("The first call to CryptEncodeObject failed. \n"
            "A public/private key pair may not exit in the container. \n");
    }
    //-------------------------------------------------------------------
    //     Allocate memory for the encoded name.

    if (!(pbNameEncoded = (BYTE*)malloc(cbNameEncoded)))
        MyHandleError("The pbNamencoded malloc operation failed. \n");

    //-------------------------------------------------------------------
    //  Call CryptEncodeObject to do the actual encoding of the name.

    if (CryptEncodeObject(
        MY_ENCODING_TYPE,    // Encoding type
        X509_NAME,           // Structure type
        &Name,               // Address of CERT_NAME_INFO structure
        pbNameEncoded,       // pbEncoded
        &cbNameEncoded))     // pbEncoded size
    {
        printf("The object is encoded. \n");
    }
    else
    {
        free(pbNameEncoded);
        MyHandleError("The second call to CryptEncodeObject failed. \n");
    }
    //-------------------------------------------------------------------
    // Set the subject member of CertReqInfo to point to 
    // a CERT_NAME_INFO structure that 
    // has been initialized with the data from cbNameEncoded
    // and pbNameEncoded.

    SubjNameBlob.cbData = cbNameEncoded;
    SubjNameBlob.pbData = pbNameEncoded;
    CertReqInfo.Subject = SubjNameBlob;

    //-------------------------------------------------------------------
    // Generate custom information. This step is not
    // implemented in this code.

    CertReqInfo.cAttribute = 0;
    CertReqInfo.rgAttribute = NULL;
    CertReqInfo.dwVersion = CERT_REQUEST_V1;

    //-------------------------------------------------------------------
    //    Call CryptExportPublicKeyInfo to return an initialized
    //    CERT_PUBLIC_KEY_INFO structure.
    //    First, get a cryptographic provider.

    //-------------------------------------------------------------------
    // Call CryptExportPublicKeyInfo to get the size of the returned
    // information.

    if (CryptExportPublicKeyInfo(
        hCryptProv,            // Provider handle
        AT_SIGNATURE,          // Key spec
        MY_ENCODING_TYPE,      // Encoding type
        NULL,                  // pbPublicKeyInfo
        &cbPublicKeyInfo))     // Size of PublicKeyInfo
    {
        printf("The keyinfo structure is %d bytes. \n", cbPublicKeyInfo);
    }
    else
    {
        free(pbNameEncoded);
        MyHandleError("The first call to CryptExportPublickKeyInfo failed. \n"
            "The probable cause is that \n"
            "there is no key pair in the key container. \n");
    }
    //-------------------------------------------------------------------
    // Allocate the necessary memory.

    if (pbPublicKeyInfo =
        (CERT_PUBLIC_KEY_INFO*)malloc(cbPublicKeyInfo))
    {
        printf("Memory is allocated for the public key structure. \n");
    }
    else
    {
        free(pbNameEncoded);
        MyHandleError("Memory allocation failed. \n");
    }
    //-------------------------------------------------------------------
    // Call CryptExportPublicKeyInfo to get pbPublicKeyInfo.

    if (CryptExportPublicKeyInfo(
        hCryptProv,            // Provider handle
        AT_SIGNATURE,          // Key spec
        MY_ENCODING_TYPE,      // Encoding type
        pbPublicKeyInfo,       // pbPublicKeyInfo
        &cbPublicKeyInfo))     // Size of PublicKeyInfo
    {
        printf("The key has been exported. \n");
    }
    else
    {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        MyHandleError("The second call to CryptExportPublicKeyInfo failed. \n");
    }
    //-------------------------------------------------------------------
    // Set the SubjectPublicKeyInfo member of the 
    // CERT_REQUEST_INFO structure to point to the CERT_PUBLIC_KEY_INFO 
    // structure created.

    CertReqInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;

    memset(&Parameters, 0, sizeof(Parameters));
    SigAlg.pszObjId = strToLPSTR(szOID_OIWSEC_sha1RSASign);
    SigAlg.Parameters = Parameters;

    //-------------------------------------------------------------------
    // Call CryptSignAndEncodeCertificate to get the size of the
    // returned BLOB. The dwKeySpec argument should match the KeySpec
    // (AT_SIGNATURE or AT_KEYEXCHANGE) used to create the private
    // key. Here, AT_KEYEXCHANGE is assumed.

    if (CryptSignAndEncodeCertificate(
        hCryptProv,                      // Crypto provider
        AT_KEYEXCHANGE,                  // Key spec
        MY_ENCODING_TYPE,                // Encoding type
        X509_CERT_REQUEST_TO_BE_SIGNED,  // Structure type
        &CertReqInfo,                    // Structure information
        &SigAlg,                         // Signature algorithm
        NULL,                            // Not used
        NULL,                            // pbSignedEncodedCertReq
        &cbEncodedCertReqSize))          // Size of certificate 
                                         // required
    {
        printf("The size of the encoded certificate is set. \n");
    }
    else
    {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        MyHandleError("First call to CryptSignandEncode failed. \n");
    }
    //-------------------------------------------------------------------
    // Allocate memory for the encoded certificate request.

    if (pbSignedEncodedCertReq = (BYTE*)malloc(cbEncodedCertReqSize))
    {
        printf("Memory has been allocated.\n");
    }
    else
    {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        MyHandleError("The malloc operation failed. \n");
    }
    //-------------------------------------------------------------------
    // Call CryptSignAndEncodeCertificate to get the 
    // returned BLOB.

    if (CryptSignAndEncodeCertificate(
        hCryptProv,                     // Crypto provider
        AT_KEYEXCHANGE,                 // Key spec
        MY_ENCODING_TYPE,               // Encoding type
        X509_CERT_REQUEST_TO_BE_SIGNED, // Struct type
        &CertReqInfo,                   // Struct info        
        &SigAlg,                        // Signature algorithm
        NULL,                           // Not used
        pbSignedEncodedCertReq,         // Pointer
        &cbEncodedCertReqSize))         // Length of the message
    {
        printf("The message is encoded and signed. \n");
    }
    else
    {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        free(pbSignedEncodedCertReq);
        MyHandleError("The second call to CryptSignAndEncode failed. \n");
    }
    //-------------------------------------------------------------------
    // View the signed and encoded certificate request BLOB.

    pSignedEncodedCertReqBlob =
        new char[(cbEncodedCertReqSize * 2) + 1];

    //-------------------------------------------------------------------
    // Call ByteToStr, one of the general purpose functions, to convert 
    // the byte BLOB to ASCII hexadecimal format. 

    ByteToStr(cbEncodedCertReqSize,
        pbSignedEncodedCertReq,
        pSignedEncodedCertReqBlob);

    //-------------------------------------------------------------------
    // Print the string.
    printf("The string created is: \n");
    printf("%s\n", pSignedEncodedCertReqBlob);

    //-------------------------------------------------------------------
    // Free memory.

    free(pbNameEncoded);
    free(pbPublicKeyInfo);
    free(pbSignedEncodedCertReq);
    CryptReleaseContext(hCryptProv, 0);

    printf("\nMemory freed. Program ran without error. \n");
} // End of main

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to  
//  the standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(std::string s)
{
    fprintf(stderr, "An error occurred in running the program. \n");
    fprintf(stderr, "%s\n", s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError

void printTypes() {
    std::cout << "\n-----Task 1-----" << std::endl;
    printf("Listing Available Provider Types:\n");

    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;

    while (CryptEnumProviderTypes(dwIndex, NULL, 0, &dwType, NULL, &cbName))
    {
        if (!cbName) break;
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return;
        if (!CryptEnumProviderTypes(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
        {
            std::cout << "CryptEnumProvidersTypes" << std::endl;
            return;
        }

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());

        std::cout << "--------------------------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }
}

LPTSTR printAndGetProviders(DWORD type) {
    std::cout << "\n-----Task 2-----" << std::endl;
    printf("Listing Available Providers:\n");
    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;
    LPTSTR pszNameOut;

    int i = 1;
    std::vector<LPTSTR> listNamesProviders;
    while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
    {
        if (dwType != type) {
            ++dwIndex;
            continue;
        }
        if (!cbName) break;
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;
        if (!(pszNameOut = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;

        if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
        {
            std::cout << "CryptEnumProviders" << std::endl;
            return NULL;
        }
        lstrcpy(pszNameOut, pszName);

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());
        listNamesProviders.push_back(pszNameOut);

        std::cout << "----------------" << i++ << "----------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }

    i = cin("Choose provider name: ");
    for (int a = 0; a < listNamesProviders.size(); a++) {
        if (i - 1 == a) {
            continue;
        }
        LocalFree(listNamesProviders[a]);
    }

    return listNamesProviders[i - 1];
}

HCRYPTKEY genKeyExchange(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKeyExchange = 0;
    // Контекст с ключевым контейнером доступен,
    // попытка получения дескриптора ключа подписи
    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_KEYEXCHANGE,                   // Спецификация ключа
        &hKeyExchange))                         // Дескриптор ключа
    {
        printf("A AT_KEYEXCHANGE key is available.\n");
    }
    else
    {
        printf("No AT_KEYEXCHANGE key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The AT_KEYEXCHANGE key does not exist.\n");
        printf("Creating a AT_KEYEXCHANGE key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_KEYEXCHANGE,
            0, //flag
            &hKeyExchange))
        {
            printf("Error occurred creating a exchange key.\n");
            exit(1);
        }
        printf("Created a exchange key pair.\n");

    }

    return hKeyExchange;
}
HCRYPTKEY genKeySign(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKeySign = 0;

    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_SIGNATURE,                   // Спецификация ключа
        &hKeySign))                         // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.

        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            //exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_SIGNATURE,
            CRYPT_EXPORTABLE, //flag
            &hKeySign))
        {
            printf("Error occurred creating a signature key.\n");
            exit(1);
        }
        printf("Created a signature key pair.\n");

    }





    return hKeySign;
}

HCRYPTPROV getProvider(LPTSTR pszName, DWORD type, LPCWSTR nameContainer) {

    HCRYPTPROV hCryptProv;
    BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.
    if (CryptAcquireContext(&hCryptProv, nameContainer, pszName, type, 0)) {
        printf("Context has been poluchen\n");

    }
    else {
        if (CryptAcquireContext(
            &hCryptProv,
            nameContainer,
            pszName,
            type,
            CRYPT_NEWKEYSET))
        {
            printf("A new key container has been created.\n");
        }
        else
        {
            printf("Could not create a new key container.\n");
            exit(1);
        }
    }

    DWORD cbData;

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_NAME,
        pbData,
        &cbData,
        0))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Provider name: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP name. \n");
        exit(1);
    }

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_UNIQUE_CONTAINER,
        pbData,
        &cbData,
        0))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Uniqe name of container: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP admin pin. \n");
        exit(1);
    }
    genKeyExchange(hCryptProv, pszName, type);
    genKeySign(hCryptProv, pszName, type);
    return hCryptProv;
}

int cin(std::string str) {
    std::cout << str;
    int type = 1;
    std::cin >> type;

    return type;
}