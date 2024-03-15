//-------------------------------------------------------------------
//   Copyright (C) Microsoft.  All rights reserved.

#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

// Link with the Crypt32.lib file.
#pragma comment (lib, "Crypt32")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//-------------------------------------------------------------------
//   Define the name of a certificate subject.
//   To use this program, the definition of SIGNER_NAME
//   must be changed to the name of the subject of
//   a certificate that has access to a private key. That certificate
//   must have either the CERT_KEY_PROV_INFO_PROP_ID or 
//   CERT_KEY_CONTEXT_PROP_ID property set for the context to 
//   provide access to the private signature key.

//-------------------------------------------------------------------
//    You can use a command similar to the following to create a 
//    certificate that can be used with this example:
//
//    makecert -n "cn=Test" -sk Test -ss my

//#define SIGNER_NAME L"test"
#define SIGNER_NAME L"all.cash.mephi.dron"

//-------------------------------------------------------------------
//    Define the name of the store where the needed certificate
//    can be found. 

#define CERT_STORE_NAME  L"MY"

//-------------------------------------------------------------------
//   Local function prototypes.
void MyHandleError(LPTSTR psz);
bool SignMessage(CRYPT_DATA_BLOB* pSignedMessageBlob, std::string message);
bool VerifySignedMessage(
    CRYPT_DATA_BLOB* pSignedMessageBlob,
    CRYPT_DATA_BLOB* pDecodedMessageBlob);

int _tmain(int argc, _TCHAR* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    CRYPT_DATA_BLOB SignedMessage;

    if (SignMessage(&SignedMessage, "gg"))
    {
        CRYPT_DATA_BLOB DecodedMessage;

        if (VerifySignedMessage(&SignedMessage, &DecodedMessage))
        {
            free(DecodedMessage.pbData);
        }

        free(SignedMessage.pbData);
    }

    _tprintf(TEXT("Press any key to exit."));
    _getch();
}

//-------------------------------------------------------------------
//    MyHandleError
void MyHandleError(LPTSTR psz)
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
    _ftprintf(stderr, TEXT("Program terminating. \n"));
} // End of MyHandleError

//-------------------------------------------------------------------
//    SignMessage
bool SignMessage(CRYPT_DATA_BLOB* pSignedMessageBlob, std::string message)
{
    bool fReturn = false;
    BYTE* pbMessage;
    DWORD cbMessage;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pSignerCert = 0;
    CRYPT_SIGN_MESSAGE_PARA  SigParams;
    DWORD cbSignedMessageBlob;
    BYTE* pbSignedMessageBlob = NULL;

    LPCSTR str1 = szOID_RSA_SHA1RSA;
    DWORD lenPsz = lstrlenA(str1);
    LPSTR pszOid = (LPSTR)malloc(lenPsz + 1);
    std::copy(str1, str1 + lenPsz, pszOid);
    pszOid[lenPsz] = 0;

    // Initialize the output pointer.
    pSignedMessageBlob->cbData = 0;
    pSignedMessageBlob->pbData = NULL;

    // The message to be signed.
    // Usually, the message exists somewhere and a pointer is
    // passed to the application.
    
    pbMessage = (BYTE*)malloc(message.length() + 1);
    std::copy(message.begin(), message.end(), pbMessage);
    pbMessage[message.length()] = 0;
    // Calculate the size of message. To include the 
    // terminating null character, the length is one more byte 
    // than the length returned by the strlen function.
    cbMessage = (lstrlen((TCHAR*)pbMessage) + 1) * sizeof(TCHAR);

    // Create the MessageArray and the MessageSizeArray.
    const BYTE* MessageArray[] = { pbMessage };
    DWORD_PTR MessageSizeArray[1];
    MessageSizeArray[0] = cbMessage;

    //  Begin processing. 
    printf(("The message to be signed is \"%s\".\n"),
        pbMessage);
    hCertStore = openStore();
    PCCERT_CONTEXT  pCertContext = NULL;
    int i = 0;
    std::vector<PCCERT_CONTEXT> certArray;
    while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
        DWORD reqLenStr = CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_SIMPLE_NAME_STR, NULL, NULL);
        LPWSTR strName = (LPWSTR)malloc(reqLenStr);
        CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_SIMPLE_NAME_STR, strName, reqLenStr);
        certArray.push_back(CertDuplicateCertificateContext(pCertContext));
        wprintf(L"%d %s\n", ++i, strName);
    }
    i = cin("Choose cert: ");

    pCertContext = certArray[i - 1];
    

    // Initialize the signature structure.
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pCertContext;
    SigParams.HashAlgorithm.pszObjId = pszOid;
    SigParams.HashAlgorithm.Parameters.cbData = NULL;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pCertContext;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;

    // First, get the size of the signed BLOB.
    if (CryptSignMessage(
        &SigParams,
        FALSE,
        1,
        MessageArray,
        MessageSizeArray,
        NULL,
        &cbSignedMessageBlob))
    {
        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
            cbSignedMessageBlob);
    }
    else
    {
        _tprintf(TEXT("Getting signed BLOB size failed"));
        goto exit_SignMessage;
    }

    // Allocate memory for the signed BLOB.
    if (!(pbSignedMessageBlob =
        (BYTE*)malloc(cbSignedMessageBlob)))
    {
        _tprintf(
            TEXT("Memory allocation error while signing."));
        goto exit_SignMessage;
    }

    // Get the signed message BLOB.
    if (CryptSignMessage(
        &SigParams,
        FALSE,
        1,
        MessageArray,
        MessageSizeArray,
        pbSignedMessageBlob,
        &cbSignedMessageBlob))
    {
        _tprintf(TEXT("The message was signed successfully. \n"));

        // pbSignedMessageBlob now contains the signed BLOB.
        fReturn = true;
    }
    else
    {
        _tprintf(TEXT("Error getting signed BLOB"));
        goto exit_SignMessage;
    }

exit_SignMessage:

    // Clean up and free memory as needed.
    if (pSignerCert)
    {
        CertFreeCertificateContext(pSignerCert);
    }

    if (hCertStore)
    {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    // Only free the signed message if a failure occurred.
    if (!fReturn)
    {
        if (pbSignedMessageBlob)
        {
            free(pbSignedMessageBlob);
            pbSignedMessageBlob = NULL;
        }
    }

    if (pbSignedMessageBlob)
    {
        pSignedMessageBlob->cbData = cbSignedMessageBlob;
        pSignedMessageBlob->pbData = pbSignedMessageBlob;
    }

    return fReturn;
}

//-------------------------------------------------------------------
//    VerifySignedMessage
//
//    Verify the message signature. Usually, this would be done in 
//    a separate program. 
bool VerifySignedMessage(
    CRYPT_DATA_BLOB* pSignedMessageBlob,
    CRYPT_DATA_BLOB* pDecodedMessageBlob)
{
    bool fReturn = false;
    PCCERT_CONTEXT hCertContext = NULL;
    DWORD cbDecodedMessageBlob;
    BYTE* pbDecodedMessageBlob = NULL;
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

    // Initialize the output.
    pDecodedMessageBlob->cbData = 0;
    pDecodedMessageBlob->pbData = NULL;

    // Initialize the VerifyParams data structure.
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;

    // First, call CryptVerifyMessageSignature to get the length 
    // of the buffer needed to hold the decoded message.
    if (CryptVerifyMessageSignature(
        &VerifyParams,
        0,
        pSignedMessageBlob->pbData,
        pSignedMessageBlob->cbData,
        NULL,
        &cbDecodedMessageBlob,
        &hCertContext))
    {
        _tprintf(TEXT("%d bytes needed for the decoded message.\n"),
            cbDecodedMessageBlob);

    }
    else
    {
        _tprintf(TEXT("Verification message failed. \n"));
        goto exit_VerifySignedMessage;
    }

    //---------------------------------------------------------------
    //   Allocate memory for the decoded message.
    if (!(pbDecodedMessageBlob =
        (BYTE*)malloc(cbDecodedMessageBlob)))
    {
        _tprintf(
            TEXT("Memory allocation error allocating decode BLOB."));
        goto exit_VerifySignedMessage;
    }

    //---------------------------------------------------------------
    // Call CryptVerifyMessageSignature again to verify the signature
    // and, if successful, copy the decoded message into the buffer. 
    // This will validate the signature against the certificate in 
    // the local store.
    if (CryptVerifyMessageSignature(
        &VerifyParams,
        0,
        pSignedMessageBlob->pbData,
        pSignedMessageBlob->cbData,
        pbDecodedMessageBlob,
        &cbDecodedMessageBlob,
        NULL))
    {
        printf(("The verified message is \"%s\".\n"),
            pbDecodedMessageBlob);

        fReturn = true;
    }
    else
    {
        _tprintf(TEXT("Verification message failed. \n"));
    }

exit_VerifySignedMessage:
    // If something failed and the decoded message buffer was 
    // allocated, free it.
    if (!fReturn)
    {
        if (pbDecodedMessageBlob)
        {
            free(pbDecodedMessageBlob);
            pbDecodedMessageBlob = NULL;
        }
    }

    // If the decoded message buffer is still around, it means the 
    // function was successful. Copy the pointer and size into the 
    // output parameter.
    if (pbDecodedMessageBlob)
    {
        pDecodedMessageBlob->cbData = cbDecodedMessageBlob;
        pDecodedMessageBlob->pbData = pbDecodedMessageBlob;
    }

    return fReturn;
}