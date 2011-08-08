// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include "certificate.hpp"
#include <iostream>

namespace w32 { namespace cr {

    ::PCCERT_CONTEXT acquire ()
    {
        HRESULT hr = 0;
        HCRYPTPROV hProv = NULL;
        PCCERT_CONTEXT p = 0;
        HCRYPTKEY hKey = 0;
        CERT_NAME_BLOB sib = { 0 };
        BOOL AX = 0;
        
        try
        {
            char cb[1000] = {0};
            sib.pbData = (BYTE*)cb; 
            sib.cbData = 1000;
            wchar_t*    szSubject= L"CN=Certificate";
            if (!CertStrToNameW(CRYPT_ASN_ENCODING, szSubject,0,0,sib.pbData,&sib.cbData,NULL))
                throw;
            wchar_t* pszKeyContainerName = L"Container";
            if (!CryptAcquireContextW(&hProv,pszKeyContainerName,MS_DEF_PROV_W,PROV_RSA_FULL,CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
            {
                hr = GetLastError();
                if (GetLastError() == NTE_EXISTS)
                {
                    if (!CryptAcquireContextW(&hProv,pszKeyContainerName,MS_DEF_PROV_W,PROV_RSA_FULL,CRYPT_MACHINE_KEYSET))
                    {
                        throw;
                    }
                }
                else
                    throw;
            }
            
            if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey))
                throw;
            
            CRYPT_KEY_PROV_INFO kpi = {0};
            kpi.pwszContainerName = pszKeyContainerName;
            kpi.pwszProvName = MS_DEF_PROV_W;
            kpi.dwProvType = PROV_RSA_FULL;
            kpi.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
            kpi.dwKeySpec = AT_KEYEXCHANGE;
            
            SYSTEMTIME et;
            GetSystemTime(&et);
            et.wYear += 1;
            
            CERT_EXTENSIONS exts = {0};
            p = CertCreateSelfSignCertificate(hProv,&sib,0,&kpi,NULL,NULL,&et,&exts);
            AX = CryptFindCertificateKeyProvInfo(p,CRYPT_FIND_MACHINE_KEYSET_FLAG,NULL) ;
        }
        catch(...)
        {
        }
        
        // cleanup.
        if (hKey)
            CryptDestroyKey(hKey);
        hKey = 0;
        if (hProv)
            CryptReleaseContext(hProv,0);
        hProv = 0;
        // return certificate.
        return (p);
    }

    void release ( ::PCCERT_CONTEXT object )
    {
        const ::BOOL result = ::CertFreeCertificateContext(object);
        if ( result == FALSE )
        {
            const ::DWORD error = ::GetLastError();
            std::cerr
                << "CertFreeCertificateContext(): " << error
                << std::endl;
        }
    }

} }
