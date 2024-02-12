#include "cryptopp/cryptlib.h"
#include "cryptopp/x509cert.h"
#include "cryptopp/secblock.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/pem.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <memory>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/asn.h"
#include "cryptopp/pem.h"
#include "cryptopp/pem_common.h"
#endif
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <locale>
#include <iostream>
#include <string>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::DSA;
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::HexEncoder;
using CryptoPP::OID;
using CryptoPP::RSA;
using CryptoPP::SecByteBlock;
using CryptoPP::SHA1;
using CryptoPP::SHA256;
using CryptoPP::SHA384;
using CryptoPP::SHA512;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::X509Certificate;
using CryptoPP::X509PublicKey;
int filePath(const std::string &path)
{
    std::string extension = path.substr(path.find_last_of(".") + 1);

    if (extension == "pem")
    {
        return 1;
    }
    else
        return 2;
}
string findSubjectPublicKey(const OID &algothirm)
{
    if (algothirm == CryptoPP::ASN1::id_ecPublicKey())
    {
        return "ecPublicKey";
    }
    else
        return "RSAEncryption";
}
inline bool IsRSAAlgorithm(const OID &alg)
{
    return alg == CryptoPP::ASN1::rsaEncryption() ||        // rsaEncryption is most popular in spki
           alg == OID(1) + 2 + 840 + 113549 + 1 + 1 + 10 || // RSA-PSS
           (alg >= CryptoPP::ASN1::rsaEncryption() && alg <= CryptoPP::ASN1::sha512_256WithRSAEncryption());
}
inline bool IsECDSAAlgorithm(const OID &alg)
{
    return alg==CryptoPP::ASN1::id_ecPublicKey();
}
int FindECDSAAlogorithm(const OID &alg)
{
    if (alg == id_ecdsaWithSHA1)
        return 1;
    if (alg == id_ecdsaWithSHA256)
        return 2;
    if (alg == id_ecdsaWithSHA384)
        return 3;
    if (alg == id_ecdsaWithSHA512)
        return 4;
    return 0;
}
inline bool IsECPrimeFieldAlgorithm(const OID& alg)
{
    if (alg != CryptoPP::ASN1::id_ecPublicKey())
        return false;
    
    return alg == CryptoPP::ASN1::prime_field() ||
        (alg >= CryptoPP::ASN1::secp112r1() && alg <= CryptoPP::ASN1::secp521r1()) ||
        (alg >= CryptoPP::ASN1::secp192r1() && alg <= CryptoPP::ASN1::secp256r1()) ||  // not a typo
        (alg >= CryptoPP::ASN1::brainpoolP160r1() && alg <= CryptoPP::ASN1::brainpoolP512r1());
}

void Decode(const char *filename, CryptoPP::BufferedTransformation &bt)
{
    FileSource file(filename, true);
    file.TransferTo(bt);
    bt.MessageEnd();
}
void DecodeRSAPublicKey(string filename, RSA::PublicKey &key)
{
    CryptoPP::ByteQueue queue;

    Decode(filename.data(), queue);
    key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
}
void DecodeDSAPublicKey(string filename, DSA::PublicKey &key)
{
    CryptoPP::ByteQueue queue;
    Decode(filename.data(), queue);
    key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
}
void EncodeSHA1PublicKey(const string &filename, const X509PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true).Ref());
}
void EncodeSHA256PublicKey(const string &filename, const X509PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true).Ref());
}
void EncodeSHA384PublicKey(const string &filename, const X509PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true).Ref());
}
void EncodeSHA512PublicKey(const string &filename, const X509PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true).Ref());
}
void DecodeSHA1PublicKey(const string &filename, ECDSA<ECP, SHA1>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true).Ref());
}
void DecodeSHA256PublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true).Ref());
}
void DecodeSHA384PublicKey(const string &filename, ECDSA<ECP, SHA384>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true).Ref());
}
void DecodeSHA512PublicKey(const string &filename, ECDSA<ECP, SHA512>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true).Ref());
}
void Encode(const string &filename, const CryptoPP::BufferedTransformation &bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

string GetPublicKeyAlgorithm(const CryptoPP::X509PublicKey &key)
{
    string mistake = "Public Key is not Valid";
    string result = OidToNameLookup(key.GetAlgorithmID(), mistake.data());
    return result;
}

void EncodeKey(CryptoPP::BufferedTransformation &bt, const X509PublicKey &key)
{
    key.DEREncode(bt);
    bt.MessageEnd();
}
void PEM_DEREncode(CryptoPP::BufferedTransformation &bt, const X509PublicKey &key)
{
    key.DEREncode(bt);
    bt.MessageEnd();
}
void Decode(const string &filename, CryptoPP::BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
void DecodePublicKey(const string &filename, RSA::PublicKey &key)
{
    CryptoPP::ByteQueue queue;

    Decode(filename, queue);
    key.BERDecodePublicKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());
}
bool compare(string s1,string s2)
{
    if(s1.size() != s2.size())
    {
        if(s1.size() > s2.size())return true;
        else return false;
    }
    else 
    {
        for(int i = 0 ; i <= s1.size() ; i++)
        {
            if(s1[i] == s2[i])continue;
            return(s1[i] > s2[i]);
        }
    }
}
void findPublicKeyCurve(string data)
{
    
    string s224=std::to_string(pow(2,224));
    while(s224.back() != '.')s224.pop_back();
    string s256=std::to_string(pow(2,256));
    while(s256.back() != '.')s256.pop_back();
    string s384=std::to_string(pow(2,384));
    while(s384.back() != '.')s384.pop_back();
    string s521=std::to_string(pow(2,521));
    while(s521.back() != '.')s521.pop_back();
    if(compare(s224,data))
    {
        cout << "NIST Curve: P-224"<<endl;
        return ;
    }
    if(compare(s256,data))
    {
        cout << "NIST Curve: P-256"<<endl;
        return ;
    }
    if(compare(s384,data))
    {
        cout << "NIST Curve: P-384"<<endl;
        return ;
    }
    if(compare(s521,data))
    {
        cout << "NIST Curve: P-521"<<endl;
        return ;
    }


}
void findPublicKeyInfo(const CryptoPP::X509PublicKey &key)
{
    cout << "Public Key Info:" << endl; 
    const OID &algorithm = key.GetAlgorithmID();
    string algoName = OidToNameLookup(algorithm);
    cout<<"Public Key Algorithm:"<<" "<<algoName<<endl;
    string filename = "testIn.der";
    string fileName="example.txt";
    string data;
    std::ofstream myfile;
    if (IsRSAAlgorithm(algorithm))
    {

        CryptoPP::ByteQueue queue;
        key.DEREncodePublicKey(queue);
        string data;
        Encode(filename, queue);
        RSA::PublicKey publicKey;
        DecodeRSAPublicKey(filename, publicKey);
        cout << "modulus: "<< std::hex << publicKey.GetModulus() << endl;
        cout << "Exponent:" << publicKey.GetPublicExponent()  << endl;;
    }
    else 
    {
        if(FindECDSAAlogorithm(algorithm)==1)
        {
            ECDSA<ECP, SHA1>::PublicKey publicKey;
            EncodeSHA1PublicKey(filename, key);
            DecodeSHA1PublicKey(filename, publicKey);
            cout << "Pub:" << endl;
            cout << std::hex << publicKey.GetPublicElement().x;
            cout << std::hex << publicKey.GetPublicElement().y << endl;
            myfile.open(fileName);
            myfile<<publicKey.GetGroupParameters().GetCurve().GetField().GetModulus();
            myfile.close();
            FileSource(fileName.data(),true,new StringSink(data));
        }
        if(FindECDSAAlogorithm(algorithm)==2)
        {
            ECDSA<ECP, SHA256>::PublicKey publicKey;
            EncodeSHA256PublicKey(filename, key);
            DecodeSHA256PublicKey(filename, publicKey);
            cout << "Pub:" << endl;
            cout << std::hex << publicKey.GetPublicElement().x;
            cout << std::hex << publicKey.GetPublicElement().y << endl;
            myfile.open(fileName);
            myfile<<publicKey.GetGroupParameters().GetCurve().GetField().GetModulus();
            myfile.close();
            FileSource(fileName.data(),true,new StringSink(data));

        }
        if(FindECDSAAlogorithm(algorithm)==3)
        {
            ECDSA<ECP, SHA384>::PublicKey publicKey;
            EncodeSHA384PublicKey(filename, key);
            DecodeSHA384PublicKey(filename, publicKey);
            cout << "Pub:" << endl;
            cout << std::hex << publicKey.GetPublicElement().x;
            cout << std::hex << publicKey.GetPublicElement().y << endl;
            myfile.open(fileName);
            myfile<<publicKey.GetGroupParameters().GetCurve().GetField().GetModulus();
            myfile.close();
            FileSource(fileName.data(),true,new StringSink(data));
        }
        if(FindECDSAAlogorithm(algorithm)==4)
        {
            ECDSA<ECP, SHA512>::PublicKey publicKey;
            EncodeSHA512PublicKey(filename, key);
            DecodeSHA512PublicKey(filename, publicKey);
            cout << "Pub:" << endl;
            cout << std::hex << publicKey.GetPublicElement().x;
            cout << std::hex << publicKey.GetPublicElement().y << endl;
            myfile.open(fileName);
            myfile<<publicKey.GetGroupParameters().GetCurve().GetField().GetModulus();
            myfile.close();
            FileSource(fileName.data(),true,new StringSink(data));
        }
        //Choose random mode 
        if(IsECDSAAlgorithm(algorithm))
        {
            ECDSA<ECP, SHA256>::PublicKey publicKey;
            EncodeSHA256PublicKey(filename, key);
            DecodeSHA256PublicKey(filename, publicKey);
            cout << "Pub:" << endl;
            cout << std::hex<< publicKey.GetPublicElement().x;
            cout << std::hex<< publicKey.GetPublicElement().y << endl;        
            myfile.open(fileName);
            myfile<<publicKey.GetGroupParameters().GetCurve().GetField().GetModulus();
            myfile.close();
            FileSource(fileName.data(),true,new StringSink(data));
        }
        findPublicKeyCurve(data);
    }
}

int main()
{
    // extern const std::string Certificate = argc[1];
    string Certificate;
    cout << "Enter the certificate name: \n";
    cin >> Certificate;
    int extension = filePath(Certificate);
    X509Certificate cert;
    
    auto const findSignatureInfo= [&]()
    {
        const OID &algorithm = cert.GetCertificateSignatureAlgorithm();
        string mistake = "Signature Algorithm is not Valid";
        string result = OidToNameLookup(algorithm, mistake.data());
        cout << "Signature Algorithm:"<< " " << result<<endl;
        const CryptoPP::SecByteBlock &signature = cert.GetCertificateSignature();
        const CryptoPP::SecByteBlock &toBeSigned = cert.GetToBeSigned();
        const CryptoPP::X509PublicKey &publicKey = cert.GetSubjectPublicKey();
        string data;
        StringSource(signature, signature.size(), true, new HexEncoder(new StringSink(data)));
        int cnt = 0;
        cout << "Signature Value is:";
        cout << data <<endl;
        return;
    };
    auto const CheckValidation= [&]()
    {
        AutoSeededRandomPool prng;
        if(!cert.Validate(prng,3))
        {
            cout <<"Certificate Validation is fail";
        }
        else cout<<"Certificate Validation is valid";
    };
    cout << extension ;
    switch (extension)
    {
    case 1:
    {
        FileSource ss(Certificate.data(), true);
        PEM_Load(ss, cert);
        break;
    }
    case 2:
    {
        CryptoPP::FileSource file(Certificate.data(), true);
        cert.BERDecode(file);
        break;
    }
    default:
        break;
    }
    auto const findOtherInfo=[&]()
    {
        cout << "Version: "<< cert.GetVersion() << endl;
        cout << "Serial Number: " << std::hex << cert.GetSerialNumber() << endl;
        cout << "Not Before: " << cert.GetNotBefore()<<endl;
        cout << "Not After: "  << cert.GetNotAfter()<<endl;
        cout << "Issuer: " << cert.GetIssuerDistinguishedName()<<endl;
        cout << "Subject: "<< cert.GetSubjectIdentities()<<endl;
        cout << "Subject Key: "<<cert.GetSubjectKeyIdentifier()<<endl;;
        cout << "Authority Key: "<<cert.GetAuthorityKeyIdentifier()<<endl;;
        cout << "Key Usage: "<<cert.GetSubjectKeyUsage()<<endl;
    };
    int choosen;
    cout << "Choose one option:\n "
         << " 1.Ceritficate Information\n "
         << " 2.Verify Information\n "
         << " Enter the option : ";
    cin>> choosen;
    switch(choosen)
    {
        case 1:
        {
            findOtherInfo();
            const X509PublicKey& publicKey = cert.GetSubjectPublicKey();
            findPublicKeyInfo(publicKey);
            findSignatureInfo();
            break;
        }
        case 2:
        {
            CheckValidation();
            break;
        }
        default: 
            break;
    }
}