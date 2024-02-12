#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <memory>
using std::string;
using std::cin;
using std::cout;
using std::endl;
using std::cerr;
using std::ifstream;


#include <locale>


#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/shake.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::SHA224;
using CryptoPP::SHA256;
using CryptoPP::SHA384;
using CryptoPP::SHA512;
using CryptoPP::SHA3_224;
using CryptoPP::SHA3_256;
using CryptoPP::SHA3_384;
using CryptoPP::SHA3_512;
using CryptoPP::SHAKE128;
using CryptoPP::SHAKE256;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::HexEncoder;
using CryptoPP::HashTransformation;
string GetString(string fileName)
{
    string output;
    ifstream file;
    file.open(fileName);
    output.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return output;
}
void Output(int &data)
{
    int Choosen;
    cout<< "How do you want to display output:\n"
        << "1.Display in screen\n"
        << "2.Write on file\n"
        << "Enter the option: ";
    cin >> Choosen;
    data = Choosen;
    return ;

}
void OutputFile(string text)
{
    string FileName;
    cout << "Enter FileName:";
    cin.ignore();
    cin >> FileName;
    StringSource(text,true,new FileSink(FileName.data()));
}
void OutputDigest(string digest)
{
    int Show;
    cout << " Choose one option: \n"
         << " 1.To Screen\n"
         << " 2.To File\n"
         << " Enter the option: ";
    cin>> Show;
    switch(Show)
    {
        case 1:
        {
            cout<<"digest:" << digest << endl;
            return ;
        }
        case 2:
        {
            OutputFile(digest);
            return;
        }
    }
}
string GetInput()
{
    int choosen;
    cout << " How to get input:\n"
         << " 1.From screen:\n"
         << " 2.From File:\n"
         << " Enter the option: ";
    cin >> choosen;
    string input;
    switch (choosen)
    {
    case 1:
    {
        cout << "Please enter input: ";
        cin.ignore();
        getline(cin, input);
        return input;
        break;
    }
    case 2:
    {
        string filename;
        cout << "Please enter filename: ";
        cin >> filename;

        string input = GetString(filename);
        return input;
        break;
    }
    default:
        break;
    }
    return "";
}
int main ()
{

    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    int choosen;
    cout << "Choose one option :\n"
         << " 1.SHA224\n"
         << " 2.SHA256\n"
         << " 3.SHA384\n"
         << " 4.SHA512\n"
         << " 5.SHA3-224\n"
         << " 6.SHA3-256\n"
         << " 7.SHA3-384\n"
         << " 8.SHA3-512\n"
         << " 9.SHAKE128\n"
         << " 10.SHAKE256\n"
         << " Enter the option: ";
    cin>> choosen;
    switch (choosen)
    {
        case 1:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA224);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 2:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA256);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 3:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA384);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 4:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA512);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 5:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA3_224);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 6:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA3_256);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 7:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA3_384);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 8:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            hash.reset(new SHA3_512);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(hash->DigestSize());
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 9:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            int length;
            cout << "Enter the length hash:";
            cin>> length;
            hash.reset(new SHAKE128);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(length);
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
        case 10:
        {
            string msg = GetInput();
            std::unique_ptr<HashTransformation> hash;
            int length;
            cout << "Enter the length hash:";
            cin>> length;
            hash.reset(new SHAKE256);
            string digest;
            string encoded;
            auto BeginTime = std::chrono::high_resolution_clock::now();
            for(int i=1;i<=10000;i++)
            {
                hash->Update((const CryptoPP::byte*)msg.data(), msg.size());
                digest.resize(length);
                hash->Final((CryptoPP::byte*)&digest[0]);
            }
            auto EndTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
            double averageTime = static_cast<double>(duration) / 10000.0;
            StringSource(digest, true, new HexEncoder(new StringSink(encoded)));
            OutputDigest(encoded);
            cout << "Time: " << averageTime << " ms" << std::endl;
            break;
        }
    }

    
    
}