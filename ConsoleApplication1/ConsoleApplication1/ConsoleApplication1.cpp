// ConsoleApplication1.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <iostream>
#include <string>
#include "Task1.h"
#include "Task2.h"
#include "TT.h"

int main()
{
    //Команда в PowerShell
    //-> New-SelfSignedCertificate -DnsName all.cash.mephi.dron -CertStoreLocation cert:\LocalMachine\My
    
    std::cout << "Hello World!\n";
    LPCWSTR nameCont = L"Alex";
    printTypes();
    int type = cin("Choose type: ");
    LPTSTR nameProv = printAndGetProviders(type);
    HCRYPTPROV hCrProv = getProvider(nameProv, type, nameCont);
    Task1(hCrProv);
    
    Task2();
    CRYPT_DATA_BLOB SignedMessage;
    SignMessage(&SignedMessage, "Hello Alex");
    CRYPT_DATA_BLOB DecodedMessage;

    if (VerifySignedMessage(&SignedMessage, &DecodedMessage))
    {
        free(DecodedMessage.pbData);
    }

    free(SignedMessage.pbData);
    return 0;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
