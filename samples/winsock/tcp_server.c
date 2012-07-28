// Пример простого TCP-эхо-сервера

#include <stdio.h>
#include <winsock2.h> // Wincosk2.h должен быть раньше windows!
#include <windows.h>

#define MY_PORT 1234 // Порт, который слушает сервер 666

// макрос для печати количества активных пользователей
#define PRINTNUSERS if (nclients) printf("%d user on-line\n", nclients); \
        else printf("No User on line\n");

// прототип функции, обслуживающий подключившихся пользователей
DWORD WINAPI SexToClient(LPVOID client_socket);

// глобальная переменная - количество активных пользователей
int nclients = 0;

int main(int argc, char* argv[])
{
    char buff[1024]; // Буфер для различных нужд

    printf("TCP SERVER DEMO\n");
    // Шаг 1 - Инициализация Библиотеки Сокетов
    // т.к. возвращенная функцией информация не используется
    // ей передается указатель на рабочий буфер, преобразуемый к указателю
    // на структуру WSADATA.
    // Такой прием позволяет сэкономить одну переменную, однако, буфер
    // должен быть не менее полкилобайта размером (структура WSADATA
    // занимает 400 байт)
    if (WSAStartup(0x0202, (WSADATA *)&buff[0]))
    {
        // Ошибка!
        printf("Error WSAStartup %d\n", WSAGetLastError());
        return -1;
    }

    // Шаг 2 - создание сокета
    SOCKET mysocket;
    // AF_INET - сокет Интернета
    // SOCK_STREAM - потоковый сокет (с установкой соединения)
    // 0 - по умолчанию выбирается TCP протокол
    if ((mysocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        // Ошибка!
        printf("Error socket %d\n", WSAGetLastError());
        WSACleanup(); // Деиницилизация библиотеки Winsock
        return -1;
    }

    // Шаг 3 - связывание сокета с локальным адресом
    sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(MY_PORT); // не забываем о сетевом порядке!!!
    local_addr.sin_addr.s_addr = 0; // сервер принимает подключения
                                    // на все свои IP-адреса

    // вызываем bind для связывания
    if (bind(mysocket, (sockaddr *)&local_addr, sizeof(local_addr)))
    {
        // Ошибка
        printf("Error bind %d\n", WSAGetLastError());
        closesocket(mysocket); // закрываем сокет!
        WSACleanup();
        return -1;
    }

    // Шаг 4 - ожидание подключений
    // размер очереди - 0x100
    if (listen(mysocket, 0x100))
    {
        // Ошибка
        printf("Error listen %d\n", WSAGetLastError());
        closesocket(mysocket);
        WSACleanup();
        return -1;
    }

    printf("Waiting for connections...\n");

    // Шаг 5 - извлекаем сообщение из очереди
    SOCKET client_socket; // сокет для клиента
    sockaddr_in client_addr; // адрес клиента (заполняется системой)

    // функции accept необходимо передать размер структуры
    int client_addr_size = sizeof(client_addr);

    // цикл извлечения запросов на подключение из очереди
    while ((client_socket = accept(mysocket, (sockaddr *)&client_addr, \
           &client_addr_size)))
    {
        nclients++; // увеличиваем счетчик подключившихся клиентов

        // пытаемся получить имя хоста
        HOSTENT *hst;
        hst = gethostbyaddr((char *)&client_addr. sin_addr.s_addr, 4, AF_INET);

        // вывод сведений о клиенте
        printf("+%s [%s] new connect!\n",
        (hst) ? hst->h_name : "", inet_ntoa(client_addr.sin_addr));
        PRINTNUSERS

        // Вызов нового потока для обслужвания клиента
        // Да, для этого рекомендуется использовать _beginthreadex
        // но, поскольку никаких вызовов функций стандартной Си библиотеки
        // поток не делает, можно обойтись и CreateThread
        DWORD thID;
        CreateThread(NULL, NULL, SexToClient, &client_socket, NULL, &thID);
    }
    return 0;
}

// Эта функция создается в отдельном потоке
// и обсуживает очередного подключившегося клиента независимо от остальных
DWORD WINAPI SexToClient(LPVOID client_socket)
{
    SOCKET my_sock;
    my_sock = ((SOCKET *)client_socket)[0];
    char buff[20 * 1024];
    #define sHELLO "Hello, Sailor\r\n"

    // отправляем клиенту приветствие
    send(my_sock, sHELLO, sizeof(sHELLO), 0);

    // цикл эхо-сервера: прием строки от клиента и возвращение ее клиенту
    int bytes_recv;
    while ((bytes_recv = recv(my_sock, &buff[0], sizeof(buff), 0)) &&
    bytes_recv != SOCKET_ERROR)
    send(my_sock, &buff[0], bytes_recv, 0);

    // если мы здесь, то произошел выход из цикла по причине
    // возращения функцией recv ошибки - соединение с клиентом разорвано
    nclients--; // уменьшаем счетчик активных клиентов
    printf("-disconnect\n"); PRINTNUSERS

    // закрываем сокет
    closesocket(my_sock);
    return 0;
}
