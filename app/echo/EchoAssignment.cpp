#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {

  // Local variables
  const int BACKLOG_SIZE = 100; /* section Listen() - listen() parameter: define
                                   waiting queue size */
  char BUFFER[1024]; /* section Read() - read() parameter: store request string
                      */
  char RESPONSE[1024];
  char SERVER_IP[INET_ADDRSTRLEN]; /* section Bind() - inet_ntop() parameter:
                                      store sever ip address */
  char CLIENT_IP[INET_ADDRSTRLEN]; /* section Accept() - inet_ntop() parameter:
                                      store client ip address */

  // Socket()
  int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server_socket == -1) {
    perror("Server socket creation error!");
    return -1;
  }

  // Bind()
  in_addr_t server_ip =
      inet_addr(bind_ip); /* Convert ip address from String to Binary. */
  if (server_ip == -1) {
    perror("ip address converting error!");
    return -1;
  }

  struct sockaddr_in
      server_addr; /* Initialize sockaddr_in structure for bind() function. */
  socklen_t server_addrlen = sizeof(server_addr);
  memset(&server_addr, 0, server_addrlen);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = server_ip;

  int server_bind =
      bind(server_socket, (struct sockaddr *)&server_addr, server_addrlen);
  if (server_bind == -1) {
    perror("Binding error!");
    return -1;
  }

  // Listen()
  int server_listen = listen(server_socket, BACKLOG_SIZE);
  if (server_listen == -1) {
    perror("Listen error!");
    return -1;
  }

  // Accept()
  struct sockaddr_in client_addr;
  socklen_t client_addrlen = sizeof(client_addr);

  while (true) {

    int client_socket =
        accept(server_socket, (struct sockaddr *)&client_addr, &client_addrlen);
    if (client_socket == -1) {
      perror("Accept error!");
      return -1;
    }

    int peer_info = getpeername(client_socket, (struct sockaddr *)&client_addr,
                                &client_addrlen);
    if (peer_info == -1) {
      perror("Getpeername error!");
      return -1;
    }
    const char *client_ipaddr = inet_ntop(AF_INET, &(client_addr.sin_addr),
                                          CLIENT_IP, sizeof(CLIENT_IP));
    if (client_ipaddr == NULL) {
      perror("can't get client's ip address!");
      return -1;
    }

    int server_info = getsockname(
        server_socket, (struct sockaddr *)&server_addr, &server_addrlen);
    if (server_info == -1) {
      perror("Getsockname error!");
      return -1;
    }
    const char *server_ipaddr = inet_ntop(AF_INET, &(server_addr.sin_addr),
                                          SERVER_IP, sizeof(SERVER_IP));
    if (server_ipaddr == NULL) {
      perror("can't get server's ip address!");
      return -1;
    }

    // Read()
    memset(&BUFFER, 0, sizeof(BUFFER));
    ssize_t read_bytes = read(client_socket, BUFFER, sizeof(BUFFER));
    if (read_bytes == -1) {
      perror("Read error!");
      return -1;
    }

    BUFFER[strlen(BUFFER) + 1] = 0;
    submitAnswer(CLIENT_IP, BUFFER);

    // Write()
    memset(&RESPONSE, 0, sizeof(RESPONSE));
    if (strcmp("hello", BUFFER) == 0) {
      strcpy(RESPONSE, server_hello);
    }

    else if (strcmp("whoami", BUFFER) == 0) {
      strcpy(RESPONSE, CLIENT_IP);
    }

    else if (strcmp("whoru", BUFFER) == 0) {
      strcpy(RESPONSE, SERVER_IP);
    }

    else {
      strcpy(RESPONSE, BUFFER);
    }

    RESPONSE[strlen(RESPONSE) + 1] = '\n';
    if (write(client_socket, RESPONSE, strlen(RESPONSE) + 2) == -1) {
      perror("Write error - client side!");
      return -1;
    }
  }

  // CLose()
  if (close(server_socket) == -1) {
    perror("Close error - server socket!");
    return -1;
  }

  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.

  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {

  // Local variables
  char BUFFER[1024];
  char COMMAND[strlen(command) + 2];

  // Socket()
  int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (client_socket == -1) {
    perror("Client socket creation error!");
    return -1;
  }

  // Connect()
  in_addr_t binary_server_ip =
      inet_addr(server_ip); /* Convert ip address from String to Binary. */
  if (binary_server_ip == -1) {
    perror("ip address converting error!");
    return -1;
  }

  struct sockaddr_in
      server_addr; /* Initialize sockaddr_in structure for bind() function. */
  socklen_t server_addrlen = sizeof(server_addr);
  memset(&server_addr, 0, server_addrlen);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = binary_server_ip;

  int client_connect =
      connect(client_socket, (const sockaddr *)&server_addr, server_addrlen);
  if (client_connect == -1) {
    perror("Connect error!");
    return -1;
  }

  // Write()
  memset(&COMMAND, 0, sizeof(COMMAND));
  strcpy(COMMAND, command);
  COMMAND[strlen(command) + 1] = '\n';
  if (write(client_socket, COMMAND, sizeof(COMMAND)) == -1) {
    perror("Write error - client side!");
    return -1;
  }

  // Read()
  memset(&BUFFER, 0, sizeof(BUFFER));
  if (read(client_socket, BUFFER, sizeof(BUFFER)) == -1) {
    perror("Read error - client side!");
    return -1;
  }

  BUFFER[strlen(BUFFER) + 1] = 0;
  submitAnswer(server_ip, BUFFER);

  // CLose()
  if (close(client_socket) == -1) {
    perror("Close error - client socket!");
    return -1;
  }

  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.

  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
