/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]),
                         std::get<int>(param.params[2]));

    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    // fd, buffer, count
    //  this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain,
                                   int type, int protocol) {
  if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP) {
    this->returnSystemCall(syscallUUID, -1);
  }

  int sockFd = createFileDescriptor(pid);
  if (sockFd < 0) {
    this->returnSystemCall(syscallUUID, -1);
  }

  Socket sock = {domain, type, protocol, SocketState::CREATED};
  struct sockaddr_in *sockAddr;
  struct SocketHandShake socketHandShake;
  SocketData sockData = {sock, sockAddr, socketHandShake};
  this->socketMap[pid][sockFd] = sockData;
  this->returnSystemCall(syscallUUID, sockFd);
};

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &socketData = sockIter->second;
  if (socketData.socket.socketstate == SocketState::BOUND) {
    const sockaddr_in *sockAddr = socketData.sockAddr;
    std::tuple<uint32_t, in_port_t> addrTuple =
        std::make_tuple(sockAddr->sin_addr.s_addr, sockAddr->sin_port);
    boundSet.erase(addrTuple);
  }

  pidIter->second.erase(sockIter);

  this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd,
                                 const struct sockaddr *addr,
                                 socklen_t addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &socketData = sockIter->second;

  if (socketData.socket.socketstate != SocketState::CREATED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (addrlen != sizeof(*addr)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  sockaddr_in *sockAddrPtr = (sockaddr_in *)(addr);
  uint32_t toBindAddr = sockAddrPtr->sin_addr.s_addr;
  in_port_t toBindPort = sockAddrPtr->sin_port;

  std::tuple<uint32_t, in_port_t> addrTuple =
      std::make_tuple(toBindAddr, toBindPort);

  for (const auto &addrs : boundSet) {
    uint32_t currAddr = std::get<0>(addrs);
    in_port_t currPort = std::get<1>(addrs);
    if (toBindPort == currPort) {
      if (toBindAddr == currAddr || toBindAddr == INADDR_ANY ||
          currAddr == INADDR_ANY) {
        this->returnSystemCall(syscallUUID, -1);
        return;
      }
    }
  }

  socketData.sockAddr = sockAddrPtr;
  socketData.socket.socketstate = SocketState::BOUND;
  boundSet.insert(addrTuple);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &socketData = sockIter->second;

  if (*addrlen < sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  sockaddr_in *sockAddrPtr = (sockaddr_in *)(addr);
  *sockAddrPtr = *socketData.sockAddr;
  *addrlen = sizeof(sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd,
                                   int backlog) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &socketData = sockIter->second;

  if (socketData.socket.socketstate != SocketState::BOUND) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  socketData.socket.socketstate = SocketState::LISTENING;
  socketData.socketHandShake.BACKLOG = backlog;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd,
                                    const struct sockaddr *addr,
                                    socklen_t addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &socketData = sockIter->second;

  if (socketData.socket.socketstate != SocketState::CREATED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addrlen != sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // checking func

  const struct sockaddr_in *serverAddrPtr = (const struct sockaddr_in *)addr;
  uint32_t serverIP = serverAddrPtr->sin_addr.s_addr;
  in_port_t serverPort = serverAddrPtr->sin_port;

  socketData.socket.socketstate = SocketState::CONNECTED;
  socketData.socketHandShake.connectedTuple =
      std::make_tuple(serverIP, serverPort);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   const struct sockaddr *addr,
                                   socklen_t addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &socketData = pidIter->second[fd];
  if (socketData.socket.socketstate != SocketState::LISTENING) {
    this->returnSystemCall(syscallUUID, -1); // 소켓이 듣기 상태가 아님
    return;
  }

  // 연결 대기열에서 대기 중인 연결 요청을 확인하고 처리하는 로직 구현
  std::queue<std::tuple<int, uint32_t>> queue =
      socketData.socketHandShake.listeningQueue;
  if (queue.empty()) {
    std
        // 새 소켓 파일 디스크립터 생성 및 클라이언트와 연결
        int new
  }
  elseckFd = createFileDescriptor(pid); // 가상의 파일 디스크립터 생성 함수
  if (newSockFd < 0) {
    this->returnSystemCall(syscallUUID, -1); // 파일 디스크립터 생성 실패
    return;
  }

  // 새 소켓을 클라이언트와 연결된 상태로 설정
  Socket newSocket = {AF_INET, SOCK_STREAM, IPPROTO_TCP,
                      SocketState::CONNECTED};
  struct sockaddr_in *newSockAddr = new sockaddr_in;
  // 여기서는 클라이언트 주소 정보 설정을 생략함
  SocketData newSocketData = {newSocket, newSockAddr, {}};
  this->socketMap[pid][newSockFd] = newSocketData;

  // 클라이언트 주소 정보를 사용자 공간에 복사
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, newSockAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  }

  // 새로운 소켓 파일 디스크립터 반환
  this->returnSystemCall(syscallUUID, newSockFd);
}

} // namespace E
