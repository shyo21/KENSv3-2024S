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

  struct Socket sock = {domain, type, protocol, SocketState::CREATED};
  struct sockaddr_in *sockAddr = {};
  struct SocketHandShake sockHandShake = {};
  struct SocketData sockData = {sock, sockAddr, sockHandShake};

  if (this->socketMap.find(pid) == this->socketMap.end()) {
    this->socketMap[pid] = std::unordered_map<int, SocketData>();
  }

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

  SocketData &mySocketData = sockIter->second;

  if (mySocketData.socket.socketstate != SocketState::CREATED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (addrlen != sizeof(*addr)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  sockaddr_in *mySockAddr = (sockaddr_in *)(addr);
  uint32_t myAddr = mySockAddr->sin_addr.s_addr;
  in_port_t myPort = mySockAddr->sin_port;

  std::tuple<uint32_t, in_port_t> addrTuple = std::make_tuple(myAddr, myPort);

  for (const auto &addrIter : boundSet) {
    uint32_t currAddr = std::get<0>(addrIter);
    in_port_t currPort = std::get<1>(addrIter);
    if (myPort == currPort) {
      if (myAddr == currAddr || myAddr == INADDR_ANY ||
          currAddr == INADDR_ANY) {
        this->returnSystemCall(syscallUUID, -1);
        return;
      }
    }
  }

  mySocketData.sockAddr = mySockAddr;
  mySocketData.socket.socketstate = SocketState::BOUND;
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

  SocketData &mySocketData = sockIter->second;

  if (*addrlen < sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  sockaddr_in *mySockAddr = (sockaddr_in *)(addr);
  *mySockAddr = *mySocketData.sockAddr;
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

  SocketData &mysocketData = sockIter->second;

  if (mysocketData.socket.socketstate != SocketState::BOUND) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  mysocketData.socket.socketstate = SocketState::LISTENING;
  mysocketData.socketHandShake.BACKLOG = backlog;

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

  SocketData &mySocketData = sockIter->second;

  if (mySocketData.socket.socketstate != SocketState::CREATED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addrlen != sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  // serverFd
  // addr가 유효한 주소가 맞는지 확인

  const struct sockaddr_in *peerAddr = (const struct sockaddr_in *)addr;
  uint32_t peerIP = peerAddr->sin_addr.s_addr;
  in_port_t peerPort = peerAddr->sin_port;
  // checking func / check if addr - fd is LISTENING
  // peerFd : addr 주소를 가지는 서버fd 찾기
  bool peerFound = false;
  for (const auto &iterPid : socketMap) {
    for (const auto &iterFd : iterPid.second) {
      const SocketData &iterData = iterFd.second;
      if (iterData.socket.socketstate == SocketState::LISTENING) {
        if (iterData.sockAddr->sin_addr.s_addr == peerIP) {
          if (iterData.sockAddr->sin_port == peerPort) {
            SocketHandShake peerHandshake = iterData.socketHandShake;
            if (peerHandshake.BACKLOG <= peerHandshake.listeningQueue.size()) {
              this->returnSystemCall(syscallUUID, -1);
              return;
            }

            peerHandshake.listeningQueue.emplace(fd, *mySocketData.sockAddr);
            mySocketData.socketHandShake.connectedTuple =
                std::make_tuple(iterFd.first, peerAddr);
            peerFound = true;
            break;
          }
        }
      }
    }
    if (peerFound) {
      break;
    }
  }

  if (!peerFound) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  mySocketData.socket.socketstate = SocketState::CONNECTED;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   const struct sockaddr *addr,
                                   socklen_t *addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &mySocketData = sockIter->second;
  if (mySocketData.socket.socketstate != SocketState::LISTENING) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  std::queue<std::tuple<int, const struct sockaddr_in *>> myQueue =
      mySocketData.socketHandShake.listeningQueue;

  if (myQueue.empty()) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  std::tuple<int, const struct sockaddr_in *> request = myQueue.front();
  myQueue.pop();

  // 이미 listening queue에 있던 소켓이 다른 소켓과 연결되어있다면 종료.
  // 이미 해당 request ip, port에 대해 serve중이면 종료.
  if (mySocketData.socketHandShake.connectedTuple != std::make_tuple(-1, -1)) {
    returnSystemCall(syscallUUID, -1);
    return;
  } else {
    mySocketData.socketHandShake.connectedTuple = request;
  }

  // 새 소켓 파일 디스크립터 생성 및 클라이언트와 연결
  int requestFd = std::get<0>(request);
  const struct sockaddr_in *requestAddr = std::get<1>(request);

  int newMySockFd = createFileDescriptor(pid); // 가상의 파일 디스크립터 생성
  if (newMySockFd < 0) {
    this->returnSystemCall(syscallUUID, -1); // 파일 디스크립터 생성 실패
    return;
  }

  // 새 소켓을 클라이언트와 연결된 상태로 설정
  struct Socket newMySocket = {AF_INET, SOCK_STREAM, IPPROTO_TCP,
                               SocketState::CONNECTED};
  struct sockaddr_in *newMySockAddr = new sockaddr_in;
  newMySockAddr->sin_family = AF_INET;
  newMySockAddr->sin_addr.s_addr = mySocketData.sockAddr->sin_addr.s_addr;
  newMySockAddr->sin_port = mySocketData.sockAddr->sin_port;

  // 여기서는 클라이언트 주소 정보 설정을 생략함
  struct SocketHandShake newMySocketHandShake;
  newMySocketHandShake.connectedTuple =
      std::tuple<int, const struct sockaddr_in *>(requestFd, requestAddr);
  struct SocketData newMySocketData = {newMySocket, newMySockAddr,
                                       newMySocketHandShake};

  // sockethandshake connectedTuple에 peer정보넣기

  this->socketMap[pid][newMySockFd] = newMySocketData;

  // 클라이언트 주소 정보를 사용자 공간에 복사
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, newMySockAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  }

  // 새로운 소켓 파일 디스크립터 반환
  this->returnSystemCall(syscallUUID, newMySockFd);
}

} // namespace E
