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
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  
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
  //SocketMap에 없는 pid에서 getsockname을 호출하면 오류
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  //주소를 찾으려는 fd가 socketMap에 없다면 오류
  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  //socketMap에서 fd에 해당하는 socketData 찾음
  SocketData &mySocketData = sockIter->second;
  //addrlen 이 유효한지 확인, 
  if (*addrlen < sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  //addr이 유효한지 확인, nullptr이면 안 됨.
  if(addr == nullptr){
    this->returnSystemCall(syscallUUID, -1);
    return;    
  }
    //sockAddr이 바인드 되지 않았거나 sockAddr 이 init 되지 않음.
  if (mySocketData.sockAddr == nullptr || mySocketData.socket.socketstate !=SocketState::BOUND ) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  struct sockaddr_in *mySockAddr = (struct sockaddr_in *)(addr);
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
  //fd에 해당하는 SocketData 찾음.
  SocketData &mysocketData = sockIter->second;
  //socketstate가 bound가 아닐 경우 리턴.
  //
  if (mysocketData.socket.socketstate != SocketState::BOUND) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  mysocketData.socket.socketstate = SocketState::LISTENING;
  //backlog 조건, 0<=backlog<=SOMAXCONN(max length of backlog(128))
  if(backlog>SOMAXCONN){
    backlog = SOMAXCONN;
  }
  if(backlog<0){
    backlog = 0;
  }
  mysocketData.socketHandShake.BACKLOG = backlog;
  listeningSet.insert(std::make_tuple(fd,mysocketData.sockAddr->sin_addr.s_addr,mysocketData.sockAddr->sin_port));

  std::cout<<"inserted listening server: "<<listeningSet.empty()<<std::endl;
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
  //fd에 해당하는 SocketData 찾음.
  SocketData &mySocketData = sockIter->second;
  //유효한 소켓이 아닌 경우, CREATED 인 경우 오류

  //주소 길이값이 유효하지 않을 경우 오류
  if(addrlen != sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  // serverFd
  // addr가 유효한 주소가 맞는지 확인

  const struct sockaddr_in *peerAddr = (const struct sockaddr_in *)addr;
  uint32_t peerIP = peerAddr->sin_addr.s_addr;
  in_port_t peerPort = peerAddr->sin_port;
  // checking func / check if addr - fd is LISTENING
  // peerFd : addr 주소를 가지는 서버fd socketMap에서 찾기
  // 찾은 fd 값으로 해당 peer의 socketHandShake의 listening queue에 나의 fd와 주소정보 튜플 push하기

  std::cout<<"sival from outside"<<std::endl;
  std::cout<<"checklisteningSet: "<<listeningSet.empty()<<std::endl;

  int peerFd = -1;
  for(const auto& iter: listeningSet) {
    std::cout<<"sival"<<std::endl;
    if((std::get<1>(iter)==INADDR_ANY)||(std::get<1>(iter)==peerIP)) {
      if(std::get<2>(iter)==peerPort){
        peerFd = std::get<0>(iter);
        break;
      }
    }
  }

  if (peerFd == -1) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  bool found = false;
  for(const auto& pidIter:socketMap){
    for(const auto& fdIter:pidIter.second){
      std::cout << "connect queue push: " << pidIter.first << " // " << fdIter.first << std::endl;
      if(fdIter.first == peerFd){
        socketMap[pidIter.first][fdIter.first].socketHandShake.listeningQueue.push(std::tuple<int, const struct sockaddr_in *>(fd, mySocketData.sockAddr));
        perror("i found peerfd");
        found = true;
        break;
      }
    }
    if(found==true){
      break;
    }
  }

  mySocketData.socket.socketstate = SocketState::WAITING;

  this->returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   struct sockaddr *addr,
                                   socklen_t *addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    std::cout << '1';
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    std::cout << '2';
    returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &mySocketData = sockIter->second;
  std::cout << "accept: " << pidIter->first << " // " << sockIter->first << std::endl;
  if (mySocketData.socket.socketstate != SocketState::LISTENING) {
    std::cout << '3';
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  
  if (mySocketData.socketHandShake.listeningQueue.empty()) {
    std::cout << '4';
    returnSystemCall(syscallUUID, -1);
    return;
  }

  std::tuple<int, const struct sockaddr_in *> request = 
      mySocketData.socketHandShake.listeningQueue.front();
  mySocketData.socketHandShake.listeningQueue.pop();
  

  // 이미 listening queue에 있던 소켓이 다른 소켓과 연결되어있다면 종료.
  // 이미 해당 request ip, port에 대해 serve중이면 종료.


  // 새 소켓 파일 디스크립터 생성 및 클라이언트와 연결
  int requestFd = std::get<0>(request);
  const struct sockaddr_in *requestAddr = std::get<1>(request);

  int newMySockFd = createFileDescriptor(pid); // 가상의 파일 디스크립터 생성
  if (newMySockFd < 0) {
    std::cout << '5';
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

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen) {
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

  if (mySocketData.socket.socketstate != SocketState::CONNECTED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  const struct sockaddr_in *peerAddr = std::get<1>(mySocketData.socketHandShake.connectedTuple);
  if (peerAddr != nullptr && addr != nullptr && addrlen != nullptr && *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, peerAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  } else {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->returnSystemCall(syscallUUID, 0);
}

} // namespace E
