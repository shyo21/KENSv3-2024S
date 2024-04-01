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
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
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
  SocketData sockData = {sock, sockAddr};
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

  // same address binding

  // for (const auto &pids : this->socketMap) {
  //   for (const auto &fds : pids.second) {
  //     const SocketData &sds = fds.second;
  //     std::cout << "iter - ing inner: " << sds.sockAddr->sin_port << " "
  //               << inet_ntoa(sds.sockAddr->sin_addr) << std::endl;
  //     if (sds.socket.socketstate == SocketState::BOUND) {
  //       if (sds.sockAddr->sin_port == sockAddrPtr->sin_port) {
  //         std::cout << "sdsport: " << sds.sockAddr->sin_port
  //                   << " sockport: " << sockAddrPtr->sin_port << std::endl;
  //         if ((sds.sockAddr->sin_addr.s_addr ==
  //         sockAddrPtr->sin_addr.s_addr)
  //         ||
  //             (sds.sockAddr->sin_addr.s_addr == INADDR_ANY) ||
  //             (sockAddrPtr->sin_addr.s_addr == INADDR_ANY)) {
  //           this->returnSystemCall(syscallUUID, -1);
  //           return;
  //         }
  //       }
  //     }
  //   }
  // }

  socketData.sockAddr = sockAddrPtr;
  socketData.socket.socketstate = SocketState::BOUND;
  boundSet.insert(addrTuple);

  this->returnSystemCall(syscallUUID, 0);
}
} // namespace E
