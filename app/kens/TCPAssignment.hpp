/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Additional Header
#include <iostream>
#include <queue>
#include <set>
#include <tuple>
#include <unordered_map>

namespace E {

/*Basic descripter for socket state info*/
enum class SocketState { CLOSED, CREATED, CONNECTED, BOUND, WAITING,LISTENING };

/*Basic socket information*/
struct Socket {
  int domain;   /*AF_INET*/
  int type;     /*SOCK_STREAM*/
  int protocol; /*IPPROTO_TCP*/
  SocketState socketstate;
};
struct SocketHandShake {
  // listening queue
  std::queue<std::tuple<int, const struct sockaddr_in *>> listeningQueue;
  // backlogsize
  int BACKLOG = -1;
  // connect fd, addr
  std::tuple<int, const struct sockaddr_in *> connectedTuple;
};
struct SocketData {
  struct Socket socket;
  struct sockaddr_in *sockAddr;
  struct SocketHandShake socketHandShake;
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  std::unordered_map<int, std::unordered_map<int, struct SocketData>> socketMap;
  std::set<std::tuple<uint32_t, in_port_t>> boundSet;
  std::set<std::tuple<int,uint32_t,in_port_t>> listeningSet;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

  // Add
  void syscall_socket(UUID, int, int, int, int);
  void syscall_close(UUID, int, int);
  void syscall_bind(UUID, int, int, const struct sockaddr *, socklen_t);
  void syscall_getsockname(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_listen(UUID, int, int, int);
  void syscall_connect(UUID, int, int, const struct sockaddr *, socklen_t);
  void syscall_accept(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_getpeername(UUID, int, int, struct sockaddr *, socklen_t *);
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
