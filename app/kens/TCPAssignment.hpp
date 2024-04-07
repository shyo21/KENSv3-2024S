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
#include <random>
#include <set>
#include <tuple>
#include <unordered_map>

namespace E {

/*Basic descripter for socket state info*/
enum class SocketState {
  CLOSED,
  CREATED,
  BOUND,
  WAITING,
  LISTENING,
  SYN_SENT,
  SYN_RCV,
  SYNACK_RCV,
  ACK_RCV,
  ESTABLISHED,
  CONNECTED,
};
/*Basic socket information*/
struct Socket {
  int domain;       /*AF_INET*/
  int type;         /*SOCK_STREAM*/
  int protocol;     /*IPPROTO_TCP*/
  int pid;          /*pid*/
  int fd;           /*fd*/
  int BACKLOG = -1; /*backlog size*/

  bool bound = false;      /*check if bound*/
  SocketState socketState; /*sockstate*/

  struct sockaddr_in *myAddr = nullptr; /*Bindaddr*/
  std::queue<Packet *> listeningQueue;
  std::queue<> acceptQueue;
  // queue - pid, fd, myaddr, peerAddr -
}

const int IP_DATAGRAM_START = 14;
const int TCP_SEGMENT_START = IP_DATAGRAM_START + 20;

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  // pid : Sockets
  std::set<struct Socket *> socketSet;
  // my ip,port : state , peer ip, port, seq, ack
  std::unordered_map<std::pair<uint32_t, in_port_t>,
                     std::tuple<SocketState, int, int>>
      handShakingMap;

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
  uint32_t getSrcIP(Packet *);
  uint32_t getDestIP(Packet *);
  uint16_t getSrcPort(Packet *);
  uint16_t getDestPort(Packet *);
  uint8_t getFlags(Packet *);
  void setPacketSrcDest(Packet *, uint32_t, uint16_t, uint32_t, uint16_t);

  struct Socket *getSocket(std::pair<uint32_t, in_port_t>);
  void deleteSocket(struct Socket *);

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
