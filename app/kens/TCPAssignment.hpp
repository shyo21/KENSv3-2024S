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
  LISTENING,
  SYN_SENT,
  SYN_RCVD,
  ESTABLISHED
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
  uint32_t expectedAck;

  struct sockaddr_in *myAddr = nullptr;        /*Bindaddr*/
  struct sockaddr_in *connectedAddr = nullptr; /*peeraddr*/
  // listening 중인 packet
  std::queue<Packet> listeningQueue;
  // pid 내 소켓 addr, 상대 소켓 addr -- ??
  std::queue<std::tuple<struct sockaddr_in *, struct sockaddr_in *>>
      acceptQueue;
};

const int IP_DATAGRAM_START = 14;
const int TCP_SEGMENT_START = IP_DATAGRAM_START + 20;
const int FIN = 1;
const int SYN = 2;
const int ACK = 16;

const size_t PACKET_HEADER_SIZE = 54;

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  std::unordered_map<
      std::pair<uint32_t, in_port_t>,
      std::unordered_map<std::pair<uint32_t, in_port_t>,
                         std::pair<struct Socket *, SocketState>>>
      handshakingMap;
  // pid : Sockets
  std::set<struct Socket *> socketSet;
  // pid uuid - 소켓 포인터 / <소켓 포인터 , uuid>
  std::set<std::tuple<struct Socket *, UUID, struct sockaddr *, socklen_t *>>
      blockedProcessHandler;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  // Add
  uint32_t getSrcIP(Packet *);
  uint32_t getDestIP(Packet *);
  uint16_t getSrcPort(Packet *);
  uint16_t getDestPort(Packet *);
  uint8_t getFlag(Packet *);

  void setPacketSrcDest(Packet *, uint32_t, uint16_t, uint32_t, uint16_t);
  struct Socket *getSocket(std::pair<uint32_t, in_port_t>,
                           std::pair<uint32_t, in_port_t>);

  void handleSYNSent(Packet *, struct Socket *);
  void handleListening(Packet *, struct Socket *);
  void handleSYNRcvd(Packet *, struct Socket *);
  void handleEstab(Packet *, struct Socket *);
  void deleteSocket(struct Socket *);

  void syscall_socket(UUID, int, int, int, int);
  void syscall_close(UUID, int, int);
  void syscall_bind(UUID, int, int, const struct sockaddr *, socklen_t);
  void syscall_getsockname(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_listen(UUID, int, int, int);
  void syscall_connect(UUID, int, int, const struct sockaddr *, socklen_t);
  void syscall_accept(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_getpeername(UUID, int, int, struct sockaddr *, socklen_t *);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
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
