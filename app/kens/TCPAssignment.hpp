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
#include <algorithm>
#include <iostream>
#include <queue>
#include <random>
#include <set>
#include <tuple>
#include <unordered_map>

namespace E {

/* Basic descripter for socket state info */
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
  uint32_t expectedAck;    /*seqNum + 1*/

  struct sockaddr_in *myAddr = nullptr;        /*bindaddr*/
  struct sockaddr_in *connectedAddr = nullptr; /*peeraddr*/
  std::queue<Packet> listeningQueue;           /*with backlog size*/
  std::queue<std::tuple<struct sockaddr_in *, struct sockaddr_in *>>
      acceptQueue;

  std::vector<char> sendBuffer;    /* 송신 데이터 버퍼 */
  std::vector<int> sendByteVector; /* 송신 데이터 크기 리스트 */
  std::vector<char> receiveBuffer; /* 수신 데이터 버퍼 */
  uint32_t sendBase;               /* 송신 기준점 */
  uint32_t sendNext;           /* 다음에 송신할 데이터의 시작점 */
  uint32_t receiveNext;        /* 다음에 받을 데이터의 시작점 */
  uint32_t windowSize = 51200; // 현재 윈도우 크기
};

struct packetInfo {
  size_t PACKET_SIZE;

  /* IP datagram header */
  uint8_t ihl = 5;
  size_t IP_HEADER_SIZE = 20; /* ihl * 4 */
  uint16_t totalLength;
  uint32_t srcIP, destIP;

  /* TCP segment header */
  uint16_t srcPort, destPort;
  uint32_t seqNum, ackNum;
  uint8_t dataOffset = 5;
  size_t TCP_HEADER_SIZE = 20; /* (dataOffset >> 4) * 4 */
  uint8_t flag;
  uint16_t windowSize = 51200;
  uint16_t checkSum;
};

/*frequently used constants*/
const uint8_t FIN = 1;
const uint8_t SYN = 2;
const uint8_t ACK = 16;
const size_t DEFAULT_HEADER_SIZE = 54;
const size_t ETHERNET_HEADER_SIZE = 14;
const size_t MSS = 512;

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  std::set<struct Socket *> socketSet; /*sockets*/
  std::set<std::tuple<struct Socket *, UUID, void *, void *>>
      blockedProcessHandler; /*blocked processes*/

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  /*implemented functions*/
  void readPacket(Packet *, packetInfo *);
  void writePacket(Packet *, packetInfo *);
  void writeCheckSum(Packet *);

  struct Socket *getSocket(std::pair<uint32_t, in_port_t>,
                           std::pair<uint32_t, in_port_t>);

  void handleSYNSent(Packet *, struct Socket *);
  void handleListening(Packet *, struct Socket *);
  void handleSYNRcvd(Packet *, struct Socket *);
  void handleEstab(Packet *, struct Socket *);

  void sendData(struct Socket *socket);
  void deleteSocket(struct Socket *);

  void syscall_socket(UUID, int, int, int, int);
  void syscall_close(UUID, int, int);
  void syscall_bind(UUID, int, int, const struct sockaddr *, socklen_t);
  void syscall_getsockname(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_listen(UUID, int, int, int);
  void syscall_connect(UUID, int, int, const struct sockaddr *, socklen_t);
  void syscall_accept(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_getpeername(UUID, int, int, struct sockaddr *, socklen_t *);
  void syscall_read(UUID, int, int, void *, size_t);
  void syscall_write(UUID, int, int, const void *, size_t);

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
