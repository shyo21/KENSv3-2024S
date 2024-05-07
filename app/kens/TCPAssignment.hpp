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
#include <any>
#include <chrono>
#include <cmath>
#include <iostream>
#include <queue>
#include <random>
#include <set>
#include <tuple>
#include <unordered_map>

namespace E {

struct unackedInfo {
  Packet *packet = nullptr;

  bool islastACK = false;

  uint32_t expectedAck = 0;
  size_t dataSize = 0;

  UUID timerUUID;
  Time sentTime;
};

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

  sockaddr_in *myAddr = nullptr;        /*bindaddr*/
  sockaddr_in *connectedAddr = nullptr; /*peeraddr*/
  std::queue<Packet> listeningQueue;    /*with backlog size*/
  std::queue<std::tuple<sockaddr_in *, sockaddr_in *>> acceptQueue;

  std::vector<std::tuple<bool, UUID, size_t, std::vector<char>>> sendBuffer;
  std::vector<std::vector<char>> receiveBuffer;
  std::vector<unackedInfo *> unAckedPackets;

  size_t windowSize = 51200;
  size_t sentSize = 0;
  size_t sendBase = 0;
  size_t sendNext = 0;

  uint32_t sentSeq;
  uint32_t sentAck;

  /*Timer Value*/
  Time sampleRTT = 0;
  Time estimatedRTT = 100 * 1000000;
  Time devRTT = 0;
  Time timeoutInterval = 100 * 1000000;
};

enum class blockedState { CONNECT, ACCEPT, READ, WRITE, CLOSE };
struct blockedProcess {
  /* 이 프로세스가 어디서 생성되었는가 */
  blockedState type;

  Socket *socket = nullptr;
  UUID uuid;

  /* for handshake */
  sockaddr_in *addr = nullptr;
  socklen_t addrlen;
  socklen_t *addrlenptr = nullptr;

  /* for data transfer */
  void *buf = nullptr;
  size_t count;
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
const float ALPHA = 0.125;
const float BETA = 0.25;

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  std::set<Socket *> socketSet;            /*sockets*/
  std::set<blockedProcess *> blockHandler; /*blocked processes*/

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  /*implemented functions*/
  void readPacket(Packet *, packetInfo *);
  void writePacket(Packet *, packetInfo *);
  void writeCheckSum(Packet *);
  bool isCheckSum(Packet *);

  Socket *getSocket(std::pair<uint32_t, in_port_t>,
                    std::pair<uint32_t, in_port_t>);

  void handleSYNSent(Packet *, Socket *);
  void handleListening(Packet *, Socket *);
  void handleSYNRcvd(Packet *, Socket *);
  void handleEstab(Packet *, Socket *);

  void sendData(Socket *);
  void deleteSocket(Socket *);

  void getRTT(Socket *);

  void syscall_socket(UUID, int, int, int, int);
  void syscall_close(UUID, int, int);
  void syscall_bind(UUID, int, int, const sockaddr *, socklen_t);
  void syscall_getsockname(UUID, int, int, sockaddr *, socklen_t *);
  void syscall_listen(UUID, int, int, int);
  void syscall_connect(UUID, int, int, const sockaddr *, socklen_t);
  void syscall_accept(UUID, int, int, sockaddr *, socklen_t *);
  void syscall_getpeername(UUID, int, int, sockaddr *, socklen_t *);
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
