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

uint32_t TCPAssignment::getSrcIP(Packet *packet) {
  uint32_t ipaddr;
  packet->readData(IP_DATAGRAM_START + 12, &ipaddr, 4);
  return ntohl(ipaddr);
}

uint32_t TCPAssignment::getDestIP(Packet *packet) {
  uint32_t ipaddr;
  packet->readData(IP_DATAGRAM_START + 16, &ipaddr, 4);
  return ntohl(ipaddr);
}

uint16_t TCPAssignment::getSrcPort(Packet *packet) {
  uint16_t port;
  packet->readData(TCP_SEGMENT_START, &port, 2);
  return ntohs(port);
}

uint16_t TCPAssignment::getDestPort(Packet *packet) {
  uint16_t port;
  packet->readData(TCP_SEGMENT_START + 2, &port, 2);
  return ntohs(port);
}

uint8_t TCPAssignment::getFlags(Packet *packet) {
  uint8_t flag;
  packet->readData(TCP_SEGMENT_START + 13, &flag, 1);
  return flag;
}

void TCPAssignment::setPacketSrcDest(Packet *packet, uint32_t srcIP,
                                     uint16_t srcPort, uint32_t destIP,
                                     uint16_t destPort) {
  uint32_t nSrcIP = htonl(srcIP);
  uint32_t nDestIP = htonl(destIP);
  uint16_t nSrcPort = htonl(srcPort);
  uint16_t nDestPort = htonl(destPort);

  packet->writeData(IP_DATAGRAM_START + 12, &nSrcIP, 4);
  packet->writeData(IP_DATAGRAM_START + 16, &nDestIP, 4);
  packet->writeData(TCP_SEGMENT_START, &nSrcPort, 2);
  packet->writeData(TCP_SEGMENT_START + 2, &nDestPort, 2);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t flags;

  // 패킷에서 필요한 정보 추출(host 형식)
  srcIP = getSrcIP(&packet);
  srcPort = getSrcPort(&packet);
  destIP = getDestIP(&packet);
  destPort = getDestPort(&packet);
  flags = getFlags(&packet);

  packet.readData(TCP_SEGMENT_START + 4, &nSeq, 4); // seqNum
  packet.readData(TCP_SEGMENT_START + 8, &nAck, 4); // ackNum
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  // uint32_t printsrcip = htonl(srcIP);
  // char printstrsrcip[INET_ADDRSTRLEN];
  // inet_ntop(AF_INET, &printsrcip, printstrsrcip, INET_ADDRSTRLEN);

  // uint32_t printdestip = htonl(destIP);
  // char printstrdestip[INET_ADDRSTRLEN];
  // inet_ntop(AF_INET, &printdestip, printstrdestip, INET_ADDRSTRLEN);

  // std::cout << "packetdata: " << printstrsrcip << "," << srcPort << "/"
  //           << printstrdestip << "," << destPort << "/" <<
  //           std::bitset<8>(flags)
  //           << "/" << hSeq << "," << hAck << std::endl;

  std::pair<uint32_t, in_port_t> destAddrPair =
      std::make_pair(destIP, destPort);
  std::pair<uint32_t, in_port_t> srcAddrPair = std::make_pair(srcIP, srcPort);

  // flag가 어떤 상태인지 확인
  bool isSYN = flags & (1 << 1);
  bool isACK = flags & (1 << 4);

  // 플래그가 SYN인 경우 - 클라이언트로부터의 연결 요청
  if (isSYN && !isACK) {
    /* 이미 syn을 받은 적이 있는지 확인 syn 패킷을 받은놈(dest ip dest
    port) << 얘가 listen()중이고, 우리 sockset에 있는놈인가? */
    // struct Socket *mySocket = getSocket(destAddrPair);
    // if (mySocket == nullptr) {
    //   // printf("packet SYN: cannot find socket\n");
    //   return;
    // }

    // if (mySocket->socketState != SocketState::LISTENING) {
    //   printf("packet SYN: not LISTENING\n");
    //   return;
    // }

    //  SYN-ACK 패킷 생성: 기존의 패킷 클론
    size_t PACKETHEADER_SIZE = 54;
    Packet synAckPacket(PACKETHEADER_SIZE);
    setPacketSrcDest(&synAckPacket, destIP, destPort, srcIP, srcPort);

    // ACK 번호 설정(받은 SEQ number + 1)
    hAck = hSeq + 1;
    nAck = htonl(hAck);

    /* 난수 생성기 - Morsenne Twiseter 알고리즘을 이용해 1~1000까지의 균일
     * 분포를 가지는 난수를 생성한다 */
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> distrib(1, 1000);

    // SEQ 번호를 생성한 랜덤 넘버로 설정
    hSeq = distrib(gen);
    nSeq = htonl(hSeq);
    // 내 state SYN_RCV로 만들고 seq, ack 설정
    handShakingMap[destAddrPair] =
        std::make_tuple(srcAddrPair, SocketState::SYN_RCV, -1, hSeq + 1);

    // 패킷에 필요한 정보 써넣기

    uint8_t dataOffset = 5 << 4;
    synAckPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

    uint16_t windowSize = htons(65535);
    synAckPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);
    synAckPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);
    synAckPacket.writeData(TCP_SEGMENT_START + 8, &nAck, 4);
    flags = (1 << 1) | (1 << 4); // SYN-ACK
    synAckPacket.writeData(TCP_SEGMENT_START + 13, &flags, 1);

    /* TODO: Timer 설정하기 - payload 어떻게??? packet, ip, port, state? */

    //  SYN-ACK 패킷 송신
    this->sendPacket("IPv4", std::move(synAckPacket));
  }

  // SYN-ACK패킷 처리
  if (isSYN && isACK) {
    std::cout << "synack rcv" << std::endl;
    std::tuple<std::pair<uint32_t, in_port_t>, SocketState, int, int>
        toDealTuple;
    auto myIter = handShakingMap.find(destAddrPair);
    // 내가 보냈던 syn 패킷에 대한 답장이 맞다면
    if (myIter != handShakingMap.end()) {
      if ((std::get<3>(myIter->second) == hAck) &&
          (std::get<1>(myIter->second) == SocketState::SYN_SENT)) {
        toDealTuple = myIter->second;
      }
    } else {
      printf("No match SYN_RCV pair");
      return;
    }
    Packet ackPacket = packet.clone();
    // destport and srcport exchange
    setPacketSrcDest(&ackPacket, destIP, destPort, srcIP, srcPort);
    hAck = hSeq + 1; // ACK 번호 설정(받은 SEQ number + 1)
    nAck = htonl(nAck);
    // SEQ number = randomnumber
    // 난수 생성기 초기화
    std::random_device rd; // 비결정적 난수 생성기를 사용하여 시드를 생성
    std::mt19937 gen(rd()); // Mersenne Twister 알고리즘을 사용하는 생성기
    // 1부터 1000까지의 균일 분포를 가진 난수 생성
    std::uniform_int_distribution<int> distrib(1, 1000);
    hSeq = distrib(gen);
    nSeq = htonl(hSeq);
    // 내 state SYN_RCV로 만들고 seq, ack 설정
    handShakingMap[destAddrPair] =
        std::make_tuple(srcAddrPair, SocketState::SYN_RCV, -1, hAck + 1);
    // sequence number - 따로 지정
    ackPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);
    // ACK number - 받은 seq number +1
    ackPacket.writeData(TCP_SEGMENT_START + 8, &nAck, 4);
    // ACK 플래그 설정
    flags = (1 << 4); // ACK
    ackPacket.writeData(TCP_SEGMENT_START + 13, &flags, 1);
    // timer 설정하기
    // payload 어떻게??? packet, ip, port, state?

    // socketstate = connected, connectedPair = srcAddrPair
    struct Socket *mySocket = getSocket(destAddrPair);
    mySocket->socketState = SocketState::CONNECTED;
    mySocket->connectedPair = srcAddrPair;
    //  SYN-ACK 패킷 송신
    this->sendPacket("IPv4", std::move(ackPacket));
  }
  // ACK 패킷 처리 / handShakingMap에서 찾은 pair의 상태가 SYN_RCV여야함. ack ==
  // seq+1이어야 함. established
  if (!isSYN && isACK) {
    // 이전 연결에 대해 보냈던 SEQnum + 1 과 같다면 listening set에 fd,
    // sockadddr 추가 , handshakingMap - established  추가 추가 클라이언트
    // 소켓의 상태를 CONNECTED로 변경
    std::tuple<std::pair<uint32_t, in_port_t>, SocketState, int, int>
        toDealTuple;
    auto myIter = handShakingMap.find(destAddrPair);
    // 내가 보냈던 syn 패킷에 대한 답장이 맞다면
    //
    if (myIter != handShakingMap.end()) {
      if ((std::get<3>(myIter->second) == hAck) &&
          (std::get<1>(myIter->second) == SocketState::SYN_SENT)) {
        toDealTuple = myIter->second;
      }
    } else {
      printf("No match SYN_RCV pair");
      return;
    }
    // 내 listening중인 소켓을 찾아서 listeningqueue에 srcdestpair입력
    struct Socket *mySocket = getSocket(destAddrPair);

    if (mySocket == nullptr) {
      printf("no listening socket found in packet ack rcv");
    } else {
      mySocket->listeningQueue.push(srcAddrPair);
      std::cout << "listing1uewew: " << mySocket->listeningQueue.empty()
                << std::endl;
    }
  }
}

struct Socket *
TCPAssignment::getSocket(std::pair<uint32_t, in_port_t> addrPair) {
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    uint32_t iterIP = setIter->myAddr->sin_addr.s_addr;
    in_port_t iterPort = setIter->myAddr->sin_port;

    if (iterPort == std::get<1>(addrPair)) {

      if ((iterIP == std::get<0>(addrPair)) || (iterIP == INADDR_ANY) ||
          (std::get<0>(addrPair) == INADDR_ANY)) {
        std::cout << "socket found" << std::endl;
        mySocket = setIter;
      }
    }
  }
  return mySocket;
}

void TCPAssignment::deleteSocket(struct Socket *socket) {
  if (socket == nullptr)
    return;

  // if (socket->myAddr != nullptr)
  //   delete socket->myAddr;

  while (!socket->listeningQueue.empty())
    socket->listeningQueue.pop();

  delete socket;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain,
                                   int type, int protocol) {
  if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP) {
    this->returnSystemCall(syscallUUID, -1);
  }

  int myfd = createFileDescriptor(pid);
  if (myfd < 0) {
    this->returnSystemCall(syscallUUID, -1);
  }

  // socket map에 이미 해당 pid set에 소켓 있으면 에러
  for (const auto &setIter : socketSet) {
    if (setIter->pid == pid && setIter->fd == myfd) {
      printf("socket(): socket with same pid&fd exists\n");
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
  }

  Socket *newSocket = new Socket;
  newSocket->domain = domain;
  newSocket->type = type;
  newSocket->protocol = protocol;
  newSocket->pid = pid;
  newSocket->fd = myfd;
  newSocket->socketState = SocketState::CREATED;

  socketSet.insert(newSocket);

  this->returnSystemCall(syscallUUID, myfd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
      break;
    }
  }

  if (mySocket == nullptr) {
    printf("close(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  socketSet.erase(mySocket);
  deleteSocket(mySocket);

  this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd,
                                 const struct sockaddr *addr,
                                 socklen_t addrlen) {
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  // 만약 소켓맵에서 못 찾는다면 에러
  if (mySocket == nullptr) {
    printf("bind(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // socketState가 created 가 아니라면 에러
  if (mySocket->socketState != SocketState::CREATED) {
    printf("bind(): invalid socket state\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // addrlen not matching
  if (addrlen != sizeof(*addr)) {
    printf("bind(): invalid addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  struct sockaddr_in *toBindAddr = (sockaddr_in *)(addr);
  in_addr_t toBindIP = toBindAddr->sin_addr.s_addr;
  in_port_t toBindPort = toBindAddr->sin_port;

  for (const auto &setIter : socketSet) {
    if (setIter->myAddr == nullptr) {
      continue;
    }
    if (setIter->bound) {
      in_addr_t iterIP = setIter->myAddr->sin_addr.s_addr;
      in_port_t iterPort = setIter->myAddr->sin_port;

      if (iterPort == toBindPort) {
        if ((iterIP == INADDR_ANY || toBindIP == INADDR_ANY ||
             iterIP == toBindIP)) {
          printf("bind(): addr already BOUND\n");
          this->returnSystemCall(syscallUUID, -1);
          return;
        }
      }
    }
  }

  mySocket->myAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  memcpy(mySocket->myAddr, toBindAddr, sizeof(sockaddr_in));
  mySocket->socketState = SocketState::BOUND;
  mySocket->bound = true;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {
  // SocketMap에 없는 pid에서 getsockname을 호출하면 오류
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  // 만약 소켓맵에서 못 찾는다면 에러
  if (mySocket == nullptr) {
    printf("getsock(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // addrlen 이 유효한지 확인,
  if (*addrlen < sizeof(sockaddr_in)) {
    printf("getsock(): invalid addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  // addr이 유효한지 확인, nullptr이면 안 됨.
  if (addr == nullptr) {
    printf("getsock(): invalid addr\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // sockAddr이 바인드 되지 않았거나 sockAddr 이 init 되지 않음.
  if (mySocket->myAddr == nullptr) {
    printf("getsock(): socket not bounded\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  struct sockaddr_in *mySockAddr = (struct sockaddr_in *)(addr);
  memcpy(mySockAddr, mySocket->myAddr, sizeof(struct sockaddr_in));
  *addrlen = sizeof(struct sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd,
                                   int backlog) {
  // SocketMap에 없는 pid에서 없는 소켓을 호출하면 오류
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  // 만약 소켓맵에서 못 찾는다면 에러
  if (mySocket == nullptr) {
    printf("listen(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // socketstate가 bound가 아닐 경우 리턴.
  if (!mySocket->bound) {
    printf("listen(): socket not bound\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // backlog 조건, 0<=backlog<=SOMAXCONN(max length of backlog(128))
  if (backlog > SOMAXCONN)
    backlog = SOMAXCONN;

  if (backlog < 0)
    backlog = 0;

  mySocket->BACKLOG = backlog;
  mySocket->socketState = SocketState::LISTENING;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd,
                                    const struct sockaddr *addr,
                                    socklen_t addrlen) {
  // SocketMap에 없는 pid에서 없는 소켓 호출하면 오류
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  // 만약 소켓맵에서 못 찾는다면 에러
  if (mySocket == nullptr) {
    printf("connect(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (mySocket->socketState == SocketState::WAITING) {
    printf("connect(): already waiting for connection\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // 주소 길이값이 유효하지 않을 경우 오류
  if (addrlen != sizeof(sockaddr_in)) {
    printf("connect() : bad addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  // 연결하고자 하는 대상의 ip주소와 port넘버 획득
  const struct sockaddr_in *peerAddr = (const struct sockaddr_in *)addr;
  uint32_t peerIP = peerAddr->sin_addr.s_addr;
  in_port_t peerPort = peerAddr->sin_port;
  auto peerPair = std::make_pair(peerIP, peerPort);

  // ip 계층에서 내가 사용할 NIC ip와 port 획득
  ipv4_t peerIPReform =
      NetworkUtil::UINT64ToArray<sizeof(uint32_t)>((uint64_t)peerIP);
  int myNICPortReform = getRoutingTable(peerIPReform);
  std::optional<ipv4_t> myNICIPOption = getIPAddr(myNICPortReform);
  ipv4_t myNICIPReform;
  if (myNICIPOption.has_value()) {
    myNICIPReform = myNICIPOption.value();
  } else {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  uint32_t myNICIP = NetworkUtil::arrayToUINT64(myNICIPReform);
  uint16_t myNICPort = static_cast<std::uint16_t>(myNICPortReform);
  auto myPair = std::make_pair(myNICIP, myNICPort);

  // 발송할 새로운 SYN packet 생성
  size_t PACKETHEADER_SIZE = 54;
  Packet synPacket(PACKETHEADER_SIZE);

  // packet 초기화
  setPacketSrcDest(&synPacket, myNICIP, myNICPort, peerIP, peerPort);

  // 난수 생성기를 이용한 seqNum 생성
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> distrib(1, 1000);
  uint32_t hSeq = distrib(gen);
  uint32_t nSeq = htonl(hSeq);
  synPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);

  uint8_t dataOffset = 5 << 4;
  synPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

  uint8_t synFlag = 1 << 1;
  synPacket.writeData(TCP_SEGMENT_START + 13, &synFlag, 1);

  uint16_t windowSize = htons(65535);
  synPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);

  // timer 설정
  // this->sendPacket("IPv4", std::move(synPacket));

  /* handshakingMap { pair(내 ip, port) } ->
   * { tuple( pair(내 ip, port), 내 상태, seqnum, acknum) } */
  handShakingMap[myPair] =
      std::make_tuple(peerPair, SocketState::SYN_SENT, -1, hSeq + 1);
  // socketMap의 fd 의 sockaddr 설정
  mySocket->myAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  mySocket->myAddr->sin_addr.s_addr = myNICIP;
  mySocket->myAddr->sin_port = myNICPort;
  mySocket->myAddr->sin_family = AF_INET;

  mySocket->socketState = SocketState::WAITING;
  mySocket->bound = true;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   struct sockaddr *addr, socklen_t *addrlen) {
  // SocketMap에 없는 pid에서 을 호출하면 오류
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  // 만약 소켓맵에서 못 찾는다면 에러
  if (mySocket == nullptr) {
    printf("accept() : socket not found\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // socket은  listening상태여야함
  if (mySocket->socketState != SocketState::LISTENING) {
    printf("accept() : socket not listening\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // std::cout << mySocket->listeningQueue.empty() << std::endl;
  //  listening queue에 아무도 없으면 에러
  if (mySocket->listeningQueue.empty()) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  std::pair<uint32_t, in_port_t> request = mySocket->listeningQueue.front();
  mySocket->listeningQueue.pop();
  std::cout << std::get<0>(request) << std::endl;
  // 이미 listening queue에 있던 소켓이 다른 소켓과 연결되어있다면 종료.
  // 이미 해당 request ip, port에 대해 serve중이면 종료.

  // 새로운 소켓을 만들어 요청 ip, port 와 연결
  int newMySockFd = createFileDescriptor(pid); // 가상의 파일 디스크립터 생성
  if (newMySockFd < 0) {
    this->returnSystemCall(syscallUUID, -1); // 파일 디스크립터 생성 실패
    return;
  }

  // 새 소켓을 클라이언트와 연결된 상태로 설정,
  // 현재 나의 소켓과 socketstate, listeningqueue connected socket제외 모두동일
  struct Socket *newMySocket = new Socket;
  newMySocket->domain = mySocket->domain;
  newMySocket->type = mySocket->type;
  newMySocket->protocol = mySocket->protocol;
  newMySocket->pid = mySocket->pid;
  newMySocket->fd = newMySockFd;
  newMySocket->socketState = SocketState::CONNECTED;
  newMySocket->myAddr = mySocket->myAddr;
  newMySocket->connectedPair = request;

  // peer socket addr
  struct sockaddr_in *peerAddr =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  peerAddr->sin_family = AF_INET;
  peerAddr->sin_addr.s_addr = std::get<0>(request);
  peerAddr->sin_port = std::get<1>(request);

  // 클라이언트 주소 정보를 사용자 공간에 복사
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, peerAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  }

  // 새로운 소켓 파일 디스크립터 반환
  this->returnSystemCall(syscallUUID, newMySockFd);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {

  // SocketMap에 없는 pid에서 을 호출하면 오류
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  // 만약 소켓맵에서 못 찾는다면 에러
  if (mySocket == nullptr) {
    printf("no matching socket in listen");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (mySocket->socketState != SocketState::CONNECTED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // peer addr 에 내 소켓의 connected socket주소 정보(connectedPair) 입력
  struct sockaddr_in *peerAddr;
  peerAddr->sin_addr.s_addr = std::get<0>(mySocket->connectedPair);
  peerAddr->sin_port = std::get<1>(mySocket->connectedPair);
  peerAddr->sin_family = AF_INET;

  if (peerAddr != nullptr && addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, peerAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  } else {
    printf("addr wrong in getpeername");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->returnSystemCall(syscallUUID, 0);
}

} // namespace E
