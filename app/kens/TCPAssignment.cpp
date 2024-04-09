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

/* 패킷에서 데이터 읽어서 return: host byte order로 */
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
uint8_t TCPAssignment::getFlag(Packet *packet) {
  uint8_t flag;
  packet->readData(TCP_SEGMENT_START + 13, &flag, 1);
  return flag;
}

/* 패킷에 ip와 port정보 쓰기: network byte order로 */
void TCPAssignment::setPacketSrcDest(Packet *packet, uint32_t srcIP,
                                     uint16_t srcPort, uint32_t destIP,
                                     uint16_t destPort) {
  uint32_t nSrcIP = htonl(srcIP);
  uint32_t nDestIP = htonl(destIP);
  uint16_t nSrcPort = htons(srcPort);
  uint16_t nDestPort = htons(destPort);

  packet->writeData(IP_DATAGRAM_START + 12, &nSrcIP, 4);
  packet->writeData(IP_DATAGRAM_START + 16, &nDestIP, 4);
  packet->writeData(TCP_SEGMENT_START, &nSrcPort, 2);
  packet->writeData(TCP_SEGMENT_START + 2, &nDestPort, 2);
}

/* 패킷에 담긴 ip-port 쌍을 이용해 적합한 소켓 선택 */
struct Socket *
TCPAssignment::getSocket(std::pair<uint32_t, in_port_t> destAddrPair,
                         std::pair<uint32_t, in_port_t> srcAddrPair) {
  uint32_t destIP = std::get<0>(destAddrPair);
  in_port_t destPort = std::get<1>(destAddrPair);
  uint32_t srcIP = std::get<0>(srcAddrPair);
  in_port_t srcPort = std::get<1>(srcAddrPair);

  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {

    /* 소켓의 상태가 ESTAB인 경우: ip-port쌍 둘 다 확인해야 함 */
    if (setIter->socketState == SocketState::ESTABLISHED) {
      uint32_t iterDestIP = setIter->myAddr->sin_addr.s_addr;
      in_port_t iterDestPort = setIter->myAddr->sin_port;
      uint32_t iterSrcIP = setIter->connectedAddr->sin_addr.s_addr;
      in_port_t iterSrcPort = setIter->connectedAddr->sin_port;

      if ((iterDestPort == destPort) && (iterSrcPort == srcPort)) {
        if ((iterDestIP == destIP) || (iterDestIP == INADDR_ANY) ||
            (destIP == INADDR_ANY)) {
          if ((iterSrcIP == srcIP) || (iterSrcIP == INADDR_ANY) ||
              (srcIP == INADDR_ANY)) {
            mySocket = setIter;
            break;
          }
        }
      }
    }
    /* 소켓의 상태가 LISTEN 또는 파생형인 경우 */
    else {
      uint32_t iterDestIP = setIter->myAddr->sin_addr.s_addr;
      in_port_t iterDestPort = setIter->myAddr->sin_port;

      if (iterDestPort == destPort) {
        if ((iterDestIP == destIP) || (iterDestIP == INADDR_ANY) ||
            (destIP == INADDR_ANY)) {
          mySocket = setIter;
          break;
        }
      }
    }
  }
  return mySocket;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag;

  /* 패킷에서 필요한 정보 추출: host-order */
  srcIP = getSrcIP(&packet);
  srcPort = getSrcPort(&packet);
  destIP = getDestIP(&packet);
  destPort = getDestPort(&packet);
  inputFlag = getFlag(&packet);

  packet.readData(TCP_SEGMENT_START + 4, &nSeq, 4);
  packet.readData(TCP_SEGMENT_START + 8, &nAck, 4);
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  /* socketSet 탐색을 통해 적합한 소켓 선택 */
  std::pair<uint32_t, in_port_t> destAddrPair =
      std::make_pair(destIP, destPort);
  std::pair<uint32_t, in_port_t> srcAddrPair = std::make_pair(srcIP, srcPort);
  struct Socket *mySocket = getSocket(destAddrPair, srcAddrPair);
  if (mySocket == nullptr) {
    // printf("packetArrived(): cannot find socket\n");
    return;
  }

  /* 선택한 소켓의 상태 패턴 매칭 */
  switch (mySocket->socketState) {
  case SocketState::LISTENING:
    this->handleListening(&packet, mySocket);
    break;
  case SocketState::SYN_SENT:
    this->handleSYNSent(&packet, mySocket);
    break;
  case SocketState::SYN_RCVD:
    this->handleSYNRcvd(&packet, mySocket);
    break;
  case SocketState::ESTABLISHED:
    this->handleEstab(&packet, mySocket);
    break;
  default:
    break;
  }
  return;
}

void TCPAssignment::handleListening(Packet *packet, struct Socket *socket) {
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag, outputFlag;

  /* 패킷에서 필요한 정보 추출: host-order */
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  packet->readData(TCP_SEGMENT_START + 4, &nSeq, 4);
  packet->readData(TCP_SEGMENT_START + 8, &nAck, 4);
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  /* SYN 패킷인 경우 */
  if ((SYN & inputFlag) && !(ACK & inputFlag)) {
    Packet synAckPacket(PACKET_HEADER_SIZE);
    setPacketSrcDest(&synAckPacket, destIP, destPort, srcIP, srcPort);

    /* ackNum = seqNum + 1 */
    hAck = hSeq + 1;
    nAck = htonl(hAck);

    /* 난수 생성기 */
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> distrib(1, 1000);
    /* SEQ 번호를 생성한 랜덤 넘버로 설정 */
    hSeq = distrib(gen);
    nSeq = htonl(hSeq);

    /* 패킷에 필요한 정보 작성 */
    uint8_t dataOffset = 5 << 4;
    synAckPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

    uint16_t windowSize = htons(65535);
    synAckPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);
    synAckPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);
    synAckPacket.writeData(TCP_SEGMENT_START + 8, &nAck, 4);
    outputFlag = SYN | ACK;
    synAckPacket.writeData(TCP_SEGMENT_START + 13, &outputFlag, 1);

    /* CHECKSUM */
    uint8_t tcpSeg[20];
    synAckPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
    uint16_t calcSum =
        ~NetworkUtil::tcp_sum(htonl(destIP), htonl(srcIP), tcpSeg, 20);
    calcSum = htons(calcSum);
    synAckPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

    /* TODO: Timer 설정하기 - payload 어떻게??? */

    /* SYN-ACK 패킷 송신 */
    this->sendPacket("IPv4", std::move(synAckPacket));

    /* 소켓 정보 설정 */
    socket->socketState = SocketState::SYN_RCVD;
    return;
  } else {
    // printf("handleListening(): not SYN packet\n");
    return;
  }
}

void TCPAssignment::handleSYNSent(Packet *packet, struct Socket *socket) {
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck, hSeqOut;
  uint16_t srcPort, destPort;
  uint8_t inputFlag, outputFlag;

  /* 패킷에서 필요한 정보 추출: host-order */
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  (*packet).readData(TCP_SEGMENT_START + 4, &nSeq, 4);
  (*packet).readData(TCP_SEGMENT_START + 8, &nAck, 4);
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  /* SYN-ACK 패킷인 경우 */
  if ((SYN & inputFlag) && (ACK & inputFlag)) {
    if (hAck != socket->expectedAck) {
      // printf("handleSYNSent(): wrong ack num\n");
      return;
    }
    Packet ackPacket(PACKET_HEADER_SIZE);
    setPacketSrcDest(&ackPacket, destIP, destPort, srcIP, srcPort);

    /* seqNum = 받은 ackNum 그대로 */
    hSeqOut = hAck;
    nSeq = htonl(hSeqOut);

    /* ackNum = seqNum + 1 */
    hAck = hSeq + 1;
    nAck = htonl(hAck);

    /* 기타 패킷 정보 작성 */
    uint8_t dataOffset = 5 << 4;
    ackPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

    uint16_t windowSize = htons(65535);
    ackPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);

    ackPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);
    ackPacket.writeData(TCP_SEGMENT_START + 8, &nAck, 4);

    outputFlag = ACK;
    ackPacket.writeData(TCP_SEGMENT_START + 13, &outputFlag, 1);

    /* CHECKSUM */
    uint8_t tcpSeg[20];
    ackPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
    uint16_t calcSum =
        ~NetworkUtil::tcp_sum(htonl(destIP), htonl(srcIP), tcpSeg, 20);
    calcSum = htons(calcSum);
    ackPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

    /* TODO: Timer 설정하기 - payload 어떻게??? */

    /* ACK 패킷 송신 */
    this->sendPacket("IPv4", std::move(ackPacket));

    /* 소켓 정보 설정 */
    socket->connectedAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    memset(socket->connectedAddr, 0, sizeof(sockaddr_in));
    socket->connectedAddr->sin_addr.s_addr = srcIP;
    socket->connectedAddr->sin_port = srcPort;
    socket->connectedAddr->sin_family = AF_INET;

    socket->socketState = SocketState::ESTABLISHED;

    /* 내가 처리한게 blocked process인지 확인 */
    auto blockedIter =
        std::find_if(blockedProcessHandler.begin(), blockedProcessHandler.end(),
                     [socket](const auto &blockedTuple) {
                       return std::get<0>(blockedTuple) == socket;
                     });
    if (blockedIter != blockedProcessHandler.end()) {
      this->returnSystemCall(std::get<1>(*blockedIter), 0);
      blockedProcessHandler.erase(blockedIter);
      return;
    }
  }
  return;
}

void TCPAssignment::handleSYNRcvd(Packet *packet, struct Socket *socket) {
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag;

  /* 패킷에서 필요한 정보 추출: host-order */
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  packet->readData(TCP_SEGMENT_START + 4, &nSeq, 4);
  packet->readData(TCP_SEGMENT_START + 8, &nAck, 4);
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  struct sockaddr_in *myAddr =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  myAddr->sin_family = AF_INET;
  myAddr->sin_addr.s_addr = destIP;
  myAddr->sin_port = destPort;

  struct sockaddr_in *peerAddr =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  peerAddr->sin_family = AF_INET;
  peerAddr->sin_addr.s_addr = srcIP;
  peerAddr->sin_port = srcPort;

  /* 연속된 SYN 패킷은 소켓의 리스닝큐에 일단 저장
   * backlog 넘치지 않게 확인 */
  if ((SYN & inputFlag) && !(ACK & inputFlag)) {
    if ((socket->BACKLOG - 1) > socket->listeningQueue.size()) {
      Packet temp = *packet;
      socket->listeningQueue.push(temp);
      return;
    }
  }

  /* ACK 패킷인 경우 */
  if (ACK & inputFlag) {
    /* 만약 block된 accept 프로세스가 있다면 여기서 처리 */
    if (!blockedProcessHandler.empty()) {
      for (const auto &setIter : blockedProcessHandler) {
        struct Socket *mySocket = std::get<0>(setIter);
        UUID syscallUUID = std::get<1>(setIter);

        if ((mySocket->pid == socket->pid) && (mySocket->fd == socket->fd)) {

          /* 새로운 fd 생성 */
          int newMySockFd = createFileDescriptor(mySocket->pid);
          if (newMySockFd < 0) {
            this->returnSystemCall(syscallUUID, -1);
            return;
          }

          /* 클라이언트와 연결될 새 소켓 */
          struct Socket *newMySocket = new Socket;
          newMySocket->domain = mySocket->domain;
          newMySocket->type = mySocket->type;
          newMySocket->protocol = mySocket->protocol;
          newMySocket->pid = mySocket->pid;
          newMySocket->fd = newMySockFd;
          newMySocket->socketState = SocketState::ESTABLISHED;
          newMySocket->myAddr = myAddr;
          newMySocket->connectedAddr = peerAddr;

          /* 소켓에 저장된 addr 추출: network-order */
          if (std::get<2>(setIter) != nullptr &&
              *std::get<3>(setIter) >= sizeof(sockaddr_in) &&
              myAddr != nullptr) {
            struct sockaddr_in *addrtoN =
                (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
            addrtoN->sin_addr.s_addr = htonl(myAddr->sin_addr.s_addr);
            addrtoN->sin_port = htons(myAddr->sin_port);
            addrtoN->sin_family = AF_INET;

            /* 추출한 addr 복사 */
            memcpy(std::get<2>(setIter), addrtoN, *std::get<3>(setIter));
            free(addrtoN);

            /* 새로 생성한 소켓 추가 */
            socketSet.insert(newMySocket);
            /* 처리한 blocked process 삭제 */
            blockedProcessHandler.erase(setIter);
            /* 처리한 결과 return */
            this->returnSystemCall(syscallUUID, newMySockFd);
            break;
          }
        }
      }
    }
    /* blocked process가 없다면 accept에서 바로 처리 가능 */
    else {
      socket->acceptQueue.push(std::make_tuple(myAddr, peerAddr));
    }

    /* 소켓 상태 다시 LISTENING으로 */
    socket->socketState = SocketState::LISTENING;

    /* 다음으로 처리할 패킷 탐색 */
    if (!(socket->listeningQueue.empty())) {
      Packet nextPacket = socket->listeningQueue.front();
      socket->listeningQueue.pop();
      packetArrived("IPv4", std::move(nextPacket));
    }
  }
  return;
}

void TCPAssignment::handleEstab(Packet *packet, struct Socket *socket) {
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag;

  /* 패킷에서 필요한 정보 추출: host-order */
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  packet->readData(TCP_SEGMENT_START + 4, &nSeq, 4);
  packet->readData(TCP_SEGMENT_START + 8, &nAck, 4);
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  if (FIN & inputFlag) {
    // printf("estab handle");
    return;
  }
  return;
}

void TCPAssignment::deleteSocket(struct Socket *socket) {
  if (socket == nullptr)
    return;

  free(socket->connectedAddr);

  while (!socket->listeningQueue.empty())
    socket->listeningQueue.pop();

  while (!socket->acceptQueue.empty())
    socket->acceptQueue.pop();

  delete socket;

  return;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain,
                                   int type, int protocol) {
  /* 기본 조건 확인 */
  if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP) {
    this->returnSystemCall(syscallUUID, -1);
  }
  /* 새로운 fd 생성 */
  int myfd = createFileDescriptor(pid);
  if (myfd < 0) {
    this->returnSystemCall(syscallUUID, -1);
  }
  /* socketSet에 pid와 fd가 같은 소켓이 이미 있는지 탐색 */
  for (const auto &setIter : socketSet) {
    if (setIter->pid == pid && setIter->fd == myfd) {
      // printf("socket(): socket with same pid&fd exists\n");
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
  }

  /* 새로운 소켓 생성 */
  Socket *newSocket = new Socket;
  newSocket->domain = domain;
  newSocket->type = type;
  newSocket->protocol = protocol;
  newSocket->pid = pid;
  newSocket->fd = myfd;
  newSocket->socketState = SocketState::CREATED;

  /* 새로 생성한 소켓 추가 */
  socketSet.insert(newSocket);

  this->returnSystemCall(syscallUUID, myfd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
      break;
    }
  }
  if (mySocket == nullptr) {
    // printf("close(): cannot find socket\n");
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
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    // printf("bind(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (mySocket->bound) {
    // printf("bind(): socket already bound\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addrlen != sizeof(*addr)) {
    // printf("bind(): invalid addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 바인딩할 addr 획득: host-order */
  struct sockaddr_in *toBindAddr =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  struct sockaddr_in *addr_ = (sockaddr_in *)(addr);
  toBindAddr->sin_addr.s_addr = ntohl(addr_->sin_addr.s_addr);
  toBindAddr->sin_port = ntohs(addr_->sin_port);
  toBindAddr->sin_family = AF_INET;

  uint32_t toBindIP = toBindAddr->sin_addr.s_addr;
  in_port_t toBindPort = toBindAddr->sin_port;

  /* 이미 바인딩됐는지 확인 */
  for (const auto &setIter : socketSet) {
    if (setIter->bound) {
      in_addr_t iterIP = setIter->myAddr->sin_addr.s_addr;
      in_port_t iterPort = setIter->myAddr->sin_port;

      if (iterPort == toBindPort) {
        if ((iterIP == INADDR_ANY || toBindIP == INADDR_ANY ||
             iterIP == toBindIP)) {
          // printf("bind(): addr already BOUND\n");
          this->returnSystemCall(syscallUUID, -1);
          return;
        }
      }
    }
  }

  /* 소켓 정보 변경 */
  mySocket->myAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  memcpy(mySocket->myAddr, toBindAddr, sizeof(sockaddr_in));
  mySocket->bound = true;

  free(toBindAddr);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    // printf("getsock(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (*addrlen < sizeof(sockaddr_in)) {
    // printf("getsock(): invalid addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addr == nullptr) {
    // printf("getsock(): invalid addr\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (mySocket->myAddr == nullptr) {
    // printf("getsock(): socket not bounded\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 소켓에 저장된 addr 추출: network-order */
  struct sockaddr_in *addrtoN =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  addrtoN->sin_addr.s_addr = htonl(mySocket->myAddr->sin_addr.s_addr);
  addrtoN->sin_port = htons(mySocket->myAddr->sin_port);
  addrtoN->sin_family = AF_INET;

  /* 추출한 addr 복사 */
  memcpy(addr, addrtoN, sizeof(struct sockaddr_in));
  *addrlen = sizeof(struct sockaddr_in);

  free(addrtoN);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd,
                                   int backlog) {
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    // printf("listen(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (!mySocket->bound) {
    // printf("listen(): socket not bound\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  /* 0 <= backlog <= SOMAXCONN */
  if (backlog > SOMAXCONN)
    backlog = SOMAXCONN;
  if (backlog < 0)
    backlog = 0;

  /* 소켓 정보 변경 */
  mySocket->BACKLOG = backlog;
  mySocket->socketState = SocketState::LISTENING;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd,
                                    const struct sockaddr *addr,
                                    socklen_t addrlen) {
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    // printf("connect(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (addrlen != sizeof(sockaddr_in)) {
    // printf("connect() : bad addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 일단 blockedProcess로 설정 */
  struct sockaddr *addr_ = (struct sockaddr *)addr;
  blockedProcessHandler.insert(
      std::make_tuple(mySocket, syscallUUID, addr_, &addrlen));

  /* 연결대상의 ip-port 획득: host-order */
  const struct sockaddr_in *peerAddr = (const struct sockaddr_in *)addr;
  uint32_t peerIP = ntohl(peerAddr->sin_addr.s_addr);
  in_port_t peerPort = ntohs(peerAddr->sin_port);
  uint32_t myIP;
  in_port_t myPort;

  /* 내 소켓이 unbound인 경우: IP layer 참조해 주소 획득 */
  if (!(mySocket->bound)) {
    ipv4_t peerIP_ =
        NetworkUtil::UINT64ToArray<sizeof(uint32_t)>((uint64_t)peerIP);
    int routingTablePort = getRoutingTable(peerIP_);
    std::optional<ipv4_t> myIPOption = getIPAddr(routingTablePort);
    ipv4_t myIP_;
    if (myIPOption.has_value()) {
      myIP_ = myIPOption.value();
    } else {
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
    myIP = ntohl(NetworkUtil::arrayToUINT64(myIP_));

    /* 빈 port 탐색 */
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<in_port_t> distrib(1024, 65535);
    bool occupied = false;
    do {
      myPort = distrib(gen);
      for (const auto &sockIter : socketSet) {
        if (sockIter->bound && (sockIter->myAddr->sin_port == myPort)) {
          occupied = true;
          break;
        }
      }
    } while (occupied);

  }
  /* 내 소켓이 bound인 경우 */
  else {
    myIP = mySocket->myAddr->sin_addr.s_addr;
    myPort = mySocket->myAddr->sin_port;
  }

  /* SYN packet 생성 */
  Packet synPacket(PACKET_HEADER_SIZE);
  setPacketSrcDest(&synPacket, myIP, myPort, peerIP, peerPort);

  /* 랜덤 seqNum 생성 */
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> distrib(1, 1000);
  uint32_t hSeq = distrib(gen);
  uint32_t nSeq = htonl(hSeq);
  synPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);

  mySocket->expectedAck = hSeq + 1;

  uint8_t dataOffset = 5 << 4;
  synPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

  uint8_t synFlag = SYN;
  synPacket.writeData(TCP_SEGMENT_START + 13, &synFlag, 1);

  uint16_t windowSize = htons(65535);
  synPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);

  /* CHECKSUM */
  uint8_t tcpSeg[20];
  synPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
  uint16_t calcSum =
      ~NetworkUtil::tcp_sum(htonl(myIP), htonl(peerIP), tcpSeg, 20);
  calcSum = htons(calcSum);
  synPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

  this->sendPacket("IPv4", std::move(synPacket));

  /* implicit binding */
  if (!mySocket->bound) {
    mySocket->myAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    mySocket->myAddr->sin_addr.s_addr = myIP;
    mySocket->myAddr->sin_port = myPort;
    mySocket->myAddr->sin_family = AF_INET;
    mySocket->bound = true;
  }
  mySocket->socketState = SocketState::SYN_SENT;

  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   struct sockaddr *addr, socklen_t *addrlen) {
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    // printf("accept() : socket not found\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  /* acceptQueue가 비었으면 blockedprocess로 설정 */
  if (mySocket->acceptQueue.empty()) {
    blockedProcessHandler.insert(
        std::make_tuple(mySocket, syscallUUID, addr, addrlen));
    // printf("blocking accept\n");
    return;
  }

  /* acceptQueue에서 요청 추출 */
  std::tuple<struct sockaddr_in *, struct sockaddr_in *> request =
      mySocket->acceptQueue.front();
  mySocket->acceptQueue.pop();

  /* 새로운 fd 생성 */
  int newMySockFd = createFileDescriptor(pid);
  if (newMySockFd < 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 새로운 소켓: 기본적으로 내 clone, with modifications */
  struct Socket *newMySocket = new Socket;
  newMySocket->domain = mySocket->domain;
  newMySocket->type = mySocket->type;
  newMySocket->protocol = mySocket->protocol;
  newMySocket->pid = mySocket->pid;
  newMySocket->fd = newMySockFd;
  newMySocket->socketState = SocketState::ESTABLISHED;
  newMySocket->myAddr = mySocket->myAddr;
  newMySocket->connectedAddr = std::get<1>(request);

  socketSet.insert(newMySocket);

  /* 소켓에 저장된 addr 추출: network-order */
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    struct sockaddr_in *addrtoN =
        (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    addrtoN->sin_addr.s_addr = htonl(newMySocket->myAddr->sin_addr.s_addr);
    addrtoN->sin_port = htons(newMySocket->myAddr->sin_port);
    addrtoN->sin_family = AF_INET;

    /* 추출한 addr 복사 */
    memcpy(addr, addrtoN, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);

    free(addrtoN);
  }
  // printf("newMySockFd %d\n", newMySockFd);

  this->returnSystemCall(syscallUUID, newMySockFd);
  return;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {
  /* 소켓 탐색 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    // printf("no matching socket in listen");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (mySocket->socketState != SocketState::ESTABLISHED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 소켓에 저장된 addr 추출: network-order */
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    struct sockaddr_in *addrtoN =
        (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    addrtoN->sin_addr.s_addr = htonl(mySocket->connectedAddr->sin_addr.s_addr);
    addrtoN->sin_port = htons(mySocket->connectedAddr->sin_port);
    addrtoN->sin_family = AF_INET;

    /* 추출한 addr 복사 */
    memcpy(addr, addrtoN, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);

    free(addrtoN);
  } else {
    // printf("addr wrong in getpeername");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->returnSystemCall(syscallUUID, 0);
}

} // namespace E