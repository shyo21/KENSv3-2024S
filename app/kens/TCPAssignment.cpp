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

uint8_t TCPAssignment::getFlag(Packet *packet) {
  uint8_t flag;
  packet->readData(TCP_SEGMENT_START + 13, &flag, 1);
  return flag;
}

void TCPAssignment::setPacketSrcDest(Packet *packet, uint32_t srcIP,
                                     uint16_t srcPort, uint32_t destIP,
                                     uint16_t destPort) {
  uint32_t nSrcIP = htonl(srcIP);
  uint32_t nDestIP = htonl(destIP);
  uint16_t nSrcPort = htons(srcPort);
  uint16_t nDestPort = htons(destPort);

  std::cout << "setpacket: " << srcIP << " " << srcPort << " " << destIP << " "
            << destPort << std::endl;

  packet->writeData(IP_DATAGRAM_START + 12, &nSrcIP, 4);
  packet->writeData(IP_DATAGRAM_START + 16, &nDestIP, 4);
  packet->writeData(TCP_SEGMENT_START, &nSrcPort, 2);
  packet->writeData(TCP_SEGMENT_START + 2, &nDestPort, 2);
}

struct Socket *
TCPAssignment::getSocket(std::pair<uint32_t, in_port_t> destAddrPair,
                         std::pair<uint32_t, in_port_t> srcAddrPair) {
  uint32_t destIP = std::get<0>(destAddrPair);
  in_port_t destPort = std::get<1>(destAddrPair);
  uint32_t srcIP = std::get<0>(srcAddrPair);
  in_port_t srcPort = std::get<1>(srcAddrPair);

  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
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
    } else {
      uint32_t iterDestIP = setIter->myAddr->sin_addr.s_addr;
      in_port_t iterDestPort = setIter->myAddr->sin_port;
      // std::cout << "iter: " << iterIP << " " << iterPort << std::endl;
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

  // 패킷에서 필요한 정보 추출(host 형식)
  srcIP = getSrcIP(&packet);
  srcPort = getSrcPort(&packet);
  destIP = getDestIP(&packet);
  destPort = getDestPort(&packet);
  inputFlag = getFlag(&packet);

  packet.readData(TCP_SEGMENT_START + 4, &nSeq, 4); // seqNum
  packet.readData(TCP_SEGMENT_START + 8, &nAck, 4); // ackNum
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  std::pair<uint32_t, in_port_t> destAddrPair =
      std::make_pair(destIP, destPort);
  std::pair<uint32_t, in_port_t> srcAddrPair = std::make_pair(srcIP, srcPort);

  // 소켓Set에서 해당 소켓 destpair를 이용해서 찾기
  struct Socket *mySocket = getSocket(destAddrPair, srcAddrPair);
  if (mySocket == nullptr) {
    // std::cout << srcIP << " " << destIP << " ";
    // printf("packetArrived(): cannot find socket\n");
    return;
  }

  // 해당 소켓의 state에 따라 함수를 호출하는 pattern matching
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
void TCPAssignment::handleEstab(Packet *packet, struct Socket *socket) {

  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag;

  // 패킷에서 필요한 정보 추출(host 형식)
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  packet->readData(TCP_SEGMENT_START + 4, &nSeq, 4); // seqNum
  packet->readData(TCP_SEGMENT_START + 8, &nAck, 4); // ackNum
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  // if fin
  if (FIN & inputFlag) {
    printf("estab handle");
    return;
  }
  return;
}

void TCPAssignment::handleListening(Packet *packet, struct Socket *socket) {
  printf("listening\n");
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag, outputFlag;

  // 패킷에서 필요한 정보 추출(host 형식)
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  packet->readData(TCP_SEGMENT_START + 4, &nSeq, 4); // seqNum
  packet->readData(TCP_SEGMENT_START + 8, &nAck, 4); // ackNum
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  // if SYN RCVD
  // else nothing?
  if ((SYN & inputFlag) && !(ACK & inputFlag)) {
    // socket -> synrcvd로
    // 새 패킷 만들어서 synack 보내기
    Packet synAckPacket(PACKET_HEADER_SIZE);
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

    // 패킷에 필요한 정보 써넣기
    uint8_t dataOffset = 5 << 4;
    synAckPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

    uint16_t windowSize = htons(65535);
    synAckPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);
    synAckPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);
    synAckPacket.writeData(TCP_SEGMENT_START + 8, &nAck, 4);
    outputFlag = SYN | ACK; // SYN-ACK
    synAckPacket.writeData(TCP_SEGMENT_START + 13, &outputFlag, 1);
    // CHECKSUM
    uint8_t tcpSeg[20];
    synAckPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
    uint16_t calcSum =
        ~NetworkUtil::tcp_sum(htonl(destIP), htonl(srcIP), tcpSeg, 20);
    calcSum = htons(calcSum);
    synAckPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

    /* TODO: Timer 설정하기 - payload 어떻게??? packet, ip, port, state? */

    //  SYN-ACK 패킷 송신
    this->sendPacket("IPv4", std::move(synAckPacket));
    socket->socketState = SocketState::SYN_RCVD;
    return;

  } else {
    printf("packet arrived : listening state but not syn rcv");
    return;
  }
}

void TCPAssignment::handleSYNRcvd(Packet *packet, struct Socket *socket) {
  // std::cout << "syn rcv" << std::endl;
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck;
  uint16_t srcPort, destPort;
  uint8_t inputFlag;

  // 패킷에서 필요한 정보 추출(host 형식)
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  packet->readData(TCP_SEGMENT_START + 4, &nSeq, 4); // seqNum
  packet->readData(TCP_SEGMENT_START + 8, &nAck, 4); // ackNum
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

  // 연속으로 syn 패킷이 들어오면? 소켓의 리스닝큐에 패킷을 일단 저장
  // socket의 backlog 값보다 현재 리스닝큐의 사이즈가 작다면 패킷 추가
  // backlog = 현재 3-way handshake중인 packet + 인 통신
  if ((SYN & inputFlag) && !(ACK & inputFlag)) {
    if ((socket->BACKLOG - 1) > socket->listeningQueue.size()) {
      Packet temp = *packet;
      socket->listeningQueue.push(temp);
      return;
    } else {
      // queue full - drop
      // return;
    }
  }
  // ack이 왔다면 무엇에 대한 ack일까
  if (ACK & inputFlag) {
    // 만약 block된 accept 프로세스가 있다면 여기서 처리
    // printf("ack rcv\n");
    if (!blockedProcessHandler.empty()) {
      for (const auto &setIter : blockedProcessHandler) {
        // block된 소켓 accept
        UUID syscallUUID = std::get<1>(setIter);
        int pid = std::get<0>(setIter)->pid;
        struct Socket *mySocket = std::get<0>(setIter);

        if ((std::get<0>(setIter)->pid == socket->pid) &&
            (std::get<0>(setIter)->fd == socket->fd)) {
          // 현재 내 소켓에 대해서 block된 process 존재
          // 새로운 소켓을 만들어 요청 ip, port 와 연결
          int newMySockFd =
              createFileDescriptor(pid); // 가상의 파일 디스크립터 생성
          if (newMySockFd < 0) {
            this->returnSystemCall(syscallUUID,
                                   -1); // 파일 디스크립터 생성 실패
            return;
          }
          // 새 소켓을 클라이언트와 연결된 상태로 설정,
          // 현재 나의 소켓과 socketstate, listeningqueue connected socket제외
          // 모두동일
          struct Socket *newMySocket = new Socket;
          newMySocket->domain = mySocket->domain;
          newMySocket->type = mySocket->type;
          newMySocket->protocol = mySocket->protocol;
          newMySocket->pid = mySocket->pid;
          newMySocket->fd = newMySockFd;
          newMySocket->socketState = SocketState::ESTABLISHED;
          newMySocket->myAddr = myAddr;
          newMySocket->connectedAddr = peerAddr;

          // 주소 정보를 사용자 공간에 복사
          if (std::get<2>(setIter) != nullptr &&
              *std::get<3>(setIter) >= sizeof(sockaddr_in) &&
              myAddr != nullptr) {
            struct sockaddr_in *addrtoN =
                (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
            addrtoN->sin_addr.s_addr = htonl(myAddr->sin_addr.s_addr);
            addrtoN->sin_port = htons(myAddr->sin_port);
            addrtoN->sin_family = AF_INET;

            memcpy(std::get<2>(setIter), addrtoN, *std::get<3>(setIter));
            std::cout << "uuid : " << syscallUUID << "newfd :  " << newMySockFd
                      << " mysocket pid: " << mySocket->pid << std::endl;
            printf("blocked process handle\n");
            socketSet.insert(newMySocket);

            blockedProcessHandler.erase(setIter);
            this->returnSystemCall(syscallUUID, newMySockFd);
            break;
          }
        }
      }
    } else {
      // block된 친구가 없다면 accept에서 처리해줄것이야!
      socket->acceptQueue.push(std::make_tuple(myAddr, peerAddr));
    }
    socket->socketState = SocketState::LISTENING;
    if (!(socket->listeningQueue.empty())) {
      Packet nextPacket = socket->listeningQueue.front();
      socket->listeningQueue.pop();
      packetArrived("IPv4", std::move(nextPacket));
    }
    //
  }
  return;
}

void TCPAssignment::handleSYNSent(Packet *packet, struct Socket *socket) {
  printf("synsent");
  uint32_t srcIP, destIP, hSeq, hAck, nSeq, nAck, hSeqOut;
  uint16_t srcPort, destPort;
  uint8_t inputFlag, outputFlag;

  /* 패킷에서 필요한 정보 추출 - host 형식 */
  srcIP = getSrcIP(packet);
  srcPort = getSrcPort(packet);
  destIP = getDestIP(packet);
  destPort = getDestPort(packet);
  inputFlag = getFlag(packet);

  (*packet).readData(TCP_SEGMENT_START + 4, &nSeq, 4); /* seqNum */
  (*packet).readData(TCP_SEGMENT_START + 8, &nAck, 4); /* ackNum */
  hSeq = ntohl(nSeq);
  hAck = ntohl(nAck);

  /* SYN-ACK을 받은 경우 - ACK 패킷 발송으로 답신 */
  if ((SYN & inputFlag) && (ACK & inputFlag)) {
    if (hAck != socket->expectedAck) {
      printf("handle synsent : wrong ack num");
      return;
    }
    /* ACK 패킷 생성 */
    Packet ackPacket(PACKET_HEADER_SIZE);
    setPacketSrcDest(&ackPacket, destIP, destPort, srcIP, srcPort);

    /* SEQ 번호 설정 - 받은 ackNum 그대로 */
    hSeqOut = hAck;
    nSeq = htonl(hSeqOut);

    /* ACK 번호 설정 - 받은 seqNum + 1 */
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

    // CHECKSUM
    uint8_t tcpSeg[20];
    ackPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
    uint16_t calcSum =
        ~NetworkUtil::tcp_sum(htonl(destIP), htonl(srcIP), tcpSeg, 20);
    calcSum = htons(calcSum);
    ackPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

    /* TODO: Timer 설정하기 - payload 어떻게??? packet, ip, port, state? */

    /* ACK 패킷 송신 */
    this->sendPacket("IPv4", std::move(ackPacket));

    /* 내 소켓이 dest 소켓과 연결되었다는 정보 추가 */
    socket->connectedAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    memset(socket->connectedAddr, 0, sizeof(sockaddr_in));
    socket->connectedAddr->sin_addr.s_addr = srcIP;
    socket->connectedAddr->sin_port = srcPort;
    socket->connectedAddr->sin_family = AF_INET;

    socket->socketState = SocketState::ESTABLISHED;
    // /* simultaneous connection 처리 */
    // if (!(SYN & inputFlag) && (ACK & inputFlag)) {
    //   socket->socketState = SocketState::ESTABLISHED;
    // } else {
    //   socket->socketState = SocketState::SYN_RCVD;
    // }

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
    } else {
      return;
    }
  }

  // /* SYN을 받은 경우 - SYN-ACK 패킷을 전송하며 동시 연결 준비 */
  // if ((SYN & inputFlag) && !(ACK & inputFlag)) {
  //   // 새 패킷 만들어서 synack 보내기
  //   Packet synAckPacket(PACKET_HEADER_SIZE);
  //   setPacketSrcDest(&synAckPacket, destIP, destPort, srcIP, srcPort);

  //   // ACK 번호 설정(받은 SEQ number + 1)
  //   hAck = hSeq + 1;
  //   nAck = htonl(hAck);

  //   /* 난수 생성기 - Morsenne Twiseter 알고리즘을 이용해 1~1000까지의 균일
  //    * 분포를 가지는 난수를 생성한다 */
  //   std::random_device rd;
  //   std::mt19937 gen(rd());
  //   std::uniform_int_distribution<int> distrib(1, 1000);

  //   // SEQ 번호를 생성한 랜덤 넘버로 설정
  //   hSeq = distrib(gen);
  //   nSeq = htonl(hSeq);

  //   // 패킷에 필요한 정보 써넣기
  //   uint8_t dataOffset = 5 << 4;
  //   synAckPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

  //   uint16_t windowSize = htons(65535);
  //   synAckPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);
  //   synAckPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);
  //   synAckPacket.writeData(TCP_SEGMENT_START + 8, &nAck, 4);
  //   outputFlag = SYN | ACK; // SYN-ACK
  //   synAckPacket.writeData(TCP_SEGMENT_START + 13, &outputFlag, 1);
  //   // CHECKSUM
  //   uint8_t tcpSeg[20];
  //   synAckPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
  //   uint16_t calcSum =
  //       ~NetworkUtil::tcp_sum(htonl(destIP), htonl(srcIP), tcpSeg, 20);
  //   calcSum = htons(calcSum);
  //   synAckPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

  //   /* TODO: Timer 설정하기 - payload 어떻게??? packet, ip, port, state? */

  //   //  SYN-ACK 패킷 송신
  //   this->sendPacket("IPv4", std::move(synAckPacket));
  //   socket->socketState = SocketState::SYN_RCVD;
  //   return;
  // }
  return;
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
  /* SocketMap에 없는 소켓을 호출하면 오류 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    printf("bind(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (mySocket->bound) {
    printf("bind(): socket already bound\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  // addrlen not matching
  if (addrlen != sizeof(*addr)) {
    printf("bind(): invalid addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  struct sockaddr_in *toBindAddr =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  struct sockaddr_in *addr_ = (sockaddr_in *)(addr);
  toBindAddr->sin_addr.s_addr = ntohl(addr_->sin_addr.s_addr);
  toBindAddr->sin_port = ntohs(addr_->sin_port);
  toBindAddr->sin_family = AF_INET;

  uint32_t toBindIP = toBindAddr->sin_addr.s_addr;
  in_port_t toBindPort = toBindAddr->sin_port;

  for (const auto &setIter : socketSet) {
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

  struct sockaddr_in *addrtoN =
      (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
  addrtoN->sin_addr.s_addr = htonl(mySocket->myAddr->sin_addr.s_addr);
  addrtoN->sin_port = htons(mySocket->myAddr->sin_port);
  addrtoN->sin_family = AF_INET;

  memcpy(addr, addrtoN, sizeof(struct sockaddr_in));
  *addrlen = sizeof(struct sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd,
                                   int backlog) {
  /* SocketMap에 없는 소켓을 호출하면 오류 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
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
  /* SocketMap에 없는 소켓 호출하면 오류 */
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    printf("connect(): cannot find socket\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  /* 주소 길이값이 유효하지 않을 경우 오류 */
  if (addrlen != sizeof(sockaddr_in)) {
    printf("connect() : bad addrlen\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 일단 blockedProcess로 설정 */
  struct sockaddr *addr_ = (struct sockaddr *)addr;
  blockedProcessHandler.insert(
      std::make_tuple(mySocket, syscallUUID, addr_, &addrlen));

  /* 연결하고자 하는 대상의 ip주소와 port넘버 획득 */
  const struct sockaddr_in *peerAddr = (const struct sockaddr_in *)addr;
  uint32_t peerIP = ntohl(peerAddr->sin_addr.s_addr);
  in_port_t peerPort = ntohs(peerAddr->sin_port);

  /* 내 ip 주소 저장할 변수 초기화 */
  uint32_t myIP;
  in_port_t myPort;

  /* 내 소켓이 unbound인 경우 - implicit binding 실행 */
  if (!(mySocket->bound)) {
    /* ip 계층에서 내가 사용할 NIC ip 획득 */
    ipv4_t peerIP_ =
        NetworkUtil::UINT64ToArray<sizeof(uint32_t)>((uint64_t)peerIP);
    int routingTablePort = getRoutingTable(peerIP_);
    std::optional<ipv4_t> myIPOption = getIPAddr(routingTablePort);
    std::cout << "testes: " << myIPOption.has_value() << std::endl;
    ipv4_t myIP_;
    if (myIPOption.has_value()) {
      myIP_ = myIPOption.value();
    } else {
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
    myIP = ntohl(NetworkUtil::arrayToUINT64(myIP_));

    /* 통신에 사용할 빈 port번호 탐색 */
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

  } else {
    myIP = mySocket->myAddr->sin_addr.s_addr;
    myPort = mySocket->myAddr->sin_port;
  }

  /* 발송할 새로운 SYN packet 생성 */
  Packet synPacket(PACKET_HEADER_SIZE);

  // packet 초기화
  setPacketSrcDest(&synPacket, myIP, myPort, peerIP, peerPort);
  std::cout << myIP << " " << myPort << " " << peerIP << " " << peerPort << " "
            << std::endl;
  // 난수 생성기를 이용한 seqNum 생성
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> distrib(1, 1000);

  uint32_t hSeq = distrib(gen);
  mySocket->expectedAck = hSeq + 1;
  uint32_t nSeq = htonl(hSeq);
  synPacket.writeData(TCP_SEGMENT_START + 4, &nSeq, 4);

  uint8_t dataOffset = 5 << 4;
  synPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

  uint8_t synFlag = 1 << 1;
  synPacket.writeData(TCP_SEGMENT_START + 13, &synFlag, 1);

  uint16_t windowSize = htons(65535);
  synPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);

  // CHECKSUM
  uint8_t tcpSeg[20];
  synPacket.readData(TCP_SEGMENT_START, tcpSeg, 20);
  uint16_t calcSum =
      ~NetworkUtil::tcp_sum(htonl(myIP), htonl(peerIP), tcpSeg, 20);
  calcSum = htons(calcSum);
  synPacket.writeData(TCP_SEGMENT_START + 16, &calcSum, 2);

  this->sendPacket("IPv4", std::move(synPacket));

  if (!mySocket->bound) {
    // socketMap의 fd 의 sockaddr 설정
    mySocket->myAddr = (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    mySocket->myAddr->sin_addr.s_addr = myIP;
    mySocket->myAddr->sin_port = myPort;
    mySocket->myAddr->sin_family = AF_INET;
    /* 내 소켓 상태를 bound로 설정 */
    mySocket->bound = true;
  }
  mySocket->socketState = SocketState::SYN_SENT;

  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   struct sockaddr *addr, socklen_t *addrlen) {
  printf("accept\n");
  // SocketMap에서 현재 pid 와 fd 를 가지는 소켓 포인터 찾기
  struct Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  } // socket이 안 찾아지면 안 됨!
  if (mySocket == nullptr) {
    printf("accept() : socket not found\n");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // accept queue에 아무것도 없으면 일단 block
  // blockHandler 에 정보 저장
  if (mySocket->acceptQueue.empty()) {
    blockedProcessHandler.insert(
        std::make_tuple(mySocket, syscallUUID, addr, addrlen));
    printf("blocking accept\n");
    return;
  }

  std::tuple<struct sockaddr_in *, struct sockaddr_in *> request =
      mySocket->acceptQueue.front();
  mySocket->acceptQueue.pop();
  // 이미 listening queue에 있던 소켓이 다른 소켓과 연결되어있다면 종료.
  // 이미 해당 request ip, port에 대해 serve중이면 종료.

  // 새로운 소켓을 만들어 요청 ip, port 와 연결
  int newMySockFd = createFileDescriptor(pid); // 가상의 파일 디스크립터 생성
  if (newMySockFd < 0) {
    this->returnSystemCall(syscallUUID, -1); // 파일 디스크립터 생성 실패
    return;
  }
  printf("here ");
  // 새 소켓을 클라이언트와 연결된 상태로 설정,
  // 현재 나의 소켓과 socketstate, listeningqueue connected socket제외
  // 모두동일
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

  // 클라이언트 주소 정보를 사용자 공간에 복사
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    struct sockaddr_in *addrtoN =
        (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    addrtoN->sin_addr.s_addr = htonl(newMySocket->myAddr->sin_addr.s_addr);
    addrtoN->sin_port = htons(newMySocket->myAddr->sin_port);
    addrtoN->sin_family = AF_INET;

    memcpy(addr, addrtoN, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  }
  printf("newMySockFd %d\n", newMySockFd);
  // 새로운 소켓 파일 디스크립터 반환
  this->returnSystemCall(syscallUUID, newMySockFd);
  return;
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
  if (mySocket->socketState != SocketState::ESTABLISHED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    struct sockaddr_in *addrtoN =
        (struct sockaddr_in *)malloc(sizeof(sockaddr_in));
    addrtoN->sin_addr.s_addr = htonl(mySocket->connectedAddr->sin_addr.s_addr);
    addrtoN->sin_port = htons(mySocket->connectedAddr->sin_port);
    addrtoN->sin_family = AF_INET;

    memcpy(addr, addrtoN, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  } else {
    printf("addr wrong in getpeername");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->returnSystemCall(syscallUUID, 0);
}

} // namespace E