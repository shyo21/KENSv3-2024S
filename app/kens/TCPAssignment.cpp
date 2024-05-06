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
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

/* 패킷에서 데이터 읽어오기: host byte order로 */
void TCPAssignment::readPacket(Packet *packet, packetInfo *info) {
  uint32_t nsrcIP, ndestIP, nseqNum, nackNum;
  uint16_t ntotLen, nsrcPort, ndestPort, nwinSize, ncheckSum;
  uint8_t nihl, ndataOffset, nflag;

  size_t IP_START = ETHERNET_HEADER_SIZE;
  packet->readData(IP_START, &nihl, 1);
  packet->readData(IP_START + 2, &ntotLen, 2);
  packet->readData(IP_START + 12, &nsrcIP, 4);
  packet->readData(IP_START + 16, &ndestIP, 4);

  size_t IP_HEADER_SIZE = (nihl & 15) * 4;
  size_t TCP_START = ETHERNET_HEADER_SIZE + IP_HEADER_SIZE;
  packet->readData(TCP_START, &nsrcPort, 2);
  packet->readData(TCP_START + 2, &ndestPort, 2);
  packet->readData(TCP_START + 4, &nseqNum, 4);
  packet->readData(TCP_START + 8, &nackNum, 4);
  packet->readData(TCP_START + 12, &ndataOffset, 1);
  packet->readData(TCP_START + 13, &nflag, 1);
  packet->readData(TCP_START + 14, &nwinSize, 2);
  packet->readData(TCP_START + 16, &ncheckSum, 2);

  info->PACKET_SIZE = packet->getSize();

  info->ihl = nihl & 15;
  info->IP_HEADER_SIZE = IP_HEADER_SIZE;
  info->totalLength = ntohs(ntotLen);
  info->srcIP = ntohl(nsrcIP);
  info->destIP = ntohl(ndestIP);

  info->srcPort = ntohs(nsrcPort);
  info->destPort = ntohs(ndestPort);
  info->seqNum = ntohl(nseqNum);
  info->ackNum = ntohl(nackNum);
  info->dataOffset = ndataOffset >> 4;
  info->TCP_HEADER_SIZE = (ndataOffset >> 4) * 4;
  info->flag = nflag;
  info->windowSize = ntohs(nwinSize);
  info->checkSum = ntohs(ncheckSum);
}

/* 패킷에 데이터 작성하기: network byte order로 */
void TCPAssignment::writePacket(Packet *packet, packetInfo *info) {
  uint32_t nsrcIP, ndestIP, nseqNum, nackNum;
  uint16_t nsrcPort, ndestPort, nwinSize;
  uint8_t ndataOffset, nflag;

  nsrcIP = htonl(info->srcIP);
  ndestIP = htonl(info->destIP);

  nsrcPort = htons(info->srcPort);
  ndestPort = htons(info->destPort);
  nseqNum = htonl(info->seqNum);
  nackNum = htonl(info->ackNum);
  ndataOffset = (info->dataOffset) << 4;
  nflag = info->flag;
  nwinSize = htons(info->windowSize);

  size_t IP_START = ETHERNET_HEADER_SIZE;
  packet->writeData(IP_START + 12, &nsrcIP, 4);
  packet->writeData(IP_START + 16, &ndestIP, 4);

  size_t TCP_START = ETHERNET_HEADER_SIZE + info->IP_HEADER_SIZE;
  packet->writeData(TCP_START, &nsrcPort, 2);
  packet->writeData(TCP_START + 2, &ndestPort, 2);
  packet->writeData(TCP_START + 4, &nseqNum, 4);
  packet->writeData(TCP_START + 8, &nackNum, 4);
  packet->writeData(TCP_START + 12, &ndataOffset, 1);
  packet->writeData(TCP_START + 13, &nflag, 1);
  packet->writeData(TCP_START + 14, &nwinSize, 2);
}

void TCPAssignment::writeCheckSum(Packet *packet) {
  uint32_t nsrcIP, ndestIP;
  uint16_t ncheckSum, checkSum;
  uint8_t nihl;

  size_t PACKET_SIZE = packet->getSize();

  size_t IP_START = ETHERNET_HEADER_SIZE;
  packet->readData(IP_START + 12, &nsrcIP, 4);
  packet->readData(IP_START + 16, &ndestIP, 4);

  size_t TCP_START = IP_START + 20;
  size_t TCP_SIZE = PACKET_SIZE - TCP_START;

  uint8_t tcpSeg[TCP_SIZE];
  packet->readData(TCP_START, tcpSeg, TCP_SIZE);
  checkSum = ~NetworkUtil::tcp_sum(nsrcIP, ndestIP, tcpSeg, TCP_SIZE);
  ncheckSum = htons(checkSum);

  packet->writeData(TCP_START + 16, &ncheckSum, 2);
}

bool TCPAssignment::isCheckSum(Packet *packet) {
  uint32_t nsrcIP, ndestIP;
  uint16_t ncheckSum, rcvCheckSum, calCheckSum, masking;
  uint8_t nihl;

  size_t PACKET_SIZE = packet->getSize();

  size_t IP_START = ETHERNET_HEADER_SIZE;
  packet->readData(IP_START + 12, &nsrcIP, 4);
  packet->readData(IP_START + 16, &ndestIP, 4);

  size_t TCP_START = IP_START + 20;
  size_t TCP_SIZE = PACKET_SIZE - TCP_START;

  uint8_t tcpSeg[TCP_SIZE];
  packet->readData(TCP_START, tcpSeg, TCP_SIZE);
  calCheckSum = NetworkUtil::tcp_sum(nsrcIP, ndestIP, tcpSeg, TCP_SIZE);

  return 0xFFFF == calCheckSum;
}

/* 패킷에 담긴 ip-port 쌍을 이용해 적합한 소켓 선택 */
Socket *TCPAssignment::getSocket(std::pair<uint32_t, in_port_t> destAddrPair,
                                 std::pair<uint32_t, in_port_t> srcAddrPair) {
  uint32_t destIP = std::get<0>(destAddrPair);
  in_port_t destPort = std::get<1>(destAddrPair);
  uint32_t srcIP = std::get<0>(srcAddrPair);
  in_port_t srcPort = std::get<1>(srcAddrPair);

  Socket *mySocket = nullptr;

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
        }
      }
    }
  }
  return mySocket;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  std::pair<uint32_t, in_port_t> srcAddrPair, destAddrPair;

  /* 패킷에서 정보 읽어오기 */
  packetInfo *info = new packetInfo;
  readPacket(&packet, info);

  /* socketSet 탐색을 통해 적합한 소켓 선택 */
  srcAddrPair = std::make_pair(info->srcIP, info->srcPort);
  destAddrPair = std::make_pair(info->destIP, info->destPort);
  Socket *mySocket = getSocket(destAddrPair, srcAddrPair);
  if (mySocket == nullptr) {
    // printf("packetArrived(): cannot find socket\n");
    return;
  }
  if (!isCheckSum(&packet)) {
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

  delete info;
  info = nullptr;
}

void TCPAssignment::handleListening(Packet *packet, Socket *socket) {
  /* 패킷에서 필요한 정보 추출: host-order */
  packetInfo *info = new packetInfo;
  readPacket(packet, info);

  /* SYN 패킷인 경우 */
  if ((SYN & info->flag) && !(ACK & info->flag)) {

    /* SYNACK 패킷 생성 */
    packetInfo *synackInfo = new packetInfo;
    Packet *synackPacket = new Packet(DEFAULT_HEADER_SIZE);

    synackInfo->srcIP = info->destIP;
    synackInfo->destIP = info->srcIP;

    synackInfo->srcPort = info->destPort;
    synackInfo->destPort = info->srcPort;

    /* 난수 생성기 */
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> distrib(1, 1000);
    synackInfo->seqNum = distrib(gen);
    synackInfo->ackNum = info->seqNum + 1;
    synackInfo->flag = SYN | ACK;

    writePacket(synackPacket, synackInfo);
    writeCheckSum(synackPacket);

    /* SYN-ACK 패킷 송신 */
    Packet *clonePacket = new Packet(synackPacket->clone());
    this->sendPacket("IPv4", std::move(*synackPacket));

    /* synack TIMER 생성 */
    unackedInfo *u_info = new unackedInfo;

    UUID synackTimer = addTimer(std::any(socket), socket->timeoutInterval);
    Time sentTime = getCurrentTime();

    u_info->packet = clonePacket;
    u_info->timerUUID = synackTimer;
    u_info->sentTime = sentTime;

    socket->unAckedPackets.emplace_back(u_info);

    /* Socket data update*/
    socket->socketState = SocketState::SYN_RCVD;
    socket->sentSeq = synackInfo->seqNum + 1;
    socket->sentAck = synackInfo->ackNum;

    delete synackInfo;
    synackInfo = nullptr;

  } else {
    // printf("handleListening(): not SYN packet\n");
  }

  delete info;
  info = nullptr;
}

void TCPAssignment::handleSYNSent(Packet *packet, Socket *socket) {
  /* 패킷에서 필요한 정보 추출: host-order */
  packetInfo *info = new packetInfo;
  readPacket(packet, info);

  /* SYN-ACK 패킷인 경우 */
  if ((SYN & info->flag) && (ACK & info->flag)) {

    if (info->ackNum != socket->sentSeq + 1) {
      // printf("handleSYNSent(): wrong ack num\n");
      return;
    }

    unackedInfo *u_info = socket->unAckedPackets.front();
    // cancelTimer()
    cancelTimer(u_info->timerUUID);
    // RTT 확인(현재 시점 - 보낸 시점) 및 업데이트
    socket->sampleRTT = getCurrentTime() - u_info->sentTime;
    getRTT(socket);

    delete u_info->packet;
    u_info->packet = nullptr;

    // unAckedPackets 에서 삭제
    socket->unAckedPackets.erase(socket->unAckedPackets.begin());

    delete u_info;
    u_info = nullptr;

    /* ACK 패킷 생성 */
    packetInfo *ackInfo = new packetInfo;
    Packet *ackPacket = new Packet(DEFAULT_HEADER_SIZE);

    ackInfo->srcIP = info->destIP;
    ackInfo->destIP = info->srcIP;

    ackInfo->srcPort = info->destPort;
    ackInfo->destPort = info->srcPort;

    ackInfo->seqNum = info->ackNum;
    ackInfo->ackNum = info->seqNum + 1;
    ackInfo->flag = ACK;

    writePacket(ackPacket, ackInfo);
    writeCheckSum(ackPacket);

    /* ACK 패킷 송신 */
    this->sendPacket("IPv4", std::move(*ackPacket));

    /* 소켓 정보 설정 */
    socket->connectedAddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
    memset(socket->connectedAddr, 0, sizeof(sockaddr_in));
    socket->connectedAddr->sin_addr.s_addr = info->srcIP;
    socket->connectedAddr->sin_port = info->srcPort;
    socket->connectedAddr->sin_family = AF_INET;

    socket->socketState = SocketState::ESTABLISHED;
    socket->sentSeq = ackInfo->seqNum;
    socket->sentAck = ackInfo->ackNum;

    /* 처리한게 connect에서 block된 프로세스인지 확인 */
    if (!blockHandler.empty()) {

      for (const auto &setIter : blockHandler) {

        Socket *mySocket = setIter->socket;
        UUID syscallUUID = setIter->uuid;

        if ((mySocket->pid == socket->pid) && (mySocket->fd == socket->fd) &&
            setIter->type == blockedState::CONNECT) {

          this->returnSystemCall(syscallUUID, 0);

          blockHandler.erase(setIter);
          delete setIter;

          break;
        }
      }
    }

    delete ackInfo;
    ackInfo = nullptr;
  }

  delete info;
  info = nullptr;
}

void TCPAssignment::handleSYNRcvd(Packet *packet, Socket *socket) {
  /* 패킷에서 필요한 정보 추출: host-order */
  packetInfo *info = new packetInfo;
  readPacket(packet, info);

  sockaddr_in *myAddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
  myAddr->sin_family = AF_INET;
  myAddr->sin_addr.s_addr = info->destIP;
  myAddr->sin_port = info->destPort;

  sockaddr_in *peerAddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
  peerAddr->sin_family = AF_INET;
  peerAddr->sin_addr.s_addr = info->srcIP;
  peerAddr->sin_port = info->srcPort;

  /* 연속된 SYN 패킷은 소켓의 리스닝큐에 일단 저장
   * backlog 넘치지 않게 확인 */
  if ((SYN & info->flag) && !(ACK & info->flag)) {
    if ((socket->BACKLOG - 1) > socket->listeningQueue.size()) {
      Packet temp = *packet;
      socket->listeningQueue.push(temp);
      return;
    }
  }

  /* ACK 패킷인 경우 */
  if (ACK & info->flag) {
    // unAckedPacket의 맨 앞에꺼 뽑아와서 정보 획득
    unackedInfo *u_info = socket->unAckedPackets.front();

    // cancelTimer()
    cancelTimer(u_info->timerUUID);
    // RTT 확인(현재 시점 - 보낸 시점) 및 업데이트
    socket->sampleRTT = getCurrentTime() - u_info->sentTime;
    getRTT(socket);

    delete u_info->packet;
    u_info->packet = nullptr;

    // unAckedPackets 에서 삭제
    socket->unAckedPackets.erase(socket->unAckedPackets.begin());

    delete u_info;
    u_info = nullptr;

    /* 만약 block된 accept 프로세스가 있다면 여기서 처리 */
    if (!blockHandler.empty()) {

      for (const auto &setIter : blockHandler) {

        Socket *mySocket = setIter->socket;
        UUID syscallUUID = setIter->uuid;

        if ((mySocket->pid == socket->pid) && (mySocket->fd == socket->fd) &&
            setIter->type == blockedState::ACCEPT) {

          int newMySockFd = createFileDescriptor(mySocket->pid);
          if (newMySockFd < 0) {
            this->returnSystemCall(syscallUUID, -1);
            return;
          }

          /* 클라이언트와 연결될 새 소켓 */
          Socket *newMySocket = new Socket;
          newMySocket->domain = mySocket->domain;
          newMySocket->type = mySocket->type;
          newMySocket->protocol = mySocket->protocol;
          newMySocket->pid = mySocket->pid;
          newMySocket->fd = newMySockFd;

          newMySocket->bound = true;
          newMySocket->socketState = SocketState::ESTABLISHED;

          newMySocket->myAddr = myAddr;
          newMySocket->connectedAddr = peerAddr;

          newMySocket->sentSeq = mySocket->sentSeq;
          newMySocket->sentAck = mySocket->sentAck;

          /* 소켓에 저장된 addr 추출: network-order */
          if (setIter->addr != nullptr &&
              *(setIter->addrlenptr) >= sizeof(sockaddr_in) &&
              myAddr != nullptr) {

            sockaddr_in *addrtoN = (sockaddr_in *)malloc(sizeof(sockaddr_in));
            addrtoN->sin_addr.s_addr = htonl(myAddr->sin_addr.s_addr);
            addrtoN->sin_port = htons(myAddr->sin_port);
            addrtoN->sin_family = AF_INET;

            /* 추출한 addr 복사 */
            memcpy(setIter->addr, addrtoN, *(setIter->addrlenptr));
            free(addrtoN);

            /* 새로 생성한 소켓 추가 */
            socketSet.insert(newMySocket);

            this->returnSystemCall(syscallUUID, newMySockFd);

            blockHandler.erase(setIter);
            delete setIter;

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

  delete info;
  info = nullptr;
}

void TCPAssignment::handleEstab(Packet *packet, Socket *socket) {
  /* 패킷에서 정보 읽어오기 */
  packetInfo *info = new packetInfo;
  readPacket(packet, info);

  size_t payloadLength =
      info->totalLength - (info->IP_HEADER_SIZE + info->TCP_HEADER_SIZE);
  size_t TCP_START = ETHERNET_HEADER_SIZE + info->IP_HEADER_SIZE;

  // synack packet을 받았을 때 처리
  /* ACK 패킷을 다시 전송*/

  /* 받은 패킷에 데이터 payload가 들어있는 경우 */
  if (payloadLength > 0) {

    /* 내가 기대하던 seqnum이 아닌경우 fast retransmit */
    if (socket->sentAck != info->seqNum) {
      /* 개같이 받은 패킷에 대한 ACK 발송 */
      packetInfo *ackInfo = new packetInfo;
      Packet *ackPacket = new Packet(DEFAULT_HEADER_SIZE);

      ackInfo->srcIP = info->destIP;
      ackInfo->destIP = info->srcIP;

      ackInfo->srcPort = info->destPort;
      ackInfo->destPort = info->srcPort;
      ackInfo->seqNum = socket->sentSeq;
      ackInfo->ackNum = socket->sentAck;

      ackInfo->flag = ACK;
      ackInfo->windowSize = info->windowSize;

      writePacket(ackPacket, ackInfo);
      writeCheckSum(ackPacket);

      this->sendPacket("IPv4", std::move(*ackPacket));

      delete ackInfo;
      ackInfo = nullptr;
      return;
    };
    /* TODO: 내가 이미 받은 패킷인 경우 fast retransmit */

    /* 새로운 패킷인 경우 데이터를 내 버퍼로 복사 */
    std::vector<char> payload(payloadLength);
    packet->readData(TCP_START + info->TCP_HEADER_SIZE, payload.data(),
                     payloadLength);

    socket->receiveBuffer.push_back(payload);

    /* read()에서 blocked된 process인지 확인 */
    if (!blockHandler.empty()) {

      for (auto setIter = blockHandler.begin();
           setIter != blockHandler.end();) {

        blockedProcess *readBlock = *setIter;

        Socket *mySocket = readBlock->socket;
        UUID syscallUUID = readBlock->uuid;
        void *buf = readBlock->buf;
        size_t count = readBlock->count;

        if ((mySocket->pid == socket->pid) && (mySocket->fd == socket->fd) &&
            readBlock->type == blockedState::READ) {

          char *data = static_cast<char *>(buf);
          size_t copiedSize = 0;

          while (!mySocket->receiveBuffer.empty() && copiedSize < count) {
            std::vector<char> &chunk = mySocket->receiveBuffer.front();
            size_t remainingSize = count - copiedSize;
            size_t copySize = std::min(chunk.size(), remainingSize);

            std::copy(chunk.begin(), chunk.begin() + copySize,
                      data + copiedSize);
            copiedSize += copySize;

            if (copySize == chunk.size()) {
              mySocket->receiveBuffer.erase(mySocket->receiveBuffer.begin());
            } else {
              chunk.erase(chunk.begin(), chunk.begin() + copySize);
            }
          }

          this->returnSystemCall(syscallUUID, copiedSize);

          setIter = blockHandler.erase(setIter);
          delete readBlock;

        } else {
          ++setIter;
        }
      }
    }

    /* 정상적으로 복사완료한 패킷에 대한 ACK 발송 */
    packetInfo *ackInfo = new packetInfo;
    Packet *ackPacket = new Packet(DEFAULT_HEADER_SIZE);

    ackInfo->srcIP = info->destIP;
    ackInfo->destIP = info->srcIP;

    ackInfo->srcPort = info->destPort;
    ackInfo->destPort = info->srcPort;
    ackInfo->seqNum = info->ackNum;
    ackInfo->ackNum = info->seqNum + payloadLength;

    ackInfo->flag = ACK;
    ackInfo->windowSize = info->windowSize;

    writePacket(ackPacket, ackInfo);
    writeCheckSum(ackPacket);

    this->sendPacket("IPv4", std::move(*ackPacket));

    socket->sentSeq = ackInfo->seqNum;
    socket->sentAck = ackInfo->ackNum;

    delete ackInfo;
    ackInfo = nullptr;
  }

  /* 빈 ACK 패킷인 경우 */
  else if (ACK & info->flag) {
    if (socket->unAckedPackets.empty()) {
      // TODO: ack이 왔는데 unackedpacket이 비어있다면???
      return;
    }

    uint32_t expAck = socket->unAckedPackets.front()->expectedAck;
    Time currTime = getCurrentTime();

    /* 받은 ack넘버가 예상값과 일치하는 경우 */
    if (info->ackNum >= expAck) {

      for (auto unackIter = socket->unAckedPackets.begin();
           unackIter != socket->unAckedPackets.end();) {

        unackedInfo *unackInfo = *unackIter;

        if (info->ackNum > unackInfo->expectedAck) {

          socket->sendNext -= unackInfo->dataSize;

          cancelTimer(unackInfo->timerUUID);

          delete unackInfo->packet;
          unackInfo->packet = nullptr;

          unackIter = socket->unAckedPackets.erase(unackIter);
          delete unackInfo;
        }

        else if (info->ackNum == unackInfo->expectedAck) {

          socket->sendNext -= unackInfo->dataSize;

          cancelTimer(unackInfo->timerUUID);
          socket->sampleRTT = currTime - unackInfo->sentTime;
          getRTT(socket);

          delete unackInfo->packet;
          unackInfo->packet = nullptr;

          socket->unAckedPackets.erase(unackIter);
          delete unackInfo;

          break;
        }

        else {
          break;
        }
      }
    }

    else {
      /* expectedAck > info->ackNum */

      return;
    }

    /* 보내야 할 데이터가 더 남았는지 확인 */
    if (!socket->sendBuffer.empty()) {
      sendData(socket);
    }

    else {
      if (!blockHandler.empty()) {
        for (const auto &setIter : blockHandler) {
          Socket *mySocket = setIter->socket;
          UUID syscallUUID = setIter->uuid;
          int pid = socket->pid;
          int fd = socket->fd;

          if ((mySocket->pid == pid) && (mySocket->fd == fd) &&
              setIter->type == blockedState::CLOSE) {

            // socketSet.erase(mySocket);
            // deleteSocket(mySocket);
            // this->removeFileDescriptor(pid, fd);

            this->returnSystemCall(syscallUUID, 0);

            blockHandler.erase(setIter);
            delete setIter;

            break;
          }
        }
      }
    }
  }

  /* FIN ACK 패킷인 경우 */
  else if (FIN & info->flag && ACK & info->flag) {
    // printf("estab handle");
    /* 정상적으로 복사완료한 패킷에 대한 ACK 발송 */
    packetInfo *ackInfo = new packetInfo;
    Packet *ackPacket = new Packet(DEFAULT_HEADER_SIZE);

    ackInfo->srcIP = info->destIP;
    ackInfo->destIP = info->srcIP;

    ackInfo->srcPort = info->destPort;
    ackInfo->destPort = info->srcPort;
    ackInfo->seqNum = info->ackNum;
    ackInfo->ackNum = info->seqNum;
    ackInfo->flag = ACK;
    ackInfo->windowSize = info->windowSize;

    writePacket(ackPacket, ackInfo);
    writeCheckSum(ackPacket);

    this->sendPacket("IPv4", std::move(*ackPacket));

    delete ackInfo;
    ackInfo = nullptr;
  }

  delete info;
  info = nullptr;
}

void TCPAssignment::sendData(Socket *socket) {
  while (!socket->sendBuffer.empty()) {

    size_t dataSize = std::get<3>(socket->sendBuffer.front()).size();
    size_t currWndEdge = socket->windowSize;
    size_t neededEdge = socket->sendNext + dataSize;

    if (currWndEdge > neededEdge) {
      size_t packetSize = DEFAULT_HEADER_SIZE + dataSize;

      packetInfo *dataInfo = new packetInfo;
      Packet *dataPacket = new Packet(packetSize);

      dataInfo->srcIP = socket->myAddr->sin_addr.s_addr;
      dataInfo->destIP = socket->connectedAddr->sin_addr.s_addr,

      dataInfo->srcPort = socket->myAddr->sin_port,
      dataInfo->destPort = socket->connectedAddr->sin_port;
      dataInfo->seqNum = socket->sentSeq + socket->sentSize;
      dataInfo->ackNum = socket->sentAck;
      dataInfo->flag = ACK;

      writePacket(dataPacket, dataInfo);
      dataPacket->writeData(DEFAULT_HEADER_SIZE,
                            std::get<3>(socket->sendBuffer.front()).data(),
                            dataSize);
      writeCheckSum(dataPacket);

      Packet *clonePacket = new Packet(dataPacket->clone());

      this->sendPacket("IPv4", std::move(*dataPacket));

      socket->sentSize = dataSize;
      socket->sendNext += packetSize;
      socket->sentSeq = dataInfo->seqNum;
      socket->sentAck = dataInfo->ackNum;
      socket->sendBuffer.erase(socket->sendBuffer.begin());

      unackedInfo *u_info = new unackedInfo;

      u_info->expectedAck = socket->sentSeq + dataSize;
      u_info->dataSize = dataSize;

      u_info->packet = clonePacket;
      u_info->timerUUID = addTimer(socket, socket->timeoutInterval);
      u_info->sentTime = getCurrentTime();

      socket->unAckedPackets.emplace_back(u_info);

      delete dataInfo;
      dataInfo = nullptr;
    } else {
      return;
    }
  }
}

void TCPAssignment::deleteSocket(Socket *socket) {
  if (socket == nullptr)
    return;

  free(socket->connectedAddr);

  while (!socket->listeningQueue.empty())
    socket->listeningQueue.pop();

  while (!socket->acceptQueue.empty())
    socket->acceptQueue.pop();

  delete socket;
}

void TCPAssignment::timerCallback(std::any payload) {
  Socket *mySocket = nullptr;

  if (payload.has_value()) {
    mySocket = std::any_cast<Socket *>(payload);
  } else {
    return;
  }

  for (auto info : mySocket->unAckedPackets) {
    cancelTimer(info->timerUUID);

    UUID newTimer = addTimer(mySocket, mySocket->timeoutInterval);
    Time sentTime = getCurrentTime();

    info->timerUUID = newTimer;
    info->sentTime = sentTime;

    Packet *clonePacket = new Packet(info->packet->clone());

    this->sendPacket("IPv4", std::move(*info->packet));

    info->packet = clonePacket;
  }
}

void TCPAssignment::getRTT(Socket *socket) {
  Time estimatedRTT =
      (1 - ALPHA) * (socket->estimatedRTT) + ALPHA * socket->sampleRTT;

  Time devRTT;
  if (socket->sampleRTT >= socket->estimatedRTT) {
    devRTT = (1 - BETA) * (socket->devRTT) +
             BETA * (socket->sampleRTT - socket->estimatedRTT);
  } else {
    devRTT = (1 - BETA) * (socket->devRTT) +
             BETA * (socket->estimatedRTT - socket->sampleRTT);
  }

  Time timeoutInterval = estimatedRTT + 4 * devRTT;

  socket->estimatedRTT = estimatedRTT;
  socket->devRTT = devRTT;
  socket->timeoutInterval = timeoutInterval;
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
  Socket *mySocket = nullptr;
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

  if (!mySocket->sendBuffer.empty() || !mySocket->unAckedPackets.empty()) {

    blockedProcess *closeBlock = new blockedProcess;

    closeBlock->type = blockedState::CLOSE;
    closeBlock->socket = mySocket;
    closeBlock->uuid = syscallUUID;

    blockHandler.insert(closeBlock);
    return;
  }

  socketSet.erase(mySocket);
  deleteSocket(mySocket);
  this->removeFileDescriptor(pid, fd);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd,
                                 const sockaddr *addr, socklen_t addrlen) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
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
  sockaddr_in *toBindAddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
  sockaddr_in *addr_ = (sockaddr_in *)(addr);
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
  mySocket->myAddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
  memcpy(mySocket->myAddr, toBindAddr, sizeof(sockaddr_in));
  mySocket->bound = true;

  free(toBindAddr);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,
                                        sockaddr *addr, socklen_t *addrlen) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
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
  sockaddr_in *addrtoN = (sockaddr_in *)malloc(sizeof(sockaddr_in));
  addrtoN->sin_addr.s_addr = htonl(mySocket->myAddr->sin_addr.s_addr);
  addrtoN->sin_port = htons(mySocket->myAddr->sin_port);
  addrtoN->sin_family = AF_INET;

  /* 추출한 addr 복사 */
  memcpy(addr, addrtoN, sizeof(sockaddr_in));
  *addrlen = sizeof(sockaddr_in);

  free(addrtoN);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd,
                                   int backlog) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
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
                                    const sockaddr *addr, socklen_t addrlen) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
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
  blockedProcess *connectBlock = new blockedProcess;

  connectBlock->type = blockedState::CONNECT;
  connectBlock->socket = mySocket;
  connectBlock->uuid = syscallUUID;

  connectBlock->addr =
      reinterpret_cast<sockaddr_in *>(const_cast<sockaddr *>(addr));
  connectBlock->addrlen = addrlen;

  blockHandler.insert(connectBlock);

  /* 연결대상의 ip-port 획득: host-order */
  const sockaddr_in *peerAddr = (const sockaddr_in *)addr;
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

  /* SYN 패킷 생성 */
  packetInfo *synInfo = new packetInfo;
  Packet *synPacket = new Packet(DEFAULT_HEADER_SIZE);

  synInfo->srcIP = myIP;
  synInfo->destIP = peerIP;

  synInfo->srcPort = myPort;
  synInfo->destPort = peerPort;

  /* 난수 생성기 */
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> distrib(1, 1000);
  synInfo->seqNum = distrib(gen);
  synInfo->flag = SYN;

  writePacket(synPacket, synInfo);
  writeCheckSum(synPacket);

  Packet *clonePacket = new Packet(synPacket->clone());
  this->sendPacket("IPv4", std::move(*synPacket));

  // syn TIMER 생성
  unackedInfo *u_info = new unackedInfo;

  UUID synTimer = addTimer(std::any(mySocket), mySocket->timeoutInterval);
  Time sentTime = getCurrentTime();

  u_info->packet = clonePacket;
  u_info->timerUUID = synTimer;
  u_info->sentTime = sentTime;

  mySocket->unAckedPackets.emplace_back(u_info);

  /* implicit binding */
  if (!mySocket->bound) {
    mySocket->myAddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
    mySocket->myAddr->sin_addr.s_addr = myIP;
    mySocket->myAddr->sin_port = myPort;
    mySocket->myAddr->sin_family = AF_INET;
    mySocket->bound = true;
  }

  mySocket->socketState = SocketState::SYN_SENT;
  mySocket->sentSeq = synInfo->seqNum;

  delete synInfo;
  synInfo = nullptr;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   sockaddr *addr, socklen_t *addrlen) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
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

    blockedProcess *acceptBlock = new blockedProcess;

    acceptBlock->type = blockedState::ACCEPT;
    acceptBlock->socket = mySocket;
    acceptBlock->uuid = syscallUUID;

    acceptBlock->addr = reinterpret_cast<sockaddr_in *>(addr);
    acceptBlock->addrlenptr = addrlen;

    blockHandler.insert(acceptBlock);
    return;
  }

  /* acceptQueue에서 요청 추출 */
  std::tuple<sockaddr_in *, sockaddr_in *> request =
      mySocket->acceptQueue.front();
  mySocket->acceptQueue.pop();

  /* 새로운 fd 생성 */
  int newMySockFd = createFileDescriptor(pid);
  if (newMySockFd < 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* 새로운 소켓: 기본적으로 내 clone, with modifications */
  Socket *newMySocket = new Socket;
  newMySocket->domain = mySocket->domain;
  newMySocket->type = mySocket->type;
  newMySocket->protocol = mySocket->protocol;
  newMySocket->pid = mySocket->pid;
  newMySocket->fd = newMySockFd;

  newMySocket->bound = true;
  newMySocket->socketState = SocketState::ESTABLISHED;

  newMySocket->myAddr = mySocket->myAddr;
  newMySocket->connectedAddr = std::get<1>(request);

  newMySocket->sentSeq = mySocket->sentSeq;
  newMySocket->sentAck = mySocket->sentAck;

  socketSet.insert(newMySocket);

  /* 소켓에 저장된 addr 추출: network-order */
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    sockaddr_in *addrtoN = (sockaddr_in *)malloc(sizeof(sockaddr_in));
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
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd,
                                        sockaddr *addr, socklen_t *addrlen) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
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
    sockaddr_in *addrtoN = (sockaddr_in *)malloc(sizeof(sockaddr_in));
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

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf,
                                 size_t count) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (mySocket->socketState != SocketState::ESTABLISHED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* recieveBuffer가 비어있다면 읽을 데이터가 도착할 때까지 block */
  if (mySocket->receiveBuffer.empty()) {

    blockedProcess *readBlock = new blockedProcess;

    readBlock->type = blockedState::READ;
    readBlock->socket = mySocket;
    readBlock->uuid = syscallUUID;

    readBlock->buf = buf;
    readBlock->count = count;

    blockHandler.insert(readBlock);

    return;
  }

  /* buf가 수용할 수 있는 만큼 데이터를 복사, 나머지는 receive버퍼에 유지 */
  char *data = static_cast<char *>(buf);
  size_t copiedSize = 0;

  while (!mySocket->receiveBuffer.empty() && copiedSize < count) {
    std::vector<char> &chunk = mySocket->receiveBuffer.front();
    size_t remainingSize = count - copiedSize;
    size_t copySize = std::min(chunk.size(), remainingSize);

    std::copy(chunk.begin(), chunk.begin() + copySize, data + copiedSize);
    copiedSize += copySize;

    if (copySize == chunk.size()) {
      mySocket->receiveBuffer.erase(mySocket->receiveBuffer.begin());
    } else {
      chunk.erase(chunk.begin(), chunk.begin() + copySize);
      // break;
    }
  }

  this->returnSystemCall(syscallUUID, copiedSize);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd,
                                  const void *buf, size_t count) {
  /* 소켓 탐색 */
  Socket *mySocket = nullptr;
  for (const auto &setIter : socketSet) {
    if ((setIter->pid == pid) && (setIter->fd == fd)) {
      mySocket = setIter;
    }
  }
  if (mySocket == nullptr) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  if (mySocket->socketState != SocketState::ESTABLISHED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  /* buf에 있는 데이터를 sendBuffer로 복사 */
  const char *data = static_cast<const char *>(buf);
  size_t remaining = count;
  size_t offset = 0;

  /* 최대 크기 512바이트의 청크로 나누어서 저장 */
  while (remaining > 0) {
    size_t chunkSize = std::min(remaining, static_cast<size_t>(512));
    std::vector<char> chunk(data + offset, data + offset + chunkSize);

    remaining -= chunkSize;
    offset += chunkSize;

    if (offset != count) {
      mySocket->sendBuffer.emplace_back(false, syscallUUID, count, chunk);
    } else {
      mySocket->sendBuffer.emplace_back(true, syscallUUID, count, chunk);
    }
  }

  this->returnSystemCall(syscallUUID, count);

  /* sendBuffer에 있는 데이터를 패킷으로 만들어 발송 */
  sendData(mySocket);
}

} // namespace E