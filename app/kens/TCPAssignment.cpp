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

void TCPAssignment::getSrcIP(Packet *packet, uint32_t *ipaddr) {
  packet->readData(IP_DATAGRAM_START + 12, ipaddr, 4);
}

void TCPAssignment::getDestIP(Packet *packet, uint32_t *ipaddr) {
  packet->readData(IP_DATAGRAM_START + 16, ipaddr, 4);
}

void TCPAssignment::getSrcPort(Packet *packet, uint16_t *port) {
  packet->readData(TCP_SEGMENT_START, port, 2);
}

void TCPAssignment::getDestPort(Packet *packet, uint16_t *port) {
  packet->readData(TCP_SEGMENT_START + 2, port, 2);
}

void TCPAssignment::getFlags(Packet *packet, uint8_t *flag) {
  packet->readData(TCP_SEGMENT_START + 13, flag, 1);
}

void TCPAssignment::setPacketSrcDest(Packet *packet, uint32_t *srcIp,
                                     uint16_t *srcPort, uint32_t *destIp,
                                     uint16_t *destPort) {
  packet->writeData(IP_DATAGRAM_START + 12, srcIp, 4);
  packet->writeData(IP_DATAGRAM_START + 16, destIp, 4);
  packet->writeData(TCP_SEGMENT_START, srcPort, 2);
  packet->writeData(TCP_SEGMENT_START + 2, destPort, 2);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint32_t srcIP, destIP;
  uint16_t srcPort, destPort;
  uint8_t flags;
  // 패킷에서 필요한 정보 추출
  getSrcIP(&packet, &srcIP);
  getSrcPort(&packet, &srcPort);
  getDestIP(&packet, &destIP);
  getDestPort(&packet, &destPort);
  getFlags(&packet, &flags);
  // SEQ, ACK Number
  uint32_t seqNum;
  uint32_t ackNum;

  packet.readData(TCP_SEGMENT_START + 4, &seqNum, 4); // seqNum
  packet.readData(TCP_SEGMENT_START + 8, &ackNum, 4); // ackNum

  std::pair<uint32_t, in_port_t> destAddrPair =
      std::make_pair(destIP, destPort);
  std::pair<uint32_t, in_port_t> srcAddrPair = std::make_pair(srcIP, srcPort);

  bool SYN = flags & (1 << 1); // SYN 플래그 검사
  bool ACK = flags & (1 << 4); // ACK 플래그 검사
  // SYN 패킷 처리 (클라이언트로부터의 연결 요청) / SYN_RCV
  if (SYN && !ACK) {
    // 이미 syn을 받은 적이 있는지 확인
    // syn 패킷을 받은놈(dest ip dest port) << 얘가 listen()중이고, 우리
    // sockMap에 있는놈인가?
    // 새로운 SYN-ACK 패킷 생성 및 초기 설정
    Packet synAckPacket = packet.clone(); // cloning -> different UUID
    // destport and srcport exchange
    setPacketSrcDest(&synAckPacket, &destIP, &destPort, &srcIP, &srcPort);

    ackNum = seqNum + 1; // ACK 번호 설정(받은 SEQ number + 1)
    // SEQ number = randomnumber
    // 난수 생성기 초기화
    std::random_device rd; // 비결정적 난수 생성기를 사용하여 시드를 생성
    std::mt19937 gen(rd()); // Mersenne Twister 알고리즘을 사용하는 생성기
    // 1부터 1000까지의 균일 분포를 가진 난수 생성
    std::uniform_int_distribution<int> distrib(1, 1000);
    seqNum = distrib(gen);
    // 내 state SYN_RCV로 만들고 seq, ack 설정
    handShakingMap[destAddrPair][srcAddrPair] =
        std::make_tuple(SocketState::SYN_RCV, seqNum, ackNum);
    // sequence number - 따로 지정
    synAckPacket.writeData(TCP_SEGMENT_START + 4, &seqNum, 4);
    // ACK number - 받은 seq number +1
    synAckPacket.writeData(TCP_SEGMENT_START + 8, &ackNum, 2);
    // SYN 및 ACK 플래그 설정
    flags = (1 << 1) | (1 << 4); // SYN-ACK
    synAckPacket.writeData(13, &flags, 1);
    // timer 설정하기
    // payload 어떻게??? packet, ip, port, state?

    //  SYN-ACK 패킷 송신
    this->sendPacket("IPv4", std::move(synAckPacket));
  }
  // SYNACK패킷처리 / ack = seq+1 , seq random 설정
  if (ACK && SYN) {
    auto myIter = handShakingMap.find(destAddrPair);
    if (myIter != handShakingMap.end()) {
      auto peerIter = myIter->second.find(srcAddrPair);
      if (peerIter != myIter->second.end()) {
        // state = SYN_SENT인지 확인, seq +1 = ackNum 인지 확인
        if ((std::get<0>(peerIter->second) == SocketState::SYN_SENT) &&
            (std::get<1>(peerIter->second) + 1 == ackNum)) {
          handShakingMap[destAddrPair][srcAddrPair] =
              std::make_tuple(SocketState::ESTABLISHED, -1, -1);
        }
      } else {
        printf("No match SYN_RCV pair");
        return;
      }
    } else {
      printf("No match SYN_RCV pair");
      return;
    }
    Packet ackPacket = packet.clone();
    // destport and srcport exchange
    setPacketSrcDest(&ackPacket, &destIP, &destPort, &srcIP, &srcPort);
    ackNum = seqNum + 1; // ACK 번호 설정(받은 SEQ number + 1)
    // SEQ number = randomnumber
    // 난수 생성기 초기화
    std::random_device rd; // 비결정적 난수 생성기를 사용하여 시드를 생성
    std::mt19937 gen(rd()); // Mersenne Twister 알고리즘을 사용하는 생성기
    // 1부터 1000까지의 균일 분포를 가진 난수 생성
    std::uniform_int_distribution<int> distrib(1, 1000);
    seqNum = distrib(gen);
    // 내 state SYN_RCV로 만들고 seq, ack 설정
    handShakingMap[destAddrPair][srcAddrPair] =
        std::make_tuple(SocketState::SYN_RCV, seqNum, ackNum);
    // sequence number - 따로 지정
    ackPacket.writeData(TCP_SEGMENT_START + 4, &seqNum, 4);
    // ACK number - 받은 seq number +1
    ackPacket.writeData(TCP_SEGMENT_START + 8, &ackNum, 2);
    // ACK 플래그 설정
    flags = (1 << 4); // ACK
    ackPacket.writeData(13, &flags, 1);
    // timer 설정하기
    // payload 어떻게??? packet, ip, port, state?

    //  SYN-ACK 패킷 송신
    this->sendPacket("IPv4", std::move(ackPacket));
  }
  // ACK 패킷 처리 / handShakingMap에서 찾은 pair의 상태가 SYN_RCV여야함. ack ==
  // seq+1이어야 함. established
  if (ACK && !SYN) {
    // 이전 연결에 대해 보냈던 SEQnum + 1 과 같다면 listening set에 fd,
    // sockadddr 추가 , handshakingMap - established  추가 추가 클라이언트
    // 소켓의 상태를 CONNECTED로 변경
    auto myIter = handShakingMap.find(destAddrPair);
    if (myIter != handShakingMap.end()) {
      auto peerIter = myIter->second.find(srcAddrPair);
      if (peerIter != myIter->second.end()) {
        // state = SYN_RCV인지 확인, seq +1 = ackNum 인지 확인
        if ((std::get<0>(peerIter->second) == SocketState::SYN_RCV) &&
            (std::get<1>(peerIter->second) + 1 == ackNum)) {
          handShakingMap[destAddrPair][srcAddrPair] =
              std::make_tuple(SocketState::ESTABLISHED, -1, -1);
        }
      } else {
        printf("No match SYN_RCV pair");
        return;
      }
    } else {
      printf("No match SYN_RCV pair");
      return;
    }
    // clientFd 찾기
    int clientPid, clientFd = -1;
    std::tuple<int, int>(clientPid, clientFd) = getFd(srcIP, srcPort);
    if (clientFd == -1 || clientPid == -1) {
      perror("established. But clientFd not found");
      return;
    }
    // make client socket state CONNECTED
    socketMap[clientPid][clientFd].socket.socketstate = SocketState::CONNECTED;
    // peer 찾기
    int myPid, myFd = -1;
    std::tuple<int, int>(myPid, myFd) = getFd(destIP, destPort);
    if (myFd == -1 || myPid == -1) {
      perror("established. But serverFd not found");
      return;
    }
    // peer 의 listeningsocket의 listening queue 에 입력하기.
    socketMap[myPid][myFd].socketHandShake.listeningQueue.push(
        std::make_tuple(clientFd, socketMap[clientPid][clientFd].sockAddr));
  }
}

std::tuple<int, int> TCPAssignment::getFd(uint32_t saddr, in_port_t sinport) {
  int targetFd = -1;
  int targetPid = -1;
  for (const auto &pidIter : socketMap) {
    for (const auto &fdIter : pidIter.second) {
      if (((fdIter.second.sockAddr->sin_addr.s_addr == saddr) ||
           (fdIter.second.sockAddr->sin_addr.s_addr == INADDR_ANY)) &&
          (fdIter.second.sockAddr->sin_port == sinport)) {
        targetFd = fdIter.first;
        targetPid = pidIter.first;
        break;
      }
    }
    if (targetFd != -1) {
      break;
    }
  }
  return std::make_tuple(targetFd, targetPid);
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

  struct Socket sock = {domain, type, protocol, SocketState::CREATED};
  struct sockaddr_in *sockAddr = {};
  struct SocketHandShake sockHandShake = {};
  struct SocketData sockData = {sock, sockAddr, sockHandShake};
  // pid 에 해당하는 fd, sockdata map이 없다면 추가하기
  if (socketMap.find(pid) == this->socketMap.end()) {
    socketMap[pid] = std::unordered_map<int, SocketData>();
  }
  socketMap[pid][sockFd] = sockData;
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
  // BOUND 이외의 상태에 대해서도 처리할 수 있어야함. BOUND 에서 LISTENING이
  // 된다면?
  if (socketData.socket.socketstate == SocketState::BOUND) {
    const sockaddr_in *sockAddr = socketData.sockAddr;
    std::tuple<uint32_t, in_port_t> addrTuple =
        std::make_tuple(sockAddr->sin_addr.s_addr, sockAddr->sin_port);
    boundSet.erase(addrTuple);
  }
  // socketMap에서 fd 정보 삭제,
  // handshakingmap에서 정보 삭제, state 변경, established - > something
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

  SocketData &mySocketData = sockIter->second;

  if (mySocketData.socket.socketstate != SocketState::CREATED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (addrlen != sizeof(*addr)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  sockaddr_in *mySockAddr = (sockaddr_in *)(addr);
  uint32_t myAddr = mySockAddr->sin_addr.s_addr;
  in_port_t myPort = mySockAddr->sin_port;

  std::tuple<uint32_t, in_port_t> addrTuple = std::make_tuple(myAddr, myPort);

  for (const auto &addrIter : boundSet) {
    uint32_t currAddr = std::get<0>(addrIter);
    in_port_t currPort = std::get<1>(addrIter);
    if (myPort == currPort) {
      if (myAddr == currAddr || myAddr == INADDR_ANY ||
          currAddr == INADDR_ANY) {
        this->returnSystemCall(syscallUUID, -1);
        return;
      }
    }
  }

  mySocketData.sockAddr = mySockAddr;
  mySocketData.socket.socketstate = SocketState::BOUND;
  boundSet.insert(addrTuple);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {
  // SocketMap에 없는 pid에서 getsockname을 호출하면 오류
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // 주소를 찾으려는 fd가 socketMap에 없다면 오류
  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // socketMap에서 fd에 해당하는 socketData 찾음
  SocketData &mySocketData = sockIter->second;
  // addrlen 이 유효한지 확인,
  if (*addrlen < sizeof(sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // addr이 유효한지 확인, nullptr이면 안 됨.
  if (addr == nullptr) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // sockAddr이 바인드 되지 않았거나 sockAddr 이 init 되지 않음.
  if (mySocketData.sockAddr == nullptr ||
      mySocketData.socket.socketstate != SocketState::BOUND) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  struct sockaddr_in *mySockAddr = (struct sockaddr_in *)(addr);
  *mySockAddr = *mySocketData.sockAddr;
  *addrlen = sizeof(sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd,
                                   int backlog) {
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
  // fd에 해당하는 SocketData 찾음.
  SocketData &mysocketData = sockIter->second;
  // socketstate가 bound가 아닐 경우 리턴.
  //
  if (mysocketData.socket.socketstate != SocketState::BOUND) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  mysocketData.socket.socketstate = SocketState::LISTENING;
  // backlog 조건, 0<=backlog<=SOMAXCONN(max length of backlog(128))
  if (backlog > SOMAXCONN) {
    backlog = SOMAXCONN;
  }
  if (backlog < 0) {
    backlog = 0;
  }
  mysocketData.socketHandShake.BACKLOG = backlog;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd,
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
  // fd에 해당하는 SocketData 찾음.
  SocketData &mySocketData = sockIter->second;
  if (mySocketData.socket.socketstate != SocketState::CREATED) {
    printf("socket not STATE::CREATED");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // 주소 길이값이 유효하지 않을 경우 오류
  if (addrlen != sizeof(sockaddr_in)) {
    printf("bad addrlen");
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  // 연결하고자 하는 대상의 ip주소와 port넘버 획득
  const struct sockaddr_in *peerAddr = (const struct sockaddr_in *)addr;
  uint32_t peerIP = peerAddr->sin_addr.s_addr;
  in_port_t peerPort = peerAddr->sin_port;

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

  // 발송할 새로운 SYN packet 생성
  size_t PACKETHEADER_SIZE = 54;
  Packet synPacket(PACKETHEADER_SIZE);

  // packet 초기화
  setPacketSrcDest(&synPacket, &myNICIP, &myNICPort, &peerIP, &peerPort);

  // 난수 생성기를 이용한 seqNum 생성
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> distrib(1, 1000);
  uint32_t seqNum = distrib(gen);
  synPacket.writeData(TCP_SEGMENT_START + 4, &seqNum, 4);

  uint8_t dataOffset = 5 << 4;
  synPacket.writeData(TCP_SEGMENT_START + 12, &dataOffset, 1);

  uint8_t synFlag = 1 << 1;
  synPacket.writeData(TCP_SEGMENT_START + 13, &synFlag, 1);

  uint16_t windowSize = htons(65536);
  synPacket.writeData(TCP_SEGMENT_START + 14, &windowSize, 2);

  this->sendPacket("IPv4", std::move(synPacket));

  // handshakingMap pair(내 ip, 내 port) -> { pair(상대 ip, port) ->
  // tuple(sockstate, seqnum, acknum) }
  handShakingMap[std::make_pair(myNICIP, myNICPort)]
                [std::make_pair(peerIP, peerPort)] =
                    std::make_tuple(SocketState::SYN_SENT, seqNum, -1);
  // socketMap의 fd 의 sockaddr 설정
  socketMap[pid][fd].sockAddr->sin_addr.s_addr = myNICIP;
  socketMap[pid][fd].sockAddr->sin_port = myNICPort;
  socketMap[pid][fd].sockAddr->sin_family = AF_INET;

  mySocketData.socket.socketstate = SocketState::WAITING;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,
                                   struct sockaddr *addr, socklen_t *addrlen) {
  auto pidIter = this->socketMap.find(pid);
  if (pidIter == this->socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &mySocketData = sockIter->second;
  if (mySocketData.socket.socketstate != SocketState::LISTENING) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  if (mySocketData.socketHandShake.listeningQueue.empty()) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  std::tuple<int, const struct sockaddr_in *> request =
      mySocketData.socketHandShake.listeningQueue.front();
  mySocketData.socketHandShake.listeningQueue.pop();

  // 이미 listening queue에 있던 소켓이 다른 소켓과 연결되어있다면 종료.
  // 이미 해당 request ip, port에 대해 serve중이면 종료.

  // 새 소켓 파일 디스크립터 생성 및 클라이언트와 연결
  int requestFd = std::get<0>(request);
  const struct sockaddr_in *requestAddr = std::get<1>(request);

  int newMySockFd = createFileDescriptor(pid); // 가상의 파일 디스크립터 생성
  if (newMySockFd < 0) {
    this->returnSystemCall(syscallUUID, -1); // 파일 디스크립터 생성 실패
    return;
  }

  // 새 소켓을 클라이언트와 연결된 상태로 설정
  struct Socket newMySocket = {AF_INET, SOCK_STREAM, IPPROTO_TCP,
                               SocketState::CONNECTED};
  struct sockaddr_in *newMySockAddr = new sockaddr_in;
  newMySockAddr->sin_family = AF_INET;
  newMySockAddr->sin_addr.s_addr = mySocketData.sockAddr->sin_addr.s_addr;
  newMySockAddr->sin_port = mySocketData.sockAddr->sin_port;

  // 여기서는 클라이언트 주소 정보 설정을 생략함
  struct SocketHandShake newMySocketHandShake;
  newMySocketHandShake.connectedTuple =
      std::tuple<int, const struct sockaddr_in *>(requestFd, requestAddr);
  struct SocketData newMySocketData = {newMySocket, newMySockAddr,
                                       newMySocketHandShake};

  // sockethandshake connectedTuple에 peer정보넣기

  socketMap[pid][newMySockFd] = newMySocketData;

  // 클라이언트 주소 정보를 사용자 공간에 복사
  if (addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, newMySockAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  }

  // 새로운 소켓 파일 디스크립터 반환
  this->returnSystemCall(syscallUUID, newMySockFd);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen) {
  auto pidIter = socketMap.find(pid);
  if (pidIter == socketMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  auto sockIter = pidIter->second.find(fd);
  if (sockIter == pidIter->second.end()) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  SocketData &mySocketData = sockIter->second;

  if (mySocketData.socket.socketstate != SocketState::CONNECTED) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  //?? addr peer addr
  const struct sockaddr_in *peerAddr =
      std::get<1>(mySocketData.socketHandShake.connectedTuple);
  if (peerAddr != nullptr && addr != nullptr && addrlen != nullptr &&
      *addrlen >= sizeof(sockaddr_in)) {
    memcpy(addr, peerAddr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
  } else {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->returnSystemCall(syscallUUID, 0);
}

} // namespace E
