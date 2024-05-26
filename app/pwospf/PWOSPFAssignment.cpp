/*
 * E_PWOSPFAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "PWOSPFAssignment.hpp"

namespace E {

PWOSPFAssignment::PWOSPFAssignment(Host &host)
    : HostModule("OSPF", host), RoutingInfoInterface(host),
      TimerModule("OSPF", host) {}

PWOSPFAssignment::~PWOSPFAssignment() {}

void PWOSPFAssignment::initialize() {

  /* 내 라우터 구조체 초기화 */
  router_t *myRouter = new router_t;
  std::optional<ipv4_t> myIPOption = getIPAddr(0);
  if (myIPOption.has_value())
    myRouter->routerID = ntohl(NetworkUtil::arrayToUINT64(myIPOption.value()));
  else {
    std::cout << "init : fail to set my routerID" << std::endl;
    return;
  }
  my_router = myRouter;
  /* 내 라우터 구조체 초기화 완료 */

  /* Hello braodcast 시작 */
  int index = 0;

  while (getIPAddr(index).has_value()) {

    uint32_t myIP = ntohl(NetworkUtil::arrayToUINT64(getIPAddr(index).value()));

    // my_router interface_t 추가
    interface_t *myinterface = new interface_t;
    myinterface->ipAddr = myIP;
    myinterface->index = index;
    my_router->my_interface.emplace(myinterface);

    interface_map[my_router->routerID][myIP] = myinterface->mask;

    // ospf 헤더 정보
    pwospf_header_t *helloHead = new pwospf_header_t;
    helloHead->type = 1;
    helloHead->length = OSPF_HEAD_SIZE + 8;
    helloHead->router_id = myRouter->routerID;
    helloHead->area_id = AreaID;

    // hello 데이터
    pwospf_hello_t *hello = new pwospf_hello_t;
    hello->header_ptr = helloHead;
    hello->network_mask = MASK_INT;
    hello->hello_int = HelloInt;
    hello->padding = 0;

    // hello 패킷 생성
    Packet *helloPacket =
        new Packet(ETH_HEAD_SIZE + IP_HEAD_SIZE + helloHead->length);

    writeHello(helloPacket, hello);

    uint8_t n_protocol = 89;
    uint32_t n_src = htonl(myIP);
    uint32_t n_dest = htonl(0xe0000005);

    helloPacket->writeData(ETH_HEAD_SIZE + 9, &n_protocol, 1);
    helloPacket->writeData(ETH_HEAD_SIZE + 12, &n_src, 4);
    helloPacket->writeData(ETH_HEAD_SIZE + 16, &n_dest, 4);

    this->sendPacket("IPv4", std::move(*helloPacket));

    delete hello;
    delete helloHead;

    index++;
  }
}

void PWOSPFAssignment::finalize() {}

/* define printing operator for ipv4_t type */
std::ostream &operator<<(std::ostream &os, const ipv4_t &ipv4) {
  os << static_cast<int>(ipv4[0]) << '.' << static_cast<int>(ipv4[1]) << '.'
     << static_cast<int>(ipv4[2]) << '.' << static_cast<int>(ipv4[3]);
  return os;
}

/* convert uint32_t type ip into formatted string type */
std::string print_uint32(uint32_t ip) {
  std::string ipv4;
  ipv4 += std::to_string((ip >> 24) & 0xFF) + ".";
  ipv4 += std::to_string((ip >> 16) & 0xFF) + ".";
  ipv4 += std::to_string((ip >> 8) & 0xFF) + ".";
  ipv4 += std::to_string(ip & 0xFF);
  return ipv4;
}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size PWOSPFAssignment::pwospfQuery(const ipv4_t &ipv4) {

  uint32_t inputIP = ntohl(NetworkUtil::arrayToUINT64(ipv4));

  /* 목적지 ip가 속한 서브넷 탐색 - longest prefix match
   * 해당 서브넷에 연결된 라우터들 모두 식별
   * 식별된 라우터 중 가장 cost가 낮은 라우터 선택 */

  std::set<uint32_t> router_candidates;
  int longestMatch = -1;

  // longest prefix match
  for (const auto &outerIter : interface_map) {
    for (const auto &innerIter : outerIter.second) {
      uint32_t currSubnet = innerIter.first;

      int match = 0;
      uint32_t mask = 0x80000000;

      for (int i = 0; i < 32; i++) {
        if ((inputIP & mask) == (currSubnet & mask))
          match++;
        else
          break;
        mask >>= 1;
      }

      if (match > longestMatch) {
        router_candidates.clear();
        router_candidates.emplace(outerIter.first);
        longestMatch = match;
      }

      else if (match == longestMatch)
        router_candidates.emplace(outerIter.first);
    }
  }

  // check costs
  std::set<int> cost_candidates;
  for (const auto &iter : router_candidates) {
    if (cost_map[iter] != 0)
      cost_candidates.emplace(cost_map[iter]);
  }

  return *cost_candidates.begin();
}

pwospf_header_t *PWOSPFAssignment::readOSPFHeader(Packet *packet) {
  uint64_t n_authentication;
  uint32_t n_router_id, n_area_id;
  uint16_t n_length, n_checksum, n_authtype;
  uint8_t n_version, n_type;

  int OSPF_START = ETH_HEAD_SIZE + IP_HEAD_SIZE;

  packet->readData(OSPF_START, &n_version, 1);
  packet->readData(OSPF_START + 1, &n_type, 1);
  packet->readData(OSPF_START + 2, &n_length, 2);
  packet->readData(OSPF_START + 4, &n_router_id, 4);
  packet->readData(OSPF_START + 8, &n_area_id, 4);
  packet->readData(OSPF_START + 12, &n_checksum, 2);
  packet->readData(OSPF_START + 14, &n_authtype, 2);
  packet->readData(OSPF_START + 16, &n_authentication, 8);

  pwospf_header_t *ospf_t = new pwospf_header_t;

  ospf_t->version = n_version;
  ospf_t->type = n_type;
  ospf_t->length = ntohs(n_length);
  ospf_t->router_id = ntohl(n_router_id);
  ospf_t->area_id = ntohl(n_area_id);
  ospf_t->checksum = ntohs(n_checksum);
  ospf_t->authtype = ntohs(n_authtype);
  ospf_t->authentication = ntohll(n_authentication);

  return ospf_t;
}

pwospf_hello_t *PWOSPFAssignment::readHello(Packet *packet) {
  uint32_t n_network_mask;
  uint16_t n_hello_int, n_padding;

  int OSPF_DATA_START = ETH_HEAD_SIZE + IP_HEAD_SIZE + OSPF_HEAD_SIZE;

  packet->readData(OSPF_DATA_START, &n_network_mask, 4);
  packet->readData(OSPF_DATA_START + 4, &n_hello_int, 2);
  packet->readData(OSPF_DATA_START + 6, &n_padding, 2);

  pwospf_hello_t *hello_t = new pwospf_hello_t;

  hello_t->header_ptr = readOSPFHeader(packet);
  hello_t->network_mask = ntohl(n_network_mask);
  hello_t->hello_int = ntohs(n_hello_int);
  hello_t->padding = ntohs(n_padding);

  return hello_t;
}

pwospf_lsu_t *PWOSPFAssignment::readLSU(Packet *packet) {
  uint32_t n_num_advertisements, h_num_advertisements;
  uint16_t n_sequence, n_ttl;

  int OSPF_DATA_START = ETH_HEAD_SIZE + IP_HEAD_SIZE + OSPF_HEAD_SIZE;

  packet->readData(OSPF_DATA_START, &n_sequence, 2);
  packet->readData(OSPF_DATA_START + 2, &n_ttl, 2);
  packet->readData(OSPF_DATA_START + 4, &n_num_advertisements, 4);

  h_num_advertisements = ntohl(n_num_advertisements);

  pwospf_lsu_t *lsu_t = nullptr;
  try {
    lsu_t = reinterpret_cast<pwospf_lsu_t *>(
        new char[sizeof(pwospf_lsu_t) +
                 h_num_advertisements * sizeof(pwospf_lsu_entry_t)]);
  } catch (const std::bad_alloc &e) {
    std::cout << "Memory allocation failed: " << e.what() << std::endl;
    return nullptr;
  }

  lsu_t->header_ptr = readOSPFHeader(packet);
  lsu_t->sequence = ntohs(n_sequence);
  lsu_t->ttl = ntohs(n_ttl);
  lsu_t->num_advertisements = ntohl(n_num_advertisements);

  int OSPF_ENTRY_START = OSPF_DATA_START + 8;

  for (uint32_t i = 0; i < h_num_advertisements; i++) {

    uint32_t n_subnet, n_mask, n_router_id, n_cost;

    int THIS_ENTRY = OSPF_ENTRY_START + i * 16;

    packet->readData(THIS_ENTRY, &n_subnet, 4);
    packet->readData(THIS_ENTRY + 4, &n_mask, 4);
    packet->readData(THIS_ENTRY + 8, &n_router_id, 4);
    packet->readData(THIS_ENTRY + 12, &n_cost, 4);

    lsu_t->entries[i].subnet = ntohl(n_subnet);
    lsu_t->entries[i].mask = ntohl(n_mask);
    lsu_t->entries[i].router_id = ntohl(n_router_id);
    lsu_t->entries[i].cost = ntohl(n_cost);
  }

  return lsu_t;
}

void PWOSPFAssignment::writeOSPFHeader(Packet *packet,
                                       pwospf_header_t *header_t) {
  uint64_t n_authentication;
  uint32_t n_router_id, n_area_id;
  uint16_t n_length, n_authtype;
  uint8_t n_version, n_type;

  n_version = header_t->version;
  n_type = header_t->type;
  n_length = htons(header_t->length);
  n_router_id = htonl(header_t->router_id);
  n_area_id = htonl(header_t->area_id);
  n_authtype = htons(header_t->authtype);
  n_authentication = htonll(header_t->authentication);

  int OSPF_START = ETH_HEAD_SIZE + IP_HEAD_SIZE;

  packet->writeData(OSPF_START, &n_version, 1);
  packet->writeData(OSPF_START + 1, &n_type, 1);
  packet->writeData(OSPF_START + 2, &n_length, 2);
  packet->writeData(OSPF_START + 4, &n_router_id, 4);
  packet->writeData(OSPF_START + 8, &n_area_id, 4);
  packet->writeData(OSPF_START + 14, &n_authtype, 2);
  packet->writeData(OSPF_START + 16, &n_authentication, 8);
}

void PWOSPFAssignment::writeHello(Packet *packet, pwospf_hello_t *hello_t) {
  uint32_t n_network_mask;
  uint16_t n_hello_int, n_padding;

  n_network_mask = htonl(hello_t->network_mask);
  n_hello_int = htons(hello_t->hello_int);
  n_padding = htons(hello_t->padding);

  pwospf_header_t *header_t = hello_t->header_ptr;
  writeOSPFHeader(packet, header_t);

  int OSPF_DATA_START = ETH_HEAD_SIZE + IP_HEAD_SIZE + OSPF_HEAD_SIZE;

  packet->writeData(OSPF_DATA_START, &n_network_mask, 4);
  packet->writeData(OSPF_DATA_START + 4, &n_hello_int, 2);
  packet->writeData(OSPF_DATA_START + 6, &n_padding, 2);
}

void PWOSPFAssignment::writeLSU(Packet *packet, pwospf_lsu_t *lsu_t) {
  uint32_t n_num_advertisements, h_num_advertisements;
  uint16_t n_sequence, n_ttl;

  n_sequence = htons(lsu_t->sequence);
  n_ttl = htons(lsu_t->ttl);
  h_num_advertisements = lsu_t->num_advertisements;
  n_num_advertisements = htonl(h_num_advertisements);

  pwospf_header_t *header_t = lsu_t->header_ptr;
  writeOSPFHeader(packet, header_t);

  int OSPF_DATA_START = ETH_HEAD_SIZE + IP_HEAD_SIZE + OSPF_HEAD_SIZE;

  packet->writeData(OSPF_DATA_START, &n_sequence, 2);
  packet->writeData(OSPF_DATA_START + 2, &n_ttl, 2);
  packet->writeData(OSPF_DATA_START + 4, &n_num_advertisements, 4);

  int OSPF_ENTRY_START = OSPF_DATA_START + 8;

  for (uint32_t i = 0; i < h_num_advertisements; i++) {

    uint32_t n_subnet, n_mask, n_router_id, n_cost;

    int THIS_ENTRY = OSPF_ENTRY_START + i * 16;

    n_subnet = htonl(lsu_t->entries[i].subnet);
    n_mask = htonl(lsu_t->entries[i].mask);
    n_router_id = htonl(lsu_t->entries[i].router_id);
    n_cost = htonl(lsu_t->entries[i].cost);

    packet->writeData(THIS_ENTRY, &n_subnet, 4);
    packet->writeData(THIS_ENTRY + 4, &n_mask, 4);
    packet->writeData(THIS_ENTRY + 8, &n_router_id, 4);
    packet->writeData(THIS_ENTRY + 12, &n_cost, 4);
  }
}

void PWOSPFAssignment::packetArrived(std::string fromModule, Packet &&packet) {

  if (!checkPacket(&packet)) {
    std::cout << "packet check failed" << std::endl;
    return;
  }

  uint8_t type;
  int OSPF_START = ETH_HEAD_SIZE + IP_HEAD_SIZE;
  (&packet)->readData(OSPF_START + 1, &type, 1);

  switch (type) {
  case 1:
    handleHello(&packet);
    break;
  case 4:
    handleLSU(&packet);
    break;
  default:
    break;
  }
}

bool PWOSPFAssignment::checkPacket(Packet *packet) {
  uint64_t n_authentication;
  uint32_t n_area_id;
  uint8_t n_version;

  int OSPF_START = ETH_HEAD_SIZE + IP_HEAD_SIZE;

  packet->readData(OSPF_START, &n_version, 1);
  packet->readData(OSPF_START + 8, &n_area_id, 4);
  packet->readData(OSPF_START + 16, &n_authentication, 8);

  if (n_version != 2)
    return false;

  if (ntohl(n_area_id) != my_router->areaID)
    return false;

  if (ntohll(n_authentication) != 0)
    return false;

  return true;
}

void PWOSPFAssignment::handleHello(Packet *packet) {
  pwospf_hello_t *hello_t = readHello(packet);

  uint32_t srcIP;
  packet->readData(ETH_HEAD_SIZE + 12, &srcIP, 4);
  srcIP = ntohl(srcIP);

  interface_map[hello_t->header_ptr->router_id][srcIP] = hello_t->network_mask;

  bool isUpdated = false;

  /* 내 인터페이스에 네이버 추가하기 */
  for (const auto &setIter : my_router->my_interface) {
    uint32_t myIP = setIter->ipAddr;

    if ((myIP & MASK_INT) == (srcIP & MASK_INT)) {

      if (setIter->mask != hello_t->network_mask) {
        std::cout << "mask not match" << std::endl;
        return;
      }

      if (setIter->helloint != hello_t->hello_int) {
        std::cout << "helloint not match" << std::endl;
        return;
      }

      bool found = false;
      for (const auto &[nb1, nb2, nb3] : setIter->neighbor) {
        if (nb2 == srcIP) {
          found = true;
          // 타이머 초기화 해주기
          break;
        }
      }

      if (!found) {
        uint32_t srcID = hello_t->header_ptr->router_id;

        ipv4_t convertIP = NetworkUtil::UINT64ToArray<sizeof(uint32_t)>(
            (uint64_t)htonl(srcIP));
        int port = getRoutingTable(convertIP);
        int cost = linkCost(port);

        setIter->neighbor.emplace(srcID, srcIP, cost);

        topology_map[my_router->routerID][srcID] = cost;

        isUpdated = true;
      }

      break;
    }
  }
  /* 내 인터페이스에 네이버 추가하기 end */

  /* h_num advertisement 수 세기*/
  uint32_t h_num_advertisements = 0;
  for (const auto &setIter : my_router->my_interface) {
    if (setIter->neighbor.empty())
      h_num_advertisements++;
    else {
      for (const auto &[nb1, nb2, nb3] : setIter->neighbor) {
        h_num_advertisements++;
      }
    }
  }

  /* topology map이 업데이트 된 경우 */
  if (isUpdated) {

    // LSU packet 전송
    pwospf_header_t *lsuHead = new pwospf_header_t;
    lsuHead->type = 4;
    lsuHead->length = OSPF_HEAD_SIZE + 8 + 16 * h_num_advertisements;
    lsuHead->router_id = my_router->routerID;
    lsuHead->area_id = AreaID;

    pwospf_lsu_t *lsu_t = nullptr;
    try {
      lsu_t = reinterpret_cast<pwospf_lsu_t *>(
          new char[sizeof(pwospf_lsu_t) +
                   h_num_advertisements * sizeof(pwospf_lsu_entry_t)]);
    } catch (const std::bad_alloc &e) {
      std::cout << "Memory allocation failed: " << e.what() << std::endl;
      return;
    }

    lsu_t->header_ptr = lsuHead;
    lsu_t->sequence = my_router->seqNum;
    lsu_t->ttl = TTLInitial;
    lsu_t->num_advertisements = h_num_advertisements;

    my_router->seqNum++;

    int i = 0;
    for (const auto &setIter : my_router->my_interface) {

      if (setIter->neighbor.empty()) {

        ipv4_t convertIP = NetworkUtil::UINT64ToArray<sizeof(uint32_t)>(
            (uint64_t)setIter->ipAddr);
        int port = getRoutingTable(convertIP);
        int cost = linkCost(port);

        pwospf_lsu_entry_t *temp = new pwospf_lsu_entry_t;
        temp->subnet = setIter->ipAddr;
        temp->mask = setIter->mask;
        temp->router_id = 0;
        temp->cost = 0;

        lsu_t->entries[i] = *temp;

        delete temp;
        i++;
      }

      else {
        for (const auto &[nb1, nb2, nb3] : setIter->neighbor) {

          pwospf_lsu_entry_t *temp = new pwospf_lsu_entry_t;
          temp->subnet = nb2;
          temp->mask = setIter->mask;
          temp->router_id = nb1;
          temp->cost = nb3;

          lsu_t->entries[i] = *temp;

          uint32_t srcID = my_router->routerID;
          uint32_t destSubnet = (temp->subnet) & (temp->mask);
          uint32_t destID = nb1;

          delete temp;
          i++;
        }
      }
    }

    // 패킷 전송
    for (const auto &setIter : my_router->my_interface) {
      for (const auto &[nb1, nb2, nb3] : setIter->neighbor) {

        Packet *lsuPacket =
            new Packet(ETH_HEAD_SIZE + IP_HEAD_SIZE + lsuHead->length);

        writeLSU(lsuPacket, lsu_t);

        uint8_t n_protocol = 89;
        uint32_t n_src = htonl(setIter->ipAddr);
        uint32_t n_dest = htonl(nb2);

        lsuPacket->writeData(ETH_HEAD_SIZE + 9, &n_protocol, 1);
        lsuPacket->writeData(ETH_HEAD_SIZE + 12, &n_src, 4);
        lsuPacket->writeData(ETH_HEAD_SIZE + 16, &n_dest, 4);

        this->sendPacket("IPv4", std::move(*lsuPacket));
      }
    }

    delete lsu_t->header_ptr;
    delete lsu_t;

    // 다익스트라 알고리즘 실행
    dijkstra();

    // 라우팅 테이블 업데이트
    // buildTable();
  }

  delete hello_t;
}

void PWOSPFAssignment::handleLSU(Packet *packet) {
  pwospf_lsu_t *lsu_t = readLSU(packet);

  // 내가 생성했던 패킷이 돌아온 경우 drop
  if (lsu_t->header_ptr->router_id == my_router->routerID) {
    return;
  }

  // sequence number 같을 시에 drop
  if (lsu_t->sequence <= seq_map[lsu_t->header_ptr->router_id]) {
    return;
  }

  else {
    // seqnum 업데이트
    seq_map[lsu_t->header_ptr->router_id] = lsu_t->sequence;

    uint32_t srcID = lsu_t->header_ptr->router_id;

    for (int i = 0; i < lsu_t->num_advertisements; i++) {
      uint32_t destIP = lsu_t->entries[i].subnet;
      uint32_t mask = lsu_t->entries[i].mask;
      uint32_t destID = lsu_t->entries[i].router_id;
      int cost = lsu_t->entries[i].cost;

      if (destID != 0)
        interface_map[destID][destIP] = mask;

      topology_map[srcID][destID] = cost;
    }
    // 다익스트라 알고리즘 실행
    dijkstra();

    // 라우팅 테이블 업데이트
    // buildTable();
  }

  uint32_t srcIP;
  packet->readData(ETH_HEAD_SIZE + 12, &srcIP, 4);
  srcIP = ntohl(srcIP);

  // 메시지가 온 방향 제외 neighbor 에게 패킷 전송
  if (lsu_t->ttl > 0) {

    lsu_t->ttl = lsu_t->ttl - 1;

    for (const auto &setIter : my_router->my_interface) {
      for (const auto &[nb1, nb2, nb3] : setIter->neighbor) {

        if (srcIP != nb2) {
          Packet *lsuPacket = new Packet(ETH_HEAD_SIZE + IP_HEAD_SIZE +
                                         lsu_t->header_ptr->length);

          writeLSU(lsuPacket, lsu_t);

          uint8_t n_protocol = 89;
          uint32_t n_src = htonl(setIter->ipAddr);
          uint32_t n_dest = htonl(nb2);

          lsuPacket->writeData(ETH_HEAD_SIZE + 9, &n_protocol, 1);
          lsuPacket->writeData(ETH_HEAD_SIZE + 12, &n_src, 4);
          lsuPacket->writeData(ETH_HEAD_SIZE + 16, &n_dest, 4);

          this->sendPacket("IPv4", std::move(*lsuPacket));
        }
      }
    }
  }
  delete lsu_t;
}

typedef std::pair<int, uint32_t> pq_elem;
struct is_greater {
  bool operator()(const pq_elem &a, const pq_elem &b) {
    return a.first > b.first;
  }
};

void PWOSPFAssignment::dijkstra() {
  std::map<uint32_t, int> costs;
  std::priority_queue<pq_elem, std::vector<pq_elem>, is_greater> pq;

  uint32_t myID = my_router->routerID;
  costs[myID] = 0;
  pq.push(std::make_pair(0, myID));

  while (!pq.empty()) {

    uint32_t curr_router = pq.top().second;
    int curr_dist = pq.top().first;
    pq.pop();

    if (curr_dist > costs[curr_router])
      continue;

    const auto mapIter = topology_map.find(curr_router);

    if (mapIter != topology_map.end()) {
      const std::map<uint32_t, int> &innerMap = mapIter->second;

      for (const auto &[rID, cost] : innerMap) {
        if (rID != 0) {
          int new_dist = curr_dist + cost;

          if (costs.find(rID) == costs.end()) {
            costs[rID] = new_dist;
            pq.push(std::make_pair(new_dist, rID));
          }

          else if (new_dist < costs[rID]) {
            costs[rID] = new_dist;
            pq.push(std::make_pair(new_dist, rID));
          }
        }
      }
    }
  }
  cost_map = costs;
}

// void PWOSPFAssignment::buildTable() {
//   std::map<uint32_t, uint32_t> table;

//   for (const auto &iter : track_map) {
//     uint32_t dst_ID = iter.first;
//     uint32_t hop_ID = iter.second;

//     while (hop_ID != my_router->routerID) {
//       hop_ID = track_map.at(hop_ID);
//     }

//     table[dst_ID] = hop_ID;
//   }
//   routing_table = table;
// }

void PWOSPFAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
