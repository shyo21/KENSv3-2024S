/*
 * E_PWOSPFAssignment.hpp
 *
 */

#ifndef E_PWOSPFASSIGNMENT_HPP_
#define E_PWOSPFASSIGNMENT_HPP_

#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <E/Networking/E_Wire.hpp>

// Additional Header
#include <algorithm>
#include <any>
#include <arpa/inet.h>
#include <chrono>
#include <cmath>
#include <iostream>
#include <set>
#include <tuple>
#include <vector>

namespace E {

constexpr Size MaxCost = 20;
constexpr Size calc_cost_lcm(size_t a) {
  return a == 1 ? 1 : std::lcm(a, calc_cost_lcm(a - 1));
}
constexpr Size CostLCM = calc_cost_lcm(MaxCost);

/* Router Configuration */

//  32 bit area ID
constexpr uint32_t AreaID = 1;
// 16 bit lsuint    - interval in seconds between link state update broadcasts
constexpr uint16_t LSUInt = 30;
constexpr uint16_t TTLInitial = 16;

// 32 bit mask mask   - subnet mask of assocaited interface
constexpr ipv4_t SubnetMask = {255, 255, 255, 0};

// 16 bit helloint    - interval in seconds between HELLO broadcasts
constexpr uint16_t HelloInt = 60;

/* Router Configuration End */

/* frequently used constants */
constexpr int ETH_HEAD_SIZE = 14;
constexpr int IP_HEAD_SIZE = 20;
constexpr int OSPF_HEAD_SIZE = 24;
uint32_t MASK_INT = ntohl(NetworkUtil::arrayToUINT64(SubnetMask));

/* if ntohll and htonll not defined */
#ifndef HAVE_NTOHLL
#ifdef HAVE_BE64TOH
#include <endian.h>
#define ntohll(x) be64toh(x)
#define htonll(x) htobe64(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ntohll(x) (x)
#define htonll(x) (x)
#else
#define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32)
#define htonll(x) ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32)
#endif
#else
#define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32)
#define htonll(x) ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32)
#endif
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(push, 1)
#elif !defined(HAVE_ATTR_PACK)
#error "Compiler must support packing"
#endif

struct pwospf_header_t {
  uint8_t version = 2;
  uint8_t type;
  uint16_t length;
  uint32_t router_id;
  uint32_t area_id;
  uint16_t checksum;
  uint16_t authtype = 0;
  uint64_t authentication = 0;
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

struct pwospf_hello_t {
  pwospf_header_t *header_ptr;
  // pwospf_header_t header;
  uint32_t network_mask;
  uint16_t hello_int;
  uint16_t padding;
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

struct pwospf_lsu_entry_t {
  uint32_t subnet;
  uint32_t mask;
  uint32_t router_id;
  uint32_t cost;
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

struct pwospf_lsu_t {
  pwospf_header_t *header_ptr;
  // pwospf_header_t header;
  uint16_t sequence;
  uint16_t ttl;
  uint32_t num_advertisements;
  pwospf_lsu_entry_t entries[];
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

// router
struct interface_t {
  int index;
  uint32_t ipAddr;
  uint32_t mask = MASK_INT;
  uint16_t helloint = HelloInt;
  // ID, IP, cost
  std::set<std::tuple<uint32_t, uint32_t, int>> neighbor;
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

struct router_t {
  int seqNum = 1;
  uint32_t routerID;
  uint32_t areaID = AreaID;
  uint16_t lsuint = LSUInt;
  std::set<interface_t *> my_interface;
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

class PWOSPFAssignment : public HostModule,
                         private RoutingInfoInterface,
                         public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  /* 라우터 ID -> 해당 라우터의 네이버 ID, cost 모음 */
  std::map<uint32_t, std::map<uint32_t, int>> topology_map;

  /* 라우터 ID -> 해당 라우터의 interface IP 모음 */
  std::map<uint32_t, std::set<uint32_t>> interface_map;

  /* 라우터 ID -> 직전에 수신했던 시퀀스 넘버 */
  std::map<uint32_t, int> seq_map;

  /* 목적지 ID -> 목적지까지의 cost */
  std::map<uint32_t, int> cost_map;

  // subnet&mask routerID, routerID
  std::map<uint32_t, std::pair<uint32_t, uint32_t>> routerSubnet;

  router_t *my_router;

public:
  PWOSPFAssignment(Host &host);

  /**
   * @brief Query cost for a host
   *
   * @param ipv4 querying host's IP address
   * @return cost or -1 for no found host
   */
  Size pwospfQuery(const ipv4_t &ipv4);

  /**
   * @brief Get cost for local port (link)
   *
   * @param port_num querying port's number
   * @return local link cost
   */
  Size linkCost(int port_num) {
    Size bps = this->getWireSpeed(port_num);
    return CostLCM / bps;
  }

  virtual void initialize();
  virtual void finalize();
  virtual ~PWOSPFAssignment();

  /* implemented functions */
  void print_map();

  pwospf_header_t *readOSPFHeader(Packet *);
  pwospf_hello_t *readHello(Packet *);
  pwospf_lsu_t *readLSU(Packet *);

  void writeOSPFHeader(Packet *, pwospf_header_t *);
  void writeHello(Packet *, pwospf_hello_t *);
  void writeLSU(Packet *, pwospf_lsu_t *);

  bool checkPacket(Packet *);
  void handleHello(Packet *);
  void handleLSU(Packet *);
  void dijkstra();
  void buildTable();

protected:
  virtual std::any diagnose(std::any param) final {
    auto ip = std::any_cast<ipv4_t>(param);
    return pwospfQuery(ip);
  }
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

} // namespace E

#endif /* E_PWOSPFASSIGNMENT_HPP_ */
