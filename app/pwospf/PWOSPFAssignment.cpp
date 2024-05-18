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

void PWOSPFAssignment::initialize() {}

void PWOSPFAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size PWOSPFAssignment::pwospfQuery(const ipv4_t &ipv4) {
  // Implement below

  return -1;
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
  hello_t->header = *(hello_t->header_ptr);
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
  lsu_t->header = *(lsu_t->header_ptr);
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

void PWOSPFAssignment::packetArrived(std::string fromModule, Packet &&packet) {
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

void PWOSPFAssignment::handleHello(Packet *packet) {
  pwospf_hello_t *hello_t = readHello(packet);

  delete hello_t;
}

void PWOSPFAssignment::handleLSU(Packet *packet) {
  pwospf_lsu_t *lsu_t = readLSU(packet);

  delete lsu_t;
}

void PWOSPFAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
