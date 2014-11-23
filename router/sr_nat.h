
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include "sr_router.h"
#include "sr_protocol.h"

typedef enum {
  	dir_incoming,
	dir_outgoing,
	dir_notCrossing
} pkt_dir;

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
	int queryTimeout;
	int tcpEstTimeout;
	int tcpTransTimeout;

	struct sr_nat_mapping *mappings;
	int nextPort;
	struct sr_instance *sr;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/*	Translate the packet's dest/src IP based on whether it is
		incoming or outcoming	*/
int sr_nat_translate_packet(struct sr_instance* sr,
	uint8_t * packet, unsigned int len, char* interface);

/* Given a packet, return the NAT mapping if it exists
 */
struct sr_nat_mapping *sr_nat_get_mapping_from_packet(struct sr_instance* sr, 
	uint8_t *packet, pkt_dir direction);

pkt_dir getPacketDirection(struct sr_instance* sr, struct sr_ip_hdr *ipPacket);
int is_ip_within_nat(struct sr_instance *sr, uint32_t ip) ;

#endif
