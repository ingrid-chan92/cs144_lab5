
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_rt.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  /* Initialize any variables here */
	nat->mappings = NULL;
	nat->incoming = NULL;
	nat->nextPort = 1024;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
	struct sr_nat_mapping *curr = nat->mappings;
	while (curr != NULL) {
		struct sr_nat_mapping *prev = curr;
		curr = curr->next;
		free(prev);
	}

	struct sr_tcp_syn *incoming = nat->incoming;
	while (incoming != NULL) {
		struct sr_tcp_syn *prev = incoming;
		incoming = incoming->next;
		free(prev);
	}

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    /* time_t curtime = time(NULL); */


    /* Unsolicited timeout */

		/* Established TCP timeout */

		/* Transitory TCP timeout */

		/* ICMP timeout */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *copy = NULL;
	struct sr_nat_mapping *curr = nat->mappings;

	while (curr != NULL) {
		if (curr->aux_ext == aux_ext && curr->type == type) {
			/* Found mapping */
			curr->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, curr, sizeof(struct sr_nat_mapping));
			break;						
		}
		curr = curr->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  	pthread_mutex_lock(&(nat->lock));

  	/* handle lookup here, malloc and assign to copy */
  	struct sr_nat_mapping *copy = NULL;
	struct sr_nat_mapping *curr = nat->mappings;

	while (curr != NULL) {
		if (curr->ip_int == ip_int && curr->aux_int == aux_int && curr->type == type) {
			/* Found mapping */
			curr->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, curr, sizeof(struct sr_nat_mapping));
			break;						
		}
		curr = curr->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
	uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_if *externalIf = sr_get_interface(nat->sr, "eth2");
	struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

	/* Construct mapping from given values*/
	mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->ip_ext = externalIf->ip;
	mapping->aux_int = aux_int;
	mapping->last_updated = time(NULL);
	mapping->conns = NULL;

	/* Generate external port */
	mapping->aux_ext = htons(nat->nextPort); 
	nat->nextPort = nat->nextPort + 1;
	if (nat->nextPort >= 65535) {
		/* Max ports reached. Restart back at first port */
		nat->nextPort = 1024;
	}

	/* Insert mapping into front of list */
	mapping->next = nat->mappings;
	nat->mappings = mapping;

	/* Create a copy to return*/ 
	struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/*	Translate the packet's dest/src IP based on whether it is
		incoming or outcoming	*/
int sr_nat_translate_packet(struct sr_instance* sr,
	uint8_t *packet, unsigned int len, char* interface) {

	struct sr_ip_hdr *ipPacket= (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
	pkt_dir direction = getPacketDirection(sr, ipPacket);
	uint8_t ip_p = ipPacket->ip_p;

	/* Unsupported protocol: Drop packet */
	if (ip_p != ip_protocol_icmp && ip_p != ip_protocol_tcp) {
		return 1;
	}	

	/* Packet does not cross NAT. Do not need translation */
	if (direction == dir_notCrossing) {
		return 0;
	}

	/* At this point, packet is valid for mapping-lookup */

	struct sr_nat_mapping *mapping = sr_nat_get_mapping_from_packet(sr, packet, direction);

	/* NULL mapping case */
	if (mapping == NULL) {
		switch(ip_p) {
			case ip_protocol_icmp: {
				/* Packet meant for router. Do nothing to it*/
				return 0;

			} case ip_protocol_tcp: {
				/* Packet currently waiting in incoming. Do nothing for now */
				return 1;
			}
		}		
	}

	/* Mapping exists/Packet is valid and must be translated */

	/* Rewrite the IP, Port, and recompute checksum*/
	switch(ip_p) {
		case ip_protocol_icmp: {
			sr_icmp_hdr_t *icmpPacket = (sr_icmp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			
			if (direction == dir_incoming) {
				ipPacket->ip_dst = mapping->ip_int;
				icmpPacket->icmp_identifier = mapping->aux_int;

			} else if (direction == dir_outgoing) {
				ipPacket->ip_src = mapping->ip_ext;
				icmpPacket->icmp_identifier = mapping->aux_ext;
			}
			
			icmpPacket->icmp_sum = 0;
			icmpPacket->icmp_sum = cksum(icmpPacket, sizeof(sr_icmp_hdr_t));
			break;

		} case ip_protocol_tcp: {
			sr_tcp_hdr_t *tcpPacket = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
		
			if (direction == dir_incoming) {
				ipPacket->ip_dst = mapping->ip_int;
				tcpPacket->dest_port = mapping->aux_int;

			} else if (direction == dir_outgoing) {
				ipPacket->ip_src = mapping->ip_ext;
				tcpPacket->src_port = mapping->aux_ext;
			}	
			
			tcpPacket->sum = 0;
			tcpPacket->sum = cksum(tcpPacket, sizeof(sr_tcp_hdr_t));				
			break;
		 }
	}

	/* Rewrite the IP checksum */
	ipPacket->ip_sum = 0;
	ipPacket->ip_sum = cksum(ipPacket, sizeof(sr_ip_hdr_t));
	
	free(mapping);
	return 0;
}

struct sr_nat_mapping *sr_nat_get_mapping_from_packet(struct sr_instance* sr, uint8_t *packet, pkt_dir direction) {
	
	struct sr_ip_hdr *ipPacket= (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	struct sr_nat_mapping *mapping = NULL;
	uint16_t port = 0;
	sr_nat_mapping_type mappingType = 0;		

	/* Get the type and port from the packet */
	switch(ipPacket->ip_p) {
		case ip_protocol_icmp: {
			sr_icmp_hdr_t *icmpPacket = (sr_icmp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			mappingType =  nat_mapping_icmp;
			port = icmpPacket->icmp_identifier;
			break;

		} case ip_protocol_tcp: {
			sr_tcp_hdr_t *tcpPacket = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			mappingType = nat_mapping_tcp;
			if (direction == dir_incoming) {
				port = tcpPacket->dest_port;
			} else if (direction == dir_outgoing) {
				port = tcpPacket->src_port;
			}			
			break;
		 }
	}

	/* Get mapping based on direction */
	switch (direction) {
		case dir_incoming: {
			mapping = sr_nat_lookup_external(sr->nat, port, mappingType);
			
			if (mapping == NULL) {
				/* Do nothing for ICMP */

				if (mappingType == nat_mapping_tcp) {
					sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
					
					/* Queue unsolicited SYN TCP packets */
					if (tcp->flags & TCP_SYN) {
						pthread_mutex_lock(&(sr->nat->lock));

						/* Check if this TCP packet is already waiting */	
						struct sr_tcp_syn *incoming = sr->nat->incoming;					
						while (incoming != NULL) {
							if ((incoming->ip_src == ipPacket->ip_src) && (incoming->port_src == tcp->src_port)) {
								break;
							}
							incoming = incoming->next;
						}			

						if (incoming == NULL) {
							/* this connection not waiting. Add into waiting packets */
							struct sr_tcp_syn *newTcp = (struct sr_tcp_syn *) malloc(sizeof(struct sr_tcp_syn));
							newTcp->ip_src = ipPacket->ip_src;
							newTcp->port_src = tcp->src_port;
							newTcp->arrived = time(NULL);
							memcpy(newTcp->data, packet + sizeof(struct sr_ethernet_hdr), ICMP_DATA_SIZE);

							/* Put new packet at front of list */
							newTcp->next = sr->nat->incoming;
							sr->nat->incoming = newTcp;
						}	

						pthread_mutex_unlock(&(sr->nat->lock));
					}
				}
			}
			break;

		} case dir_outgoing: {
			mapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src, port, mappingType);

			if (mapping == NULL) {
				/* Create new mapping for this IP/Port entry */
				mapping = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src, port, mappingType);

				/* TCP Processing */
				if (mappingType == nat_mapping_tcp) {
					sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
					
					if (tcp->flags & TCP_SYN) {
						pthread_mutex_lock(&(sr->nat->lock));

						struct sr_tcp_syn *incoming = sr->nat->incoming;
						struct sr_tcp_syn *prev = NULL;

						/* Check if this TCP packet is already waiting */						
						while (incoming != NULL) {
							if ((incoming->ip_src == ipPacket->ip_dst) && (incoming->port_src == tcp->dest_port)) {
								/* Silently drop matching incoming SYN packet */
								if (prev != NULL) {
									prev->next = incoming->next;
								} else {
									sr->nat->incoming = incoming->next;
								}	
								break;								
							}
							prev = incoming;
							incoming = incoming->next;
						}

						pthread_mutex_unlock(&(sr->nat->lock));
					}
				}
			}
			break;

		} case dir_notCrossing: {
			printf("ERROR: Should never be here for non-crossing packet\n");
			break;			
		}
	}

	return mapping;
}

pkt_dir getPacketDirection(struct sr_instance* sr, struct sr_ip_hdr *ipPacket) {
	int internalSrc = is_ip_within_nat(sr, ipPacket->ip_src);
	int internalDest = is_ip_within_nat(sr, ipPacket->ip_dst);

	struct sr_if* if_eth2 = sr_get_interface(sr, "eth2");	
	int destIsNat = ipPacket->ip_dst == if_eth2->ip;	

	/* INCOMING: src is outside NAT. Dest is eth2*/
	if (!internalSrc && destIsNat) {
		return dir_incoming;
	}

	/* UNKNOWN DEST IP: Do nothing to this packet */
	if (internalDest < 0) {
		return dir_notCrossing;
	}

	/* OUTCOMING: src is inside NAT. Dest is outside NAT */
	if (internalSrc && !internalDest) {
		return dir_outgoing;
	}

	/* NOTCROSSING: src/dest is inside NAT or src/dest is outside NAT */
	return dir_notCrossing;
}

int is_ip_within_nat(struct sr_instance *sr, uint32_t ip) {
	struct sr_rt *closest = findLongestMatchPrefix(sr->routing_table, ip);
	if (closest == NULL) {
		/* Net unreachable. Do nothing to this packet */
		return -1;

	} else {		
		/* Check if this IP uses eth1 */
		if (strncmp(closest->interface, "eth1", 4) == 0) {
			return 1;
		}
	}
	return 0;
}
