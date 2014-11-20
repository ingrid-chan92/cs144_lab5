
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

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
		struct sr_nat *nat = (struct sr_nat *) nat_ptr;

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
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/*	Translate the packet's dest/src IP based on whether it is
		incoming or outcoming	*/
void sr_nat_translate_packet(struct sr_instance* sr,
	uint8_t *packet, unsigned int len, char* interface) {

	struct sr_ip_hdr *ipPacket= (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
	pkt_dir direction = getPacketDirection(sr, ipPacket);	

	if (direction == incoming) {
		printf("INCOMING\n");

	} else if (direction == outcoming) {
		printf("OUTCOMING\n");

	} else {
		/* Do nothing. Does not cross NAT boundary */		
		return;
		
	}

}

pkt_dir getPacketDirection(struct sr_instance* sr, struct sr_ip_hdr *ipPacket) {
	int insideNat = is_ip_traversing_nat(sr, ipPacket->ip_src);
	int outsideNat = is_ip_traversing_nat(sr, ipPacket->ip_dst);

	if (insideNat == 1 && outsideNat == 0) {
		/* Packet is coming from within NAT */
		return incoming;

	} else if (insideNat == 0 && outsideNat == 1) {
		/* Packet is coming from outside NAT */
		return outcoming;

	} else {
		/* Packet is not crossing NAT boundary. Do nothing */
		return notCrossing;
	}	
}

int is_ip_traversing_nat(struct sr_instance *sr, uint32_t ip) {
	struct sr_rt *closest = findLongestMatchPrefix(sr->routing_table, ip);
	if (closest != NULL) {		
		if (strncmp(closest->interface, "eth1", 4) == 0) {
			/* If using eth1, must interact with NAT */
			return 1;
		}
	}
	return 0;
}
