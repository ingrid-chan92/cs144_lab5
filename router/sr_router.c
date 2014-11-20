/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "icmp_handler.h"
#include "arp_handler.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

	if (ethertype(packet) == ethertype_arp) {			/* ARP packet */
		struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
		if (is_broadcast_mac(packet) || we_are_dest(sr, arpHeader->ar_tip)) {
			/* Process only broadcasted packets or packets meant for me */
			processArp(sr, packet, len, interface);
		}

	} else if (ethertype(packet) == ethertype_ip) { 	/* IP packet */
		struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
		if (we_are_dest(sr, ipHeader->ip_dst)) {
			/* We are destination */
			processIP(sr, packet, len, interface);
		} else {
			/* We are not destination. Forward it. */
			processForward(sr, packet, len, interface);
		}
	}
}

void processArp(struct sr_instance *sr , uint8_t *packet, unsigned int len, char *interface) {

	struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	/* Put ARP header into cache */
	struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arpHeader->ar_sha, ntohl(arpHeader->ar_sip));
	if (req != NULL) {

		/* Found requests in queue waiting for this reply. Send all waiting packets */ 
		struct sr_packet *waiting = req->packets;
		struct sr_rt *rt = findLongestMatchPrefix(sr->routing_table, htonl(req->ip));

		while (waiting != NULL) {
			send_packet_to_dest(sr, waiting->buf, waiting->len, rt->interface, arpHeader->ar_sha, arpHeader->ar_sip);
			waiting = waiting->next;
		}

		/* Destroy arp request when complete */
		sr_arpreq_destroy(&(sr->cache), req);
	}

	if (ntohs(arpHeader->ar_op) == arp_op_request) {
		/* Reply to sender with our information */
		arp_send_reply(sr, packet, len, interface);
	}

}

void processIP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) {

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	/* Ignore invalid packets */
	if (!is_sane_ip_packet(packet, len)) {
		return;
	}

	ipHeader->ip_ttl--;

	if (ipHeader->ip_p == ip_protocol_icmp) {
		/* ICMP request */

		/* Ignore invalid packets */
		if (!is_sane_icmp_packet(packet, len)) {
			return;
		}

		/* Process ICMP only if echo*/
		struct sr_icmp_hdr *icmpHeader = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
		if (icmpHeader->icmp_type == icmp_echo_req_type) {
			icmp_send_echo_reply(sr, packet, len, interface);
		}

	} else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp) {

		/* Reply with timeout if TTL exceeded */		
		if (ipHeader->ip_ttl == 0) {
			icmp_send_time_exceeded(sr, packet, len, interface);
			return;
		}

		/* TCP or UDP Payload */
		icmp_send_port_unreachable(sr, packet, len, interface);

	}

}

void processForward(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) {

	/* Ignore invalid packets */
	if (!is_sane_ip_packet(packet, len)) {
		return;
	}

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	/* Reply with timeout if TTL exceeded */
	ipHeader->ip_ttl = ipHeader->ip_ttl - 1;
	if (ipHeader->ip_ttl == 0) {
		icmp_send_time_exceeded(sr, packet, len, interface);
		return;
	}

	/* If NAT is enabled, do an address translation */
	if (sr->natEnable) {
		int failed = sr_nat_translate_packet(sr, packet, len, interface);
		if (failed) {
			/* packet could not be translated. Drop it */
			printf("ERROR: Packet could not be NAT-translated.\n");
			return;
		}
	}

	/* At this point, all checks passed, check routing table */
	struct sr_rt *closestMatch = findLongestMatchPrefix(sr->routing_table, ipHeader->ip_dst);

	if (closestMatch == NULL) {
		/* No match found. Send net unreachable */
		icmp_send_net_unreachable(sr, packet, len, interface);

	} else {
		/* Match found. Lookup MAC address in ARP cache */
		struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), ntohl(closestMatch->gw.s_addr));

		if (arpEntry != NULL) {
			/* Found MAC address. Send the packet */
			struct sr_rt *arpClosestMatch = findLongestMatchPrefix(sr->routing_table, ntohl(arpEntry->ip));
			send_packet_to_dest(sr, packet, len, arpClosestMatch->interface, arpEntry->mac, ntohl(arpEntry->ip));

		} else {
			/* Could not find MAC address. Queue request for ARP  */
			sr_arpcache_queuereq(&(sr->cache), ntohl(closestMatch->gw.s_addr), packet, len, interface);
		}
	}
}

int we_are_dest(struct sr_instance *sr, uint32_t ip) {
	struct sr_if *if_list = sr->if_list;
	while (if_list != NULL) {
		if (if_list->ip == ip) {
			return 1;
		}
		if_list = if_list->next;
	}
	return 0;
}

