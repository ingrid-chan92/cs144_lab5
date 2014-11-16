#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_router.h"

void arp_send_reply(struct sr_instance * , uint8_t *, unsigned int , char *);
void arp_send_request(struct sr_instance * , struct sr_arpreq *);
void handle_arpreq(struct sr_instance *, struct sr_arpreq *);

void send_packet_to_dest(struct sr_instance * , uint8_t *, unsigned int , char *, unsigned char *, uint32_t);
