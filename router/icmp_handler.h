#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_router.h"

void icmp_send_echo_reply(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_net_unreachable(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_host_unreachable(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_port_unreachable(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_time_exceeded(struct sr_instance* , uint8_t * , unsigned int , char* );

void icmp_send_type3(struct sr_instance* , uint8_t * , unsigned int , char* , uint8_t, uint8_t);
