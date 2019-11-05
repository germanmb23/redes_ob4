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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


static void checkARPandSendPacket(struct sr_instance *sr, sr_ethernet_hdr_t* packet,
   unsigned int length, struct sr_rt const * const route)
{

  printf("\n---------------linkArpAndSendPacket-------------------\n");


  uint32_t nextHopIpAddress = ntohl(route->gw.s_addr);
  struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache, nextHopIpAddress);

  packet->ether_type = htons(ethertype_ip);
  memcpy(packet->ether_shost, sr_get_interface(sr, route->interface)->addr, ETHER_ADDR_LEN);

   if (arpEntry != NULL)
   {
       printf("\n---------------arpEntry != NULL-------------------\n");

      memcpy(packet->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t*) packet, length, route->interface);

      free(arpEntry);
   }
   else
   {
            printf("\n---------------arpEntry = NULL-------------------\n");

      /* We need to ARP our next hop. Setup the request and send the ARP packet. */
      struct sr_arpreq* arpRequest = sr_arpcache_queuereq(&sr->cache, nextHopIpAddress,
         (uint8_t*) packet, length, route->interface);
      /*Envio el request sino se envio en el ultimo segundo*/
       if (difftime(time(0), arpRequest->sent) > 1.0)
          if (arpRequest->times_sent >= 5){
              host_unreachable(sr, arpRequest);
              sr_arpreq_destroy(&sr->cache, arpRequest);
          }
          else{
              sr_arp_request_send(sr, arpRequest->ip);
              arpRequest->sent = time(0);
              arpRequest->times_sent++;
          }
   }
}
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
struct sr_rt* sr_LPM(struct sr_instance* sr,uint32_t tip){
	struct sr_rt* res = NULL;
	uint32_t best = 0,mask;
	struct sr_rt* it = sr->routing_table;
	while(it){
		mask = it->mask.s_addr;
		if((it->dest.s_addr)==(mask&tip)){
		   	if(!res||(mask>best)){
		   		res = it;
		   		best = mask;
		   	}
		}
		it = it->next;
	}
	return res;
}

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

/* Send an ARP request. */
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip) {

      /* struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, 0x00, ip);*/
        printf("\n----------sr_arp_request_send------------\n");
        print_addr_ip_int(ip);
        struct sr_rt *ruta = sr_LPM(sr, htonl(ip));
        uint8_t* arpPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) arpPacket;
        sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*) (arpPacket + sizeof(sr_ethernet_hdr_t));


        uint8_t  broadcast[ETHER_ADDR_LEN];
        broadcast[0] = 0xff;
        broadcast[1] = 0xff;
        broadcast[2] = 0xff;
        broadcast[3] = 0xff;
        broadcast[4] = 0xff;
        broadcast[5] = 0xff;

        print_addr_eth(broadcast);
        print_addr_eth(sr_get_interface(sr, ruta->interface)->addr);

        /* Ethernet Header */
        memcpy(ethernetHdr->ether_dhost, broadcast, ETHER_ADDR_LEN*sizeof(uint8_t));
        memcpy(ethernetHdr->ether_shost, sr_get_interface(sr, ruta->interface)->addr, ETHER_ADDR_LEN*sizeof(uint8_t));
        ethernetHdr->ether_type = htons(ethertype_arp);

        /* ARP Header */
        arpHdr->ar_hrd = htons(arp_hrd_ethernet);
        arpHdr->ar_pro = htons(ethertype_ip);
        arpHdr->ar_hln = ETHER_ADDR_LEN;
        arpHdr->ar_pln = 4;
        arpHdr->ar_op = htons(arp_op_request);
        memcpy(arpHdr->ar_sha, sr_get_interface(sr, ruta->interface)->addr, ETHER_ADDR_LEN);
        arpHdr->ar_sip = sr_get_interface(sr, ruta->interface)->ip;
        memset(arpHdr->ar_tha, 0, ETHER_ADDR_LEN); /* Not strictly necessary by RFC 826 */
        arpHdr->ar_tip = htonl(ip);

        sr_send_packet(sr, arpPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), ruta->interface);

        /*free(arpPacket);*/
}

/* Send an ICMP error. */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

    printf("\n   %i    \n", type);
    if ((type==3)|| (type==11) ){
      send_TTL_Unreachable_ICMP(type, code, sr, ipDst, ipPacket);
      return;
    }
    else if (type == 0){
      send_echo_reply(type, code, sr, ipDst, ipPacket);
      return;
    }
}

void send_echo_reply(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
    sr_ip_hdr_t * siphdr = (sr_ip_hdr_t *) ipPacket;

    unsigned int replyPacketLength = sizeof(sr_ethernet_hdr_t) + ntohs(siphdr->ip_len);
    uint8_t *packetReply = (uint8_t *)malloc(replyPacketLength);
    printf("\n\n %i \n\n", htons(siphdr->ip_len));
    uint16_t ipLen = ntohs(siphdr->ip_len);

    struct sr_rt *tb = sr_LPM(sr,ipDst);

    if(tb==NULL){
      printf("\n-------------tb = NULL-------------\n");
      free(packetReply);
      return;
    }

    sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t*)(packetReply);
    ethHdr->ether_type = htons(ethertype_ip);
    memcpy(ethHdr->ether_shost, sr_get_interface(sr, tb->interface)->addr, ETHER_ADDR_LEN);

    sr_ip_hdr_t * ipHdr = (sr_ip_hdr_t *) (packetReply + sizeof(sr_ethernet_hdr_t));

    sr_icmp_hdr_t * icmpHdr = (sr_icmp_hdr_t *) (packetReply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    memcpy(ipHdr, siphdr, ipLen);
    ipHdr->ip_src = siphdr->ip_dst;
    ipHdr->ip_dst = siphdr->ip_src;
    ipHdr->ip_id = 0;
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

    icmpHdr->icmp_code = code;
    icmpHdr->icmp_type = type;
    icmpHdr->icmp_sum = 0;
    icmpHdr->icmp_sum = icmp_cksum(icmpHdr, ipLen - sizeof(sr_ip_hdr_t));

    checkARPandSendPacket(sr,packetReply,replyPacketLength,tb);
      free(packetReply);
}

void send_TTL_Unreachable_ICMP(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
        sr_ip_hdr_t* siphdr = (sr_ip_hdr_t*) ipPacket;

        unsigned int replyPacketLength = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_t3_hdr_t);
        uint8_t* packetReply = (uint8_t*)malloc(replyPacketLength);

        sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(packetReply);

        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packetReply+sizeof(sr_ethernet_hdr_t));

        struct sr_rt *tb = sr_LPM(sr,siphdr->ip_src);

        if(tb==NULL){
          printf("\n-------------tb = NULL-------------\n");
          free(packetReply);
          return;
        }

        memcpy(eth_hdr->ether_dhost,sr_get_interface(sr, tb->interface)->addr,ETHER_ADDR_LEN*sizeof(uint8_t));
        eth_hdr->ether_type = htons(ethertype_ip);

        ip_hdr->ip_hl = 5;
        ip_hdr->ip_v = 4;
        ip_hdr->ip_tos = siphdr->ip_tos;
        ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ip_hdr->ip_id = siphdr->ip_id;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_dst = siphdr->ip_src;
        ip_hdr->ip_src = sr_get_interface(sr, tb->interface)->ip;

        ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr,sizeof(sr_ip_hdr_t));

        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)(packetReply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        icmp_hdr->icmp_sum  = 0;
        icmp_hdr->next_mtu = 0;
        icmp_hdr->unused = 0;
        memcpy(icmp_hdr->data, siphdr,ICMP_DATA_SIZE);
        icmp_hdr->icmp_sum  = icmp3_cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        checkARPandSendPacket(sr, packetReply, replyPacketLength, tb);

}

void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

     printf("\n---------sr_handle_arp_packet--------------\n");

    unsigned int length = len;
    sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if * interF = sr_get_interface(sr, interface);


   switch (ntohs(arp_hdr->ar_op))
   {
      case arp_op_request:
      {
         if (arp_hdr->ar_tip == interF->ip)
         {
            /* Send Reply */
            uint8_t* replyPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)replyPacket;
            sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(replyPacket + sizeof(sr_ethernet_hdr_t));

            printf("Received ARP request. Sending ARP reply.\n");

            /* Ethernet Header */
            memcpy(ethernetHdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(ethernetHdr->ether_shost, interF->addr, ETHER_ADDR_LEN);
            ethernetHdr->ether_type = htons(ethertype_arp);

            /* ARP Header */
            arpHdr->ar_hrd = htons(arp_hrd_ethernet);
            arpHdr->ar_pro = htons(ethertype_ip);
            arpHdr->ar_hln = ETHER_ADDR_LEN;
            arpHdr->ar_pln = 4;
            arpHdr->ar_op = htons(arp_op_reply);
            memcpy(arpHdr->ar_sha, interF->addr, ETHER_ADDR_LEN);
            arpHdr->ar_sip = interF->ip;
            memcpy(arpHdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arpHdr->ar_tip = arp_hdr->ar_sip;

            sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interF->name);

            free(replyPacket);
         }
         break;
      }

      case arp_op_reply:
      {

         if (arp_hdr->ar_tip == interF->ip)
         {
            struct sr_arpreq* requestPointer = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip));

            if (requestPointer != NULL)
            {
               printf("Received ARP reply, sending all queued packets.\n");

               while (requestPointer->packets != NULL)
               {
                  struct sr_packet* curr = requestPointer->packets;

                  memcpy(((sr_ethernet_hdr_t*) curr->buf)->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

                  sr_send_packet(sr, curr->buf, curr->len, curr->iface);

                  requestPointer->packets = requestPointer->packets->next;

               }

               /* Elimino pedido de ip */
               sr_arpreq_destroy(&sr->cache, requestPointer);
            }
         }
         break;
      }

      default:
      {
         printf("\n Error Handle ARP\n");
         break;
      }
   }

   	   	/* Get ARP header and addresses */
   		/*sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
   		uint32_t ar_sip = arp_packet->ar_sip; // sender IP addr
   		uint32_t ar_tip = arp_packet->ar_tip; // target IP addr*/

   		/* add or update sender to ARP cache*/
   		/*uint8_t *src_mac = eHdr->ether_shost;
   		unsigned char *src_mac_char = (unsigned char *)src_mac;
   		struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), src_mac_char, ar_sip);*/

  /* check if the ARP packet is for one of my interfaces. */

  /* check if it is a request or reply*/

  /* if it is a request, construct and send an ARP reply*/

  /* else if it is a reply, add to ARP cache if necessary and send packets waiting for that reply*/
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {
      printf("\n---------------sr_handle_ip_packet-------------------\n");

      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

      if ((ip_hdr->ip_hl < 5) || (len - sizeof(sr_ethernet_hdr_t) < sizeof(sr_ip_hdr_t))){
       printf("\n---------Paquete IP invalido----------\n");
        return;
      }else{
        printf("\n---------Paquete IP Valido----------\n");
      }


      uint16_t headerChecksum = ip_hdr->ip_sum;
      ip_hdr->ip_sum = 0;
      uint16_t calculatedChecksum = ip_cksum(ip_hdr, ip_hdr->ip_hl*4);
      printf("\n\n\n\n---------%i----------\n\n\n\n", ip_hdr->ip_hl*4);

      if (headerChecksum != calculatedChecksum)
      {
         printf("\n---------Checksum Erroneo----------\n");
         return;
      }
      else
        printf("\n---------Checksum Correcto----------\n");

      bool toMe = false;
      if(sr_get_interface_given_ip(sr, ip_hdr->ip_dst) != NULL){
        toMe = true;
      }
      printf("\n---------------toMe %i-------------------\n", toMe);

        if (toMe)
        {
          PacketToMe(sr, ip_hdr, len, interface);
        }
        else
        {
          forwardIpPacket(sr, ip_hdr, len - ip_hdr->ip_hl*4, interface);
        }



	/* Get IP header and addresses */

	/* Check if packet is for me or the destination is in my routing table*/

	/* If non of the above is true, send ICMP net unreachable */

	/* Else if for me, check if ICMP and act accordingly*/

	/* Else, check TTL, ARP and forward if corresponds (may need an ARP request and wait for the reply) */

}

void PacketToMe(struct sr_instance* sr, sr_ip_hdr_t* packet, unsigned int length, struct sr_if  *interface)
        {
          printf("---------------IpHandleReceivedPacketToUs-------------------");
          if (packet->ip_p == ip_protocol_icmp)
          {
            printf("\n---------------Send Echo Reply-------------------\n");
            sr_send_icmp_error_packet(0, 0, sr, packet->ip_src, packet);
          }
          else
          {
            printf("---------------Send Port Unreachable-------------------");
            sr_send_icmp_error_packet(3, 3, sr, packet->ip_src, packet);
          }
}

      void forwardIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
        unsigned int length, struct sr_if* receivedInterface)
      {
        struct sr_rt* next_hop = sr_LPM(sr, packet->ip_dst);
        if (next_hop != NULL)
          printf("\n--------Existe Ruta a destino-------\n");
        /* Decremento TTL y forward */
        uint8_t packetTtl = packet->ip_ttl - 1;
        if (packetTtl == 0)
        {
            printf("\n---------------Time Exeeded-------------------\n");
            sr_send_icmp_error_packet(11, 0, sr, packet->ip_src, packet);
            return;
        }
        else
        {
            packet->ip_ttl = packetTtl;
            packet->ip_sum = 0;
            packet->ip_sum = ip_cksum(packet, packet->ip_hl*4);
        }

        if (next_hop != NULL)
        {
            printf("\n---------------Reenviar Paquete-------------------\n");
            uint8_t* forwardPacket = malloc(length + sizeof(sr_ethernet_hdr_t));
            memcpy(forwardPacket + sizeof(sr_ethernet_hdr_t), packet, length);

            checkARPandSendPacket(sr, (sr_ethernet_hdr_t*)forwardPacket, length + sizeof(sr_ethernet_hdr_t), next_hop);

            free(forwardPacket);
        }
        else
        {
            printf("\n---------------Network Unreachable-------------------\n");
            sr_send_icmp_error_packet(3, 0, sr, packet->ip_src, packet);
        }
      }


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

  /* Obtain dest and src MAC address */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */
