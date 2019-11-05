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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

//Importado por mi
#include <stdbool.h>

//aca usdar arp para averiguar la mac
void send_eth_packet(uint32_t ip_src, uint32_t ip_dst, struct sr_instance *sr, char *interface, uint8_t *ipPacket){

}

//Me devuelve un puntero con la fila de la routing table que me sirve para enviar el paquete, sino me sirve ninguna retorna NULL
struct sr_rt *porDondeSalir(uint32_t ipDst, struct sr_instance *sr){
    in_addr_t lpm = 0;
    struct sr_rt *default_gw = NULL;
    struct sr_rt *gw = NULL;

    for(struct sr_rt *entry_table = sr->routing_table; entry_table != NULL; entry_table = entry_table->next){
      if (entry_table->dest.s_addr == 0){
        default_gw = entry_table;
      }
      if(entry_table->mask.s_addr & ipDst == entry_table->dest.s_addr)
        if(entry_table->gw.s_addr > lpm){
          gw = entry_table;
        }
    }
    if (lpm = 0 && default_gw != NULL)
      gw = default_gw;

    return gw;
}
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
//Implementada por ellos
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
}

/* Send an ICMP error. */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
	//falta averiguar a que mac mando
  /*int icmpPacketLen = sizeof(sr_arp_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	uint8_t *icmpPacket = malloc(icmpPacketLen);
	sr_icmp_hdr_t *icmp_hdr = (struct sr_icmp_hdr *) icmpPacket;
	memcpy(icmp_hdr->icmp_type, type, sizeof(type));
	memcpy(icmp_hdr->icmp_code, code, sizeof(code));
  uint32_t cksum = icmp_cksum(icmp_hdr, sizeof(icmp_hdr));
	memcpy(icmp_hdr->icmp_sum, cksum, sizeof(cksum));
  struct salida_t *salida;
  salida = porDondeSalir(ipDst, sr);
  sr_send_packet(sr, icmp_hdr, icmpPacketLen, salida->interface);
  */
  }

void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

		/* Get ARP header and addresses */
		sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		uint32_t ar_sip = arp_packet->ar_sip; // sender IP addr
		uint32_t ar_tip = arp_packet->ar_tip; // target IP addr

		/* add or update sender to ARP cache*/
		uint8_t *src_mac = eHdr->ether_shost;
		unsigned char *src_mac_char = (unsigned char *)src_mac;
		sr_arpreq *arpreq = sr_arpcache_insert(sr->cache, src_mac_char, ar_sip);

		/* check if the ARP packet is for one of my interfaces. */

		/* check if it is a request or reply*/

		/* if it is a request, construct and send an ARP reply*/

		/* else if it is a reply, add to ARP cache if necessary and send packets waiting for that reply*/

}

/*
 int sr_send_packet (struct sr_instance * sr, uint8_t * buf, unsigned int
len, const char * iface)
Este método, ubicado en sr_vns_comm.c, enviará un paquete arbitrario de longitud, len, a la red
fuera de la interfaz especificada por iface.
No debe liberar el búfer que se le dio en sr_handlepacket (es por eso que el búfer está
etiquetado como "lent" en los comentarios). Usted es responsable de hacer una gestión correcta
de la memoria en los buffers que sr_send_packet le presta (es decir, sr_send_packet no
liberará la memoria de los buffers que le pase).
*/

void sr_handle_ip_packet(struct sr_instance *sr,
                        uint8_t *packet /* lent */,
                        unsigned int len,
                        uint8_t *srcAddr,
                        uint8_t *destAddr,
                        char *interface /* lent */,
                        sr_ethernet_hdr_t *eHdr)
    {
	/* Get IP header and addresses */
		sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		uint32_t ip_src = ip_packet->ip_src;
		uint32_t ip_dst = ip_packet->ip_dst;
		uint8_t ip_ttl = ip_packet->ip_ttl;


	/* Check if packet is for me or the destination is in my routing table*/
		//Me fijo si tengo alguna interface con la ip destino del paquete ip
		bool forMe = false;

		struct sr_if *it = sr->if_list;
		while(it != NULL){
			if (it->ip == destAddr){
				forMe = true;
				break;
			}
			else
				it = it->next;
		}
    //Me fijo si lo tengo en mi routing table
    in_addr_t gw = NULL, default_gw, lpm = 0;
    bool inRT = false;
    if (!forMe)
      {
        struct salida_t *salida;
        salida = porDondeSalir(ip_dst, sr);
        if (salida == NULL)
          inRT = false;
      }

	/* If non of the above is true, send ICMP net unreachable */
		//si no es para mi y no esta en la tabla de ruteo
    if(!forMe && !inRT)
			// red inalcanzable tipo 3, codigo 0
			sr_send_icmp_error_packet(0x0003, 0x0000, sr, ip_src, ip_dst);

	/* Else if for me, check if ICMP and act accordingly*/
      if (forMe){
        //ya habia correido el puntero largo sr_ethernet_hdr_t arriba ahora lo corro sr_ip_hdr_t para obterer el paquete ICMP
        sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t *) (ip_packet + sizeof(sr_ip_hdr_t));
        //mne fijo si es un echo request
        if(ip_protocol(ip_packet) == ip_protocol_icmp)
          if(icmp_packet->icmp_type == 0x0008 && icmp_packet->icmp_type == 0x0000)
            //envio echo reply type 0
            sr_send_icmp_error_packet(0x0000, 0x0000, sr, ip_src, ip_dst);

      }

	/* Else, check TTL, ARP and forward if corresponds (may need an ARP request and wait for the reply) */
  if(inRT){
    if (ip_packet->ip_ttl - 1 == 0){
      //ICMP time exeeded type 11 code 0
      sr_send_icmp_error_packet(0x000B, 0x0000, sr, ip_src, ip_packet);
    }
    else {
      send_eth_packet(ip_src, ip_dst, sr, interface, ip_packet);
    }
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

//Implementada por ellos
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
