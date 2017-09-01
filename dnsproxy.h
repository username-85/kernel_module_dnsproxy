#ifndef DNSPROXY_H
#define DNSPROXY_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/ip.h>

#define DNS_SERVER_PORT   53
#define UPD_HDRLEN         8
#define DNS_HDRLEN        12
#define DNS_ANSWLEN       16
#define DNS_Q_CONSTLEN     4   /* Constant sized fields struct _QUESTION */
#define DNS_A_OFFSET       2   /* Offset in association with DNS packet compression */
#define QNAME_MAXLEN      63
#define CONSTMAGIC         1

/* --------------------------- functions ------------------------------------*/

/* Structure of Header DNS */
struct HEADER {
	uint16_t id;       // identification number

	/* flags */
	uint8_t qr     :1; // query/response flag
	uint8_t opcode :4; // purpose of message
	uint8_t aa     :1; // authoritive answer
	uint8_t tc     :1; // truncated message
	uint8_t rd     :1; // recursion desired
	uint8_t ra     :1; // recursion available
	uint8_t z      :1; // its z! reserved
	uint8_t ad     :1; // authenticated data
	uint8_t cd     :1; // checking disabled
	uint8_t rcode  :4; // response code

	/* count */
	uint16_t qd_count; // number of question entries
	uint16_t an_count; // number of answer entries
	uint16_t ns_count; // number of authority entries
	uint16_t ar_count; // number of resource entries
};

/* Constant sized fields of Question structure */
struct _QUESTION {
	uint16_t q_type;
	uint16_t q_class;
};

/* Structure of a Question DNS */
struct QUESTION {
	uint8_t *q_name;
	struct _QUESTION *question;
};

/* Constant sized fields of Answer structure */
struct _ANSWER {
	uint16_t type;
	uint16_t _class;
	uint32_t   ttl;       // number of seconds
	uint16_t rd_length; // length field rdata
};

/* Structure of a Answer DNS */
struct ANSWER {
	uint8_t *name;
	struct _ANSWER *answer;
	uint8_t *rdata;
};

/* dns cache node */
struct dns_cache_node {
	uint8_t *name;
	uint8_t *answer;
	uint16_t name_len;
	uint16_t answer_len;
	uint16_t dns_id;
	uint16_t answer_count;

	struct list_head list; /* kernel's list structure */
};

/* --------------------------- functions ------------------------------------*/
static struct dns_cache_node * add_to_cache(uint8_t *name, uint32_t name_len,
        uint8_t *answer, uint32_t answer_len);
static struct dns_cache_node * search_cache(uint8_t *name);

static uint32_t get_datalen_question(struct QUESTION *dnsq);
static uint32_t get_datalen_answer(unsigned int answer_count);

static void send_reply_dnspacket(struct sk_buff *in_skb,
                                 uint32_t dst_ip, uint32_t dst_port,
                                 uint32_t src_ip, struct dns_cache_node *node);

static uint32_t hook_post(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state);

static uint32_t hook_pre(void *priv, struct sk_buff *skb,
                         const struct nf_hook_state *state);

#endif
