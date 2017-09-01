#include "dnsproxy.h"

/* ----------------------------- variables --------------------------------- */
static struct dns_cache_node dns_cache;
static struct net *module_ns_net;

static struct nf_hook_ops hook_post_ops = {
	.hook     = hook_post,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops hook_pre_ops = {
	.hook     = hook_pre,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};
/* ----------------------------- functions --------------------------------- */
static int __init dnsproxy_start(void)
{
	printk(KERN_INFO "dnsproxy setting module ns_net\n");
	module_ns_net = get_net_ns_by_pid(task_pid_nr(current));

	printk(KERN_INFO "dnsproxy registering netfilter hooks\n");
	nf_register_hook(&hook_post_ops);
	nf_register_hook(&hook_pre_ops);

	printk(KERN_INFO "dnsproxy cache init\n");
	INIT_LIST_HEAD(&dns_cache.list);

	return 0;
}

static void __exit dnsproxy_stop(void)
{
	struct dns_cache_node *node, *tmp;

	printk(KERN_INFO "dnsproxy stopping\n");
	nf_unregister_hook(&hook_post_ops);
	nf_unregister_hook(&hook_pre_ops);

	list_for_each_entry_safe(node, tmp, &dns_cache.list, list) {
		list_del(&node->list);
		kfree(node->name);
		kfree(node->answer);
		kfree(node);
	}

	printk(KERN_INFO "dnsproxy stopped\n");
}

static uint32_t get_datalen_question(struct QUESTION *dnsq)
{
	const uint8_t* buf = (uint8_t *)dnsq;
	uint32_t i = 0;
	while(buf[i] != 0) {
		i += (buf[i] + 1);

		if (i >= QNAME_MAXLEN) {
			i = 0;
			break;
		}
	}

	if (i)
		i++; //for '\0'

	return i;
}

// replying on dns questions from cache
static uint32_t hook_post(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
	struct iphdr     *ip_h;
	struct udphdr    *udp_h;

	struct HEADER    *dns_h;
	struct QUESTION  *dns_q;

	static struct dns_cache_node *cache_node;

	uint32_t dns_q_qnamelen = 0;

	// eth check
	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	// udp check
	ip_h = ip_hdr(skb);
	if (ip_h->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	// port check
	udp_h = (void *)(struct updhdr *)skb_transport_header(skb);
	if (udp_h->dest != ntohs(DNS_SERVER_PORT))
		return NF_ACCEPT;

	// dns
	dns_h = (struct HEADER *)
	        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN);

	// dns question
	dns_q = (struct QUESTION *)
	        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN);
	dns_q_qnamelen = get_datalen_question(dns_q);
	if (dns_q_qnamelen <= 0) {
		return NF_ACCEPT;
	}

	cache_node = search_cache((uint8_t *)dns_q);
	if (cache_node) {
		printk(KERN_INFO "dnsproxy %s found in cache\n", (char *)dns_q);
		cache_node->dns_id = ntohs(dns_h->id);

		send_reply_dnspacket(skb, ip_h->saddr, udp_h->source,
		                     ip_h->daddr, cache_node);
		printk(KERN_INFO"dnsproxy sending dns reply packet from cache\n");
		return NF_DROP;
	}

	return NF_ACCEPT;
}

// storing dns answers from packets to cache
static uint32_t hook_pre(void *priv, struct sk_buff *skb,
                         const struct nf_hook_state *state)
{
	struct iphdr    *ip_h;
	struct udphdr   *udp_h;

	struct HEADER   *dns_h;
	struct QUESTION *dns_q;
	struct ANSWER   *dns_a;
	struct _ANSWER  *dns__a;

	uint32_t dns_q_qnamelen = 0;
	uint32_t dns_a_len = 0;
	uint32_t answer_count = 0;

	static struct dns_cache_node *cache_node;

	// eth check
	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	// udp check
	ip_h = ip_hdr(skb);
	if (ip_h->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	// port check
	udp_h = (void *)(struct updhdr *)skb_transport_header(skb);
	if (udp_h->source != ntohs(DNS_SERVER_PORT))
		return NF_ACCEPT;

	dns_h = (struct HEADER *)
	        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN);
	answer_count = ntohs(dns_h->an_count);

	dns_q = (struct QUESTION *)
	        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN);

	dns_q_qnamelen = get_datalen_question(dns_q);
	if (dns_q_qnamelen <= 0) {
		return NF_ACCEPT;
	}

	dns__a = (struct _ANSWER *)
	         (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN +
	          (dns_q_qnamelen + DNS_Q_CONSTLEN) + DNS_A_OFFSET);

	// dns answer
	dns_a = (struct ANSWER *)
	        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN +
	         (dns_q_qnamelen + DNS_Q_CONSTLEN));

	dns_a_len = get_datalen_answer(answer_count);
	if (dns_a_len <= 0) {
		return NF_ACCEPT;
	}

	cache_node = search_cache((uint8_t*)dns_q);
	if (!cache_node) {
		printk(KERN_INFO "dnsproxy adding to cache \n");
		cache_node = add_to_cache((uint8_t *)dns_q, dns_q_qnamelen,
		                          (uint8_t *)dns_a, dns_a_len);
		if (cache_node)
			cache_node->answer_count = answer_count;
		else
			printk(KERN_INFO "dnsproxy add_to_cache error\n");
	}

	return NF_ACCEPT;
}

static uint32_t get_datalen_answer(uint32_t dns_answer_count)
{
	return (DNS_ANSWLEN * (dns_answer_count + CONSTMAGIC));
}

// sending dns packet
static void send_reply_dnspacket(struct sk_buff *in_skb, uint32_t dst_ip,
                                 uint32_t dst_port, uint32_t src_ip,
                                 struct dns_cache_node *node)
{
	struct sk_buff   *nskb;
	struct iphdr     *ip_h;
	struct udphdr    *udp_h;

	struct HEADER    *dns_h;
	struct _QUESTION *dns__q;

	uint8_t *data_q;
	void    *data_a;

	uint32_t dns_q_len;
	uint32_t dns_a_len;
	uint32_t udp_len;

	dns_q_len = (node->name_len);
	dns_a_len = (node->answer_len);

	udp_len   = (UPD_HDRLEN + DNS_HDRLEN + dns_q_len + dns_a_len);

	nskb = alloc_skb(sizeof(struct iphdr) + udp_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb) {
		printk (KERN_ERR "dnsproxy aloc_skb error\n");
		return;
	}

	skb_reserve(nskb, LL_MAX_HEADER);
	skb_reset_network_header(nskb);

	// IP
	ip_h = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	ip_h->version  = 4;
	ip_h->ihl      = sizeof(struct iphdr) / 4;
	ip_h->ttl      = 64;
	ip_h->tos      = 0;
	ip_h->id       = 0;
	ip_h->frag_off = htons(IP_DF);
	ip_h->protocol = IPPROTO_UDP;
	ip_h->saddr    = src_ip;
	ip_h->daddr    = dst_ip;
	ip_h->tot_len  = htons(sizeof(struct iphdr) + udp_len);
	ip_h->check    = 0;
	ip_h->check    = ip_fast_csum((uint8_t *)ip_h, ip_h->ihl);

	// UDP
	udp_h = (struct udphdr *)skb_put(nskb, UPD_HDRLEN);
	memset(udp_h, 0, sizeof(*udp_h));
	udp_h->source = htons(DNS_SERVER_PORT);
	udp_h->dest   = dst_port;
	udp_h->len    = htons(udp_len);

	// DNS
	dns_h = (struct HEADER *)skb_put(nskb, DNS_HDRLEN);
	dns_h->id       = (uint16_t)htons(node->dns_id);
	dns_h->qr       = 0;
	dns_h->opcode   = 0;
	dns_h->aa       = 0;
	dns_h->tc       = 0;
	dns_h->rd       = 1;
	dns_h->ra       = 0;
	dns_h->z        = 0;
	dns_h->ad       = 0;
	dns_h->cd       = 0;
	dns_h->rcode    = 0;
	dns_h->qd_count = htons(1);
	dns_h->an_count = htons(node->answer_count);
	dns_h->ns_count = 0;
	dns_h->ar_count = 0;

	skb_dst_set(nskb, dst_clone(skb_dst(in_skb)));
	nskb->protocol = htons(ETH_P_IP);

	//DNS QUESTION field 'q_name'
	data_q = (uint8_t *)skb_put(nskb, dns_q_len);
	memcpy(data_q, (node->name), dns_q_len);

	//DNS QUESTION fields 'q_type' and 'q_class'
	dns__q = (struct _QUESTION *)skb_put(nskb, DNS_Q_CONSTLEN);
	dns__q->q_type  = htons(1);
	dns__q->q_class = htons(1);

	//DNS ANSWER
	data_a = (void *)skb_put(nskb, dns_a_len);
	memcpy(data_a, (node->answer), dns_a_len);

	//UDP HEADER continuation
	udp_h->check  = 0;
	udp_h->check  = csum_tcpudp_magic(src_ip, dst_ip,
	                                  udp_len, IPPROTO_UDP,
	                                  csum_partial(udp_h, udp_len, 0));

	if (ip_route_me_harder(module_ns_net, nskb, RTN_UNSPEC)) {
		printk (KERN_ERR "\ndnsproxy ip_route_me_harder error");
		kfree_skb(nskb);
	}

	dst_output(module_ns_net, NULL, nskb);
}

static struct dns_cache_node * add_to_cache(uint8_t *name, uint32_t name_len,
        uint8_t *answer, uint32_t answer_len)
{
	struct dns_cache_node *node_ptr;

	node_ptr = kmalloc(sizeof(*node_ptr), GFP_KERNEL);
	if (!node_ptr) {
		printk (KERN_ERR "\ndnsproxy kmalloc error");
		return NULL;
	}

	node_ptr->name = kmalloc(name_len, GFP_KERNEL);
	memset(node_ptr->name, 0, name_len);
	memcpy(node_ptr->name, name, name_len);
	node_ptr->name_len = name_len;

	node_ptr->answer = kmalloc(answer_len, GFP_KERNEL);
	memset(node_ptr->answer, 0, answer_len);
	memcpy(node_ptr->answer, answer, answer_len);
	node_ptr->answer_len = answer_len;

	INIT_LIST_HEAD(&node_ptr->list);
	list_add_tail(&(node_ptr->list), &(dns_cache.list));

	return node_ptr;
}

static struct dns_cache_node * search_cache(uint8_t *name)
{
	struct dns_cache_node *node;
	list_for_each_entry(node, &dns_cache.list, list) {
		if (memcmp(node->name, name, node->name_len) == 0)
			return node;
	}

	return NULL;
}

MODULE_LICENSE("GPL");
module_init(dnsproxy_start);
module_exit(dnsproxy_stop);

