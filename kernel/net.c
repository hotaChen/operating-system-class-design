#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"
#define UDP_QUEUE_LEN   16       
#define UDP_BIND_SLOTS  64       

struct udp_pkt {
  uint32 src_ip;    
  uint16 sport;     
  int    len;       
  char  *data;      
};

struct udp_q {
  int    used;                
  uint16 port;                
  struct udp_pkt q[UDP_QUEUE_LEN];
  int head, tail, count;      
};
static struct udp_q udp_tab[UDP_BIND_SLOTS];

static void
udp_table_init(void)
{
  for (int i = 0; i < UDP_BIND_SLOTS; i++) {
    udp_tab[i].used = 0;
    udp_tab[i].port = 0;
    udp_tab[i].head = udp_tab[i].tail = udp_tab[i].count = 0;
    for (int j = 0; j < UDP_QUEUE_LEN; j++) {
      udp_tab[i].q[j].data = 0;
      udp_tab[i].q[j].len = 0;
    }
  }
}
static struct udp_q*
udp_lookup(uint16 port)
{
  for (int i = 0; i < UDP_BIND_SLOTS; i++)
    if (udp_tab[i].used && udp_tab[i].port == port)
      return &udp_tab[i];
  return 0;
}
static struct udp_q*
udp_alloc_slot(uint16 port)
{
  for (int i = 0; i < UDP_BIND_SLOTS; i++) {
    if (!udp_tab[i].used) {
      udp_tab[i].used = 1;
      udp_tab[i].port = port;
      udp_tab[i].head = udp_tab[i].tail = udp_tab[i].count = 0;
      return &udp_tab[i];
    }
  }
  return 0;
}
// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };

static struct spinlock netlock;

void
netinit(void)
{
  initlock(&netlock, "netlock");
  udp_table_init();
}

//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  //
  // Your code here.
  //
  int port;
  argint(0, &port); 

  if (port < 0 || port > 65535)
    return -1;

  acquire(&netlock);

  if (udp_lookup((uint16)port)) {
    release(&netlock);
    return 0;
  }

  struct udp_q *q = udp_alloc_slot((uint16)port);
  release(&netlock);
  return q ? 0 : -1;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  //
  // Optional: Your code here.
  //

  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  //
  // Your code here.
  //
  struct proc *p = myproc();
  int dport;
  uint64 u_src, u_sport, u_buf;
  int maxlen;

  argint(0, &dport);
  argaddr(1, &u_src);
  argaddr(2, &u_sport);
  argaddr(3, &u_buf);
  argint(4, &maxlen);

  if (dport < 0 || dport > 65535 || maxlen < 0)
    return -1;

  acquire(&netlock);
  struct udp_q *q = udp_lookup((uint16)dport);
  if (!q) {
    release(&netlock);
    return -1;   // 未 bind
  }

  while (q->count == 0) {
    sleep(q, &netlock);
  }

  struct udp_pkt pkt = q->q[q->head];
  q->head = (q->head + 1) % UDP_QUEUE_LEN;
  q->count--;

  release(&netlock);

  int n = pkt.len < maxlen ? pkt.len : maxlen;

  if (copyout(p->pagetable, u_buf, pkt.data, n) < 0) {
    kfree(pkt.data);
    return -1;
  }
  if (copyout(p->pagetable, u_src, (char*)&pkt.src_ip, sizeof(pkt.src_ip)) < 0) {
    kfree(pkt.data);
    return -1;
  }
  if (copyout(p->pagetable, u_sport, (char*)&pkt.sport, sizeof(pkt.sport)) < 0) {
    kfree(pkt.data);
    return -1;
  }

  kfree(pkt.data);
  return n;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void
ip_rx(char *buf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  //
  // Your code here.
  //
  /*if (len < (int)(sizeof(struct eth) + sizeof(struct ip))) {
    kfree(buf);
    return;
  }

  struct eth *eth = (struct eth *)buf;
  struct ip  *ip  = (struct ip *)(eth + 1);
  if (ip->ip_p != IPPROTO_UDP) {
    kfree(buf);
    return;
  }
  if (len < (int)(sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp))) {
    kfree(buf);
    return;
  }

  struct udp *uh = (struct udp *)(ip + 1);

  uint16 dport = ntohs(uh->dport);
  uint16 sport = ntohs(uh->sport);
  uint16 ulen  = ntohs(uh->ulen);

  if (ulen < sizeof(struct udp)) {
    kfree(buf);
    return;
  }

  int payload_len = (int)ulen - (int)sizeof(struct udp);
  char *payload = (char *)(uh + 1);
  int need = sizeof(struct eth) + sizeof(struct ip) + ulen;
  if (len < need) {
    kfree(buf);
    return;
  }

  uint32 src_ip = ntohl(ip->ip_src);
  acquire(&netlock);
  struct udp_q *q = udp_lookup(dport);
  if (!q) {
    release(&netlock);
    kfree(buf);
    return;
  }

  if (q->count == UDP_QUEUE_LEN) {
    release(&netlock);
    kfree(buf);
    return;
  }

  if (payload_len > PGSIZE) payload_len = PGSIZE; 

  char *copy = kalloc();
  if (!copy) {
    release(&netlock);
    kfree(buf);
    return;
  }
  memmove(copy, payload, payload_len);

  int t = q->tail;
  q->q[t].src_ip = src_ip;   
  q->q[t].sport  = sport;    
  q->q[t].len    = payload_len;
  q->q[t].data   = copy;

  q->tail = (q->tail + 1) % UDP_QUEUE_LEN;
  q->count++;
  wakeup(q);
  release(&netlock);*/
  kfree(buf);
}

//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if(seen_arp){
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  char *buf = kalloc();
  if(buf == 0)
    panic("send_arp_reply");
  
  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN); // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;

  if(len >= sizeof(struct eth) + sizeof(struct arp) &&
     ntohs(eth->type) == ETHTYPE_ARP){
    arp_rx(buf);
  } else if(len >= sizeof(struct eth) + sizeof(struct ip) &&
     ntohs(eth->type) == ETHTYPE_IP){
    ip_rx(buf, len);
  } else {
    kfree(buf);
  }
}
