/*
 * Copyright (C) 2017 Michio Honda
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(__FreeBSD__)
#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/conf.h>	/* cdevsw struct, UID, GID */
#include <sys/sockio.h>
#include <sys/socketvar.h>	/* struct socket */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/rwlock.h>
#include <sys/socket.h> /* sockaddrs */
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/bpf.h>		/* BIOCIMMEDIATE */
#include <net/ethernet.h>	/* struct ether_header */
#include <netinet/in.h>		/* IPPROTO_UDP */
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/endian.h>
#include <sys/refcount.h>

#elif defined(linux)
#include "bsd_glue.h"
#define ENOTSUP ENOTSUPP
#else
#error Unsupported platform
#endif /* unsupported */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_bdg.h>

#ifdef WITH_STACK

int stack_no_runtocomp = 0;
int stack_host_batch = 1;
int stack_verbose = 0;
#ifdef linux
EXPORT_SYMBOL(stack_verbose);
#endif
static int stack_extra = 2048;
SYSBEGIN(vars_stack);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, stack_no_runtocomp, CTLFLAG_RW, &stack_no_runtocomp, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stack_host_batch, CTLFLAG_RW, &stack_host_batch, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stack_verbose, CTLFLAG_RW, &stack_verbose, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stack_extra, CTLFLAG_RW, &stack_extra, 0 , "");
SYSEND;

static inline struct netmap_adapter *
nm_st_na(const struct netmap_adapter *slave)
{
	const struct netmap_vp_adapter *vpna;

	if (unlikely(!slave))
		return NULL;
	vpna = (const struct netmap_vp_adapter *)slave;
	return &vpna->na_bdg->bdg_ports[0]->up;
}

static inline int
nm_st_is_host(struct netmap_adapter *na)
{
	return na->nm_register == NULL;
}

/*
 * We need to form lists using scb and buf_idx, because they
 * can be very long due to ofo packets that have been queued
 */
#define STACK_FD_HOST	(NM_BDG_MAXPORTS*NM_BDG_MAXRINGS-1)

struct nm_st_bdg_q {
	uint32_t bq_head;
	uint32_t bq_tail;
};

struct nm_st_fwd {
	uint16_t nfds;
	uint16_t npkts;
	struct nm_st_bdg_q fde[NM_BDG_MAXPORTS * NM_BDG_MAXRINGS
		+ NM_BDG_BATCH_MAX]; /* XXX */
	uint32_t tmp[NM_BDG_BATCH_MAX];
	uint32_t fds[NM_BDG_BATCH_MAX/2]; // max fd index
};
#define STACK_FT_NULL 0	// invalid buf index

struct nm_st_extra_slot {
	struct netmap_slot slot;
	uint16_t prev;
	uint16_t next;
};

struct nm_st_extra_pool {
	u_int num;
	struct nm_st_extra_slot *slots;
	uint32_t free;
	uint32_t free_tail;
	uint32_t busy;
	uint32_t busy_tail;
};
#define NM_EXT_NULL	((uint16_t)~0)
void
nm_st_extra_dequeue(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_ring *ring;
	struct nm_st_extra_pool *pool;
	struct nm_st_extra_slot *slots, *extra;
	u_int pos;

	/* XXX raising mbuf might have been orphaned */
	if (unlikely(kring == NULL)) {
		RD(1, "no kring");
		return;
	}
	if (unlikely(kring->nr_mode != NKR_NETMAP_ON)) {
		RD(1, "not NKR_NETMAP_ON");
		return;
	}
	pool = kring->extra;
	if (unlikely(!pool)) {
		RD(1, "kring->extra has gone");
		return;
	}
	if (unlikely(!pool->num)) {
		RD(1, "extra slots have gone");
		return;
	}

	slots = pool->slots;
	ring = kring->ring;
	/* nothing to do if I am on the ring */
	if ((uintptr_t)slot >= (uintptr_t)ring->slot &&
	    (uintptr_t)slot < (uintptr_t)(ring->slot + kring->nkr_num_slots)) {
		return;
	} else if (!(likely((uintptr_t)slot >= (uintptr_t)slots) &&
	      likely((uintptr_t)slot < (uintptr_t)(slots + pool->num)))) {
		D("WARNING: invalid slot");
		return;
	}

	extra = (struct nm_st_extra_slot *)slot;
	pos = extra - slots;

	/* remove from busy list (offset has been modified to indicate prev) */
	if (extra->next == NM_EXT_NULL)
		pool->busy_tail = extra->prev; // might be NM_EXT_NULL
	else
		slots[extra->next].prev = extra->prev; // might be NM_EXT_NULL
	if (extra->prev == NM_EXT_NULL)
		pool->busy = extra->next; // might be NM_EXT_NULL
	else
		slots[extra->prev].next = extra->next; // might be NM_EXT_NULL

	/* append to free list */
	extra->next = NM_EXT_NULL;
	if (unlikely(pool->free == NM_EXT_NULL))
		pool->free = pos;
	else
		slots[pool->free_tail].next = pos;
	extra->prev = pool->free_tail; // can be NM_EXT_NULL
	pool->free_tail = pos;
}

int
nm_st_extra_enqueue(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	struct nm_st_extra_pool *pool = kring->extra;
	struct nm_st_extra_slot *slots = pool->slots, *extra;
	uint32_t tmp;
	u_int pos;
	struct nm_st_cb *scb;

	if (pool->free_tail == NM_EXT_NULL)
		return EBUSY;

	pos = pool->free_tail;
	extra = &slots[pos];

	/* remove from free list */
	pool->free_tail = extra->prev;
	if (unlikely(pool->free_tail == NM_EXT_NULL)) // I was the last one
		pool->free = NM_EXT_NULL;
	else // not the last one
		slots[extra->prev].next = NM_EXT_NULL;

	/* append to busy list */
	extra->next = NM_EXT_NULL;
	if (pool->busy == NM_EXT_NULL) {
		pool->busy = pos;
	} else
		slots[pool->busy_tail].next = pos;
	extra->prev = pool->busy_tail;
	pool->busy_tail = pos;

	scb = NMCB_BUF(NMB(na, slot));
	tmp = extra->slot.buf_idx; // backup
	extra->slot = *slot;
	slot->buf_idx = tmp;
	slot->flags |= NS_BUF_CHANGED;
	slot->len = slot->offset = slot->next = 0;
	slot->fd = 0;

	scbw(scb, kring, &extra->slot);

	return 0;
}

static inline struct nm_st_fwd *
nm_st_get_fwd(struct netmap_kring *kring)
{
	return (struct nm_st_fwd *)kring->nkr_ft;
}

void
nm_st_add_fdtable(struct nm_st_cb *scb, struct netmap_kring *kring)
{
	struct netmap_slot *slot = scb_slot(scb);
	struct nm_st_fwd *ft;
	uint32_t fd = slot->fd;
	struct nm_st_bdg_q *fde;
	int i;

	ft = nm_st_get_fwd(kring);
	i = slot->buf_idx;
	scb->next = STACK_FT_NULL;
	fde = ft->fde + fd;
	if (fde->bq_head == STACK_FT_NULL) {
		fde->bq_head = fde->bq_tail = i;
		ft->fds[ft->nfds++] = fd;
	} else {
		struct netmap_slot s = { fde->bq_tail };
		struct nm_st_cb *prev = NMCB_BUF(NMB(kring->na, &s));
		prev->next = fde->bq_tail = i;
	}
	ft->npkts++;
}

/* TX:
 * 1. sort packets by socket with forming send buffer (in-order iteration)
 * 2. do tcp processing on each socket (out-of-order iteration)
 * We must take into account MOREFRAGS.
 * We do not support INDIRECT as packet movement is done by swapping
 * We thus overwrite ptr field (8 byte width) in a slot to store a
 * socket (4 byte), next buf index (2 byte).
 * The rest of 2 bytes may be used to store the number of frags
 * (1 byte) and destination port (1 byte).
 */

struct nm_st_sk_adapter *
nm_st_ska_from_fd(struct netmap_adapter *na, int fd)
{
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;

	if (unlikely(fd >= sna->sk_adapters_max))
		return NULL;
	return sna->sk_adapters[fd];
}

/* Differ from nm_kr_space() due to different meaning of the lease */
static inline uint32_t
nm_st_kr_rxspace(struct netmap_kring *k)
{
	int busy = k->nr_hwtail - k->nkr_hwlease;

	if (busy < 0)
		busy += k->nkr_num_slots;
	return k->nkr_num_slots - 1 - busy;
}

static void
nm_st_flush(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na, *rxna;
	struct nm_bridge *b = ((struct netmap_vp_adapter *)na)->na_bdg;
	struct nm_st_fwd *ft;
	u_int lim_rx, howmany;
	u_int dst_nr, nrings;
	struct netmap_kring *rxkring;
	int j, want, sent = 0, nonfree_num = 0;
	uint32_t *nonfree;

	if (na->na_flags & NAF_BDG_MAYSLEEP) {
		BDG_RLOCK(b);
	} else if (!BDG_RTRYLOCK(b)) {
		return;
	}

	ft = nm_st_get_fwd(kring);
	nonfree = ft->tmp;
	if (nm_st_is_host(na)) {
		want = kring->rhead - kring->nr_hwcur;
		if (want < 0)
			want += kring->nkr_num_slots;
	} else {
		want = ft->npkts;
	}

	/* XXX perhaps this is handled later? */
	if (unlikely(b->bdg_active_ports < 3)) {
		RD(1, "only 1 or 2 active ports");
		goto runlock;
	}
	/* Now, we know how many packets go to the receiver */

	if (na == nm_st_na(na) || nm_st_is_host(na)) {
		rxna = &b->bdg_ports[1]->up; /* XXX */
	} else {
		rxna = nm_st_na(na);
	}

	if (unlikely(!nm_netmap_on(rxna))) {
		panic("receiver na off");
	}
	//dst_nr = kring - NMR(kring->na, NR_TX); // XXX cannot rely on ring_id
	dst_nr = kring->ring_id;
	nrings = nma_get_nrings(rxna, NR_RX);
	if (dst_nr >= nrings)
		dst_nr = dst_nr % nrings;
	rxkring = NMR(rxna, NR_RX)[dst_nr];
	lim_rx = rxkring->nkr_num_slots - 1;
	j = rxkring->nr_hwtail;

	/* under lock */

	mtx_lock(&rxkring->q_lock);
	if (unlikely(rxkring->nkr_stopped)) {
		mtx_unlock(&rxkring->q_lock);
		goto runlock;
	}
	howmany = nm_st_kr_rxspace(rxkring);
	if (howmany < want) { // try to reclaim completed buffers
		u_int i = rxkring->nkr_hwlease, n = 0;

		for (; i != rxkring->nr_hwtail; i = nm_next(i, lim_rx), n++) {
			struct netmap_slot *slot = &rxkring->ring->slot[i];
			struct nm_st_cb *scb = NMCB_BUF(NMB(rxna, slot));

			if (nm_st_cb_valid(scb) &&
			    nm_st_cb_rstate(scb) != MB_NOREF)
				break;
		}
		howmany += n;
		rxkring->nkr_hwlease = i;
	} else if (likely(want < howmany)) {
		howmany = want;
	}

	if (nm_st_is_host(na)) { // don't touch buffers
		u_int k = kring->nr_hwcur, lim_tx = kring->nkr_num_slots - 1;

		while (howmany--) {
			struct netmap_slot *ts, *rs, tmp;

			ts = &kring->ring->slot[k];
			__builtin_prefetch(ts);
			rs = &rxkring->ring->slot[j];
			__builtin_prefetch(rs);
			tmp = *rs;
			*rs = *ts;
			*ts = tmp;
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			k = nm_next(k, lim_tx);
			j = nm_next(j, lim_rx);
			sent++;
		}
	} else {
		int n;
		for (n = 0; n < ft->nfds && howmany;) {
			int fd = ft->fds[n];
			struct nm_st_bdg_q *bq = ft->fde + fd;
			uint32_t next = bq->bq_head;
			do {
				struct netmap_slot tmp, *ts, *rs;
				struct nm_st_cb *scb;

				rs = &rxkring->ring->slot[j];
				__builtin_prefetch(rs);
				tmp.buf_idx = next;
				scb = NMCB_BUF(NMB(na, &tmp));
				next = scb->next;
				//if (unlikely(!nm_st_cb_valid(scb))) {
				//	D("invalid scb %p next %u", scb, next);
				//	goto skip;
				//}
				ts = scb_slot(scb);
				//if (unlikely(ts == NULL)) {
				//	D("null ts %p next %u", ts, next);
				//	goto skip;
				//}
				if (nm_st_cb_rstate(scb) == MB_TXREF) {
					nonfree[nonfree_num++] = j;
				}
				scbw(scb, rxkring, rs);
				tmp = *rs;
				*rs = *ts;
				*ts = tmp;
				ts->len = ts->offset = 0;
				ts->fd = 0;
				ts->flags |= NS_BUF_CHANGED;
				rs->flags |= NS_BUF_CHANGED;
//skip:
				j = nm_next(j, lim_rx);
				sent++;
			} while (next != STACK_FT_NULL && --howmany);
			if (likely(next == STACK_FT_NULL))
				n++;
			bq->bq_head = next; // no NULL if howmany has run out
		}
		ft->nfds -= n;
		ft->npkts -= sent;
		memmove(ft->fds, ft->fds + n, sizeof(ft->fds[0]) * ft->nfds);
	}

	rxkring->nr_hwtail = j; // no update if !sent
	mtx_unlock(&rxkring->q_lock);

	if (sent)
		rxkring->nm_notify(rxkring, 0);
	rxkring->nkr_hwlease = rxkring->nr_hwcur;

	/* swap out packets still referred by the stack */
	for (j = 0; j < nonfree_num; j++) {
		struct netmap_slot *slot = &rxkring->ring->slot[nonfree[j]];

		if (unlikely(nm_st_extra_enqueue(rxkring, slot))) {
			/* Don't reclaim on/after this postion */
			u_long nm_i = slot - rxkring->ring->slot;
			rxkring->nkr_hwlease = nm_i;
			break;
		}
	}
runlock:
	BDG_RUNLOCK(b);
	return;
}

/* Form fdtable to be flushed */
static int
nm_st_preflush(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na;
	int k = kring->nr_hwcur;
	u_int lim_tx = kring->nkr_num_slots - 1;
	const int rhead = kring->rhead;
	int tx = 0;
	struct nm_st_fwd *ft = nm_st_get_fwd(kring);

	if (na == nm_st_na(na))
		tx = 1;
	else if (nm_st_is_host(na))
		kring->nkr_hwlease = rhead; // skip loop below
	//if (ft->npkts) {
		//nm_st_bdg_flush(kring);
	//}
	for (k = kring->nkr_hwlease; k != rhead; k = nm_next(k, lim_tx)) {
		struct netmap_slot *slot = &kring->ring->slot[k];
		struct nm_st_cb *scb;
		char *nmb = NMB(na, slot);
		int error;

		__builtin_prefetch(nmb);
		if (unlikely(slot->len == 0)) {
			continue;
		}
		if (unlikely(slot->len < VHLEN(na) + slot->offset)) {
			RD(1, "invalid data: len %u virt_hdr_len %u off %u",
				slot->len, VHLEN(na), slot->offset);
			continue;
		}
		scb = NMCB_BUF(nmb);
		scbw(scb, kring, slot);
		error = tx ? nm_os_st_send(kring, slot) :
			     nm_os_st_recv(kring, slot);
		if (unlikely(error)) {
			/* We stop processing on -EAGAIN(TX) which occurs due
			 * to misbehaviong user e.g., invalid fd.
			 */
			if (error == -EBUSY)
				k = nm_next(k, lim_tx);
			break;
		}
	}
	kring->nkr_hwlease = k; // next position to throw into the stack
	nm_st_flush(kring);
	if (ft->npkts) { // we have leftover, cannot report k
		int j;

		/* try to reclaim buffers on txring */
		for (j = kring->nr_hwcur; j != k; j = nm_next(j, lim_tx)) {
			struct netmap_slot *slot = &kring->ring->slot[j];
			struct nm_st_cb *scb;
		       
			if (unlikely(!slot->len))
				continue;
			scb = NMCB_BUF(NMB(na, slot));
			/* scb can be invalid due to new buffer swap-ed in */
			if (nm_st_cb_valid(scb) &&
			    nm_st_cb_rstate(scb) != MB_NOREF)
				break;
		}
		k = j;
	}
	return k;
}


static int
nombq_rxsync(struct netmap_kring *kring, int flags)
{
	(void)kring;
	(void)flags;
	return 0;
}

static int
nombq(struct netmap_adapter *na, struct mbuf *m)
{
	struct netmap_kring *kring;
	struct netmap_slot *hslot;
	u_int head, nm_i, lim, len = MBUF_LEN(m);

	/* host ring */
	nm_i = curcpu % nma_get_host_nrings(na, NR_RX);
	kring = NMR(na, NR_RX)[nma_get_nrings(na, NR_RX) + nm_i];
	head = kring->rhead;
	lim = kring->nkr_num_slots - 1;
	nm_i = kring->nr_hwtail;
	/* check space */
	if (unlikely(nm_i == nm_prev(kring->nr_hwcur, lim))) {
		RD(1, "kring full");
		m_freem(m);
		return EBUSY;
	} else if (unlikely(!nm_netmap_on(na))) {
		m_freem(m);
		return ENXIO;
	}
	hslot = &kring->ring->slot[nm_i];
	m_copydata(m, 0, len, (char *)NMB(na, hslot) + VHLEN(na));
	hslot->len = len;
	kring->nr_hwtail = nm_next(nm_i, lim);

	nm_i = kring->nr_hwcur;
	if (likely(nm_i != head)) {
		kring->nr_hwcur = head;
	}
	if (!stack_host_batch) {
		netmap_bwrap_intr_notify(kring, 0);
	}
	/* as if netmap_transmit + rxsync_from_host done */
	m_freem(m);
	return 0;
}

#ifdef __FreeBSD__
/* FreeBSD doesn't have protocol header offsets filled */
static inline void
mbuf_proto_headers(struct mbuf *m)
{
	uint16_t ethertype;

	ethertype = ntohs(*(uint16_t *)(m->m_data + 12));
	if (MBUF_NETWORK_OFFSET(m) > 0)
		return;
	m->m_pkthdr.l2hlen = sizeof(struct ether_header);
	m->m_pkthdr.l3hlen = sizeof(struct nm_iphdr);
}
#else
#define mbuf_proto_headers(m)
#endif /* __FreeBSD__ */

static void
csum_transmit(struct netmap_adapter *na, struct mbuf *m)
{
	if (nm_os_mbuf_has_offld(m)) {
		struct nm_iphdr *iph;
		char *th;
		uint16_t *check;

		mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)MBUF_NETWORK_HEADER(m);
		KASSERT(iph != NULL, ("NULL iph"));
		th = MBUF_TRANSPORT_HEADER(m);
		KASSERT(th != NULL, ("NULL th"));
		th = MBUF_TRANSPORT_HEADER(m);
		if (iph->protocol == IPPROTO_UDP) {
			check = &((struct nm_udphdr *)th)->check;
		} else if (likely(iph->protocol == IPPROTO_TCP)) {
			check = &((struct nm_tcphdr *)th)->check;
		} else {
			panic("bad proto %u w/ offld", iph->protocol);
		}
		/* With ethtool -K eth1 tx-checksum-ip-generic on, we
		 * see HWCSUM/IP6CSUM in dev and ip_sum PARTIAL on m.
		 */
		*check = 0;
		nm_os_csum_tcpudp_ipv4(iph, th,
			MBUF_LEN(m) - MBUF_TRANSPORT_OFFSET(m), check);
		//m->ip_summed = 0;
		//m->m_pkthdr.csum_flags = CSUM_TSO; // XXX
	}
	nombq(na, m);
}

int
nm_st_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	struct nm_st_cb *scb = NULL;
	struct netmap_slot *slot;
	char *nmb;
	int mismatch;

#ifdef linux
	/* txsync-ing TX packets are always frags */
	if (!MBUF_NONLINEAR(m)) {
		csum_transmit(na, m);
		return 0;
	}

	scb = NMCB_EXT(m, 0, NETMAP_BUF_SIZE(na));
#else
	struct mbuf *md = m;

	/* M_EXT or multiple mbufs (i.e., chain) */
	if ((m->m_flags & M_EXT)) { // not TCP case
		scb = NMCB_EXT(m, 0, NETMAP_BUF_SIZE(na));
	}
	if (!scb || !nm_st_cb_valid(scb)) { // TCP case
		if (MBUF_NONLINEAR(m) && (m->m_next->m_flags & M_EXT)) {
			scb = NMCB_EXT(m->m_next, 0, NETMAP_BUF_SIZE(na));
		}
		md = m->m_next;
	}
	if (!scb || !nm_st_cb_valid(scb)) {
		csum_transmit(na, m);
		return 0;
	}
#endif /* linux */

	if (unlikely(nm_st_cb_rstate(scb) != MB_STACK) ||
	    /* FreeBSD ARP reply recycles the request mbuf */
	    unlikely(scb_kring(scb) &&
	    scb_kring(scb)->na->na_private == na->na_private)) {
		MBUF_LINEARIZE(m); // XXX
		csum_transmit(na, m);
		return 0;
	}
	/* Valid scb, txsync-ing packet. */
	slot = scb_slot(scb);
	if (unlikely(nm_st_cb_rstate(scb) == MB_QUEUED)) {
	       	/* originated by netmap but has been queued in either extra
		 * or txring slot. The backend might drop this packet.
		 */
#ifdef linux
		struct nm_st_cb *scb2;
		int i, n = MBUF_CLUSTERS(m);

		for (i = 0; i < n; i++) {
			scb2 = NMCB_EXT(m, i, NETMAP_BUF_SIZE(na));
			nm_st_cb_wstate(scb2, MB_NOREF);
		}
#else
		/* To be done */
#endif /* linux */
		slot->len = 0; // XXX
		MBUF_LINEARIZE(m);
		csum_transmit(na, m);
		return 0;
	}

	nmb = NMB(na, slot);

	/* bring protocol headers in */
	mismatch = MBUF_HEADLEN(m) - (int)slot->offset;

	ND("MBUF_HEADLEN(m) %d MBUF_HEADLEN(nd) %d m->m_len %d"
	   "m->m_pkthdr.len %d m->m_pkthdr.l2hlen %d "
	   "m->m_pkthdr.l3hlen %d m->m_pkthdr.l4hlen %d ethtype 0x%x "
	   "slot->len %u slot->offset %u virt %u offld %d mismatch %d",
	   MBUF_HEADLEN(m), MBUF_HEADLEN(md), m->m_len, m->m_pkthdr.len,
	   m->m_pkthdr.l2hlen, m->m_pkthdr.l3hlen, m->m_pkthdr.l4hlen,
	   ntohs(*(uint16_t *)(m->m_data + 12)), slot->len, slot->offset,
	   VHLEN(na), nm_os_mbuf_has_offld(m), mismatch);

	if (!mismatch) {
		/* Length has already been validated */
		memcpy(nmb + VHLEN(na), MBUF_DATA(m), slot->offset);
	} else {
		m_copydata(m, 0, MBUF_LEN(m), nmb + VHLEN(na));
		slot->len += mismatch;
	}

	if (nm_os_mbuf_has_offld(m)) {
		struct nm_iphdr *iph;
		struct nm_tcphdr *tcph;
		uint16_t *check;
		int len, v = VHLEN(na);

		mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)(nmb + v + MBUF_NETWORK_OFFSET(m));
		tcph = (struct nm_tcphdr *)(nmb + v + MBUF_TRANSPORT_OFFSET(m));
		check = &tcph->check;
		*check = 0;
		len = slot->len - v - MBUF_TRANSPORT_OFFSET(m);
		nm_os_csum_tcpudp_ipv4(iph, tcph, len, check);
	}

	nm_st_add_fdtable(scb, scb_kring(scb));

	/* We don't know when the stack actually releases the data;
	 * it might holds reference via clone.
	 */
	nm_st_cb_wstate(scb, MB_TXREF);
#ifdef linux
	/* for FreeBSD mbuf comes from our code */
	nm_set_mbuf_data_destructor(m, &scb->ui,
			nm_os_st_mbuf_data_destructor);

#endif /* linux */
	m_freem(m);
	return 0;
}

static void
nm_st_extra_free(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = NMR(na, t)[i];
			struct netmap_ring *ring = kring->ring;
			struct nm_st_extra_pool *extra;
			uint32_t j;

			if (!kring->extra)
				continue;
			extra = kring->extra;

			j = extra->busy;
			while (j != NM_EXT_NULL) {
				struct nm_st_extra_slot *es = &extra->slots[j];
				struct nm_st_cb *scb
					= NMCB_BUF(NMB(na, &es->slot));
				nm_st_cb_set_gone(scb);
				j = es->next;
			}
			kring->extra = NULL;
			extra->num = 0;
			if (extra->slots)
				nm_os_free(extra->slots);
			nm_os_free(extra);

			/* also mark on-ring bufs */
			for (j = 0; j < kring->nkr_num_slots; j++) {
				struct nm_st_cb *scb;

				scb = NMCB_BUF(NMB(na, &ring->slot[j]));
				nm_st_cb_set_gone(scb);
			}
		}
	}
}

static int
nm_st_extra_alloc(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		/* XXX probably we don't need extra on host rings */
		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = NMR(na, t)[i];
			struct nm_st_extra_pool *pool;
			struct nm_st_extra_slot *extra_slots = NULL;
			u_int want = stack_extra, n, j, next;

			pool = nm_os_malloc(sizeof(*kring->extra));
			if (!pool)
				break;
			kring->extra = pool;

			n = netmap_extra_alloc(na, &next, want);
			if (n < want)
				D("allocated only %u bufs", n);
			kring->extra->num = n;

			if (n) {
				extra_slots = nm_os_malloc(sizeof(*extra_slots)
						* n);
				if (!extra_slots)
					break;
			}

			for (j = 0; j < n; j++) {
				struct nm_st_extra_slot *exs;
				struct netmap_slot tmp = {.buf_idx = next};

				exs = &extra_slots[j];
				exs->slot.buf_idx = next;
				exs->slot.len = 0;
				exs->prev = j == 0 ? NM_EXT_NULL : j - 1;
				exs->next = j + 1 == n ? NM_EXT_NULL : j + 1;
				next = *(uint32_t *)NMB(na, &tmp);
			}
			pool->free = 0;
			pool->free_tail = n - 1;
			pool->busy = pool->busy_tail = NM_EXT_NULL;
			pool->slots = extra_slots;
		}
		/* rollaback on error */
		if (i < netmap_real_rings(na, t)) {
			nm_st_extra_free(na);
			return ENOMEM;
		}
	}
	return 0;
}

/* Create extra buffers and mbuf pool */

static int
nm_st_mbufpool_alloc(struct netmap_adapter *na)
{
	struct netmap_kring *kring;
	int i, error = 0;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		kring = NMR(na, NR_TX)[i];
		kring->tx_pool =
			nm_os_malloc(na->num_tx_desc *
				sizeof(struct mbuf *));
		if (!kring->tx_pool) {
			D("tx_pool allocation failed");
			error = ENOMEM;
			break;
		}
		bzero(kring->tx_pool, na->num_tx_desc * sizeof(struct mbuf *));
		kring->tx_pool[0] = nm_os_malloc(sizeof(struct mbuf));
		if (!kring->tx_pool[0]) {
			error = ENOMEM;
			break;
		}
		bzero(kring->tx_pool[0], sizeof(struct mbuf));
	}
	if (error) {
		for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
			kring = NMR(na, NR_TX)[i];
			if (kring->tx_pool == NULL)
				break; // further allocation has never happened
			if (kring->tx_pool[0])
				nm_os_free(kring->tx_pool[0]);
			nm_os_free(kring->tx_pool);
			kring->tx_pool = NULL;
		}
	}
	return error;
}

static void
nm_st_mbufpool_free(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		struct netmap_kring *kring = NMR(na, NR_TX)[i];

		if (kring->tx_pool == NULL)
			continue;
		if (kring->tx_pool[0])
			nm_os_free(kring->tx_pool[0]);
		nm_os_free(kring->tx_pool);
		kring->tx_pool = NULL;
	}
}


static int
netmap_stack_bwrap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_bwrap_adapter *bna = (struct netmap_bwrap_adapter *)na;
	struct netmap_adapter *hwna = bna->hwna;
#ifdef linux
	struct netmap_hw_adapter *hw = (struct netmap_hw_adapter *)hwna;
#endif

	if (onoff) {
		int i, error;

		if (bna->up.na_bdg->bdg_active_ports > 3) {
			D("%s: stack port at this point supports only one NIC",
					na->name);
			return ENOTSUP;
		}

		/* DMA offset */
		VHLEN(na) = VHLEN(&bna->up.na_bdg->bdg_ports[0]->up);
		VHLEN(hwna) = VHLEN(na);
		if (hwna->na_flags & NAF_HOST_RINGS) {
			VHLEN(&bna->host.up) = VHLEN(hwna);
		}

		error = netmap_bwrap_reg(na, onoff);
		if (error)
			return error;

		if (nm_st_extra_alloc(na)) {
			D("extra_alloc failed for slave");
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}
		if (nm_st_mbufpool_alloc(na)) {
			D("mbufpool_alloc failed for slave");
			nm_st_extra_free(na);
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}

		/* na->if_transmit already has backup */
#ifdef linux
		hw->nm_ndo.ndo_start_xmit = linux_st_start_xmit;
		/* re-overwrite */
		hwna->ifp->netdev_ops = &hw->nm_ndo;
#elif defined (__FreeBSD__)
		hwna->ifp->if_transmit = nm_st_transmit;
#endif /* linux */

		/* set void callback on host rings */
		for (i = nma_get_nrings(hwna, NR_RX);
		     i < netmap_real_rings(hwna, NR_RX); i++) {
			NMR(hwna, NR_RX)[i]->nm_sync = nombq_rxsync;
		}
	} else {
#ifdef linux
		/* restore default start_xmit for future register */
		((struct netmap_hw_adapter *)hwna)->nm_ndo.ndo_start_xmit =
			linux_netmap_start_xmit;
#else
		hwna->ifp->if_transmit = hwna->if_transmit;
#endif
		nm_st_mbufpool_free(na);
		nm_st_extra_free(na);
		return netmap_bwrap_reg(na, onoff);
	}
	return 0;
}


static int
netmap_stack_bwrap_intr_notify(struct netmap_kring *kring, int flags) {
	struct netmap_adapter *hwna = kring->na, *vpna, *mna;
	enum txrx t = kring->tx ? NR_TX : NR_RX;

	vpna = (struct netmap_adapter *)hwna->na_private;
	if (unlikely(!vpna))
		return NM_IRQ_COMPLETED;

	/* just wakeup the client on the master */
	mna = nm_st_na(vpna);
	if (likely(mna)) {
		//u_int me = kring - NMR(hwna, t), last;
		u_int me = kring->ring_id, last;
		struct netmap_kring *mk;

		if (stack_no_runtocomp)
			return netmap_bwrap_intr_notify(kring, flags);
		last = nma_get_nrings(mna, t);
		mk = NMR(mna, t)[last > me ? me : me % last];
		mk->nm_notify(mk, 0);
	}
	return NM_IRQ_COMPLETED;
}

/*
 * When stack dies first, it simply restores all the socket
 * information on dtor().
 * Otherwise our sk->sk_destructor will cleanup stack states
 */
static void
nm_st_unregister_socket(struct nm_st_sk_adapter *ska)
{
	NM_SOCK_T *sk = ska->sk;
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)ska->na;

	if (ska->fd >= sna->sk_adapters_max) {
		D("WARNING: non-registered or invalid fd %d", ska->fd);
	} else {
		sna->sk_adapters[ska->fd] = NULL;
		NM_SOCK_LOCK(sk);
		SOCKBUF_LOCK(&sk->so_rcv);
		RESTORE_DATA_READY(sk, ska);
		RESTORE_DESTRUCTOR(sk, ska);
		nm_st_wsk(NULL, sk);
		SOCKBUF_UNLOCK(&sk->so_rcv);
		NM_SOCK_UNLOCK(sk);
	}
	nm_os_free(ska);
}

static void
nm_st_sk_destruct(NM_SOCK_T *sk)
{
	struct nm_st_sk_adapter *ska;
	struct netmap_stack_adapter *sna;

	ska = nm_st_sk(sk);
	ND("socket died first ska %p save_destruct %p", ska, ska ? ska->save_sk_destruct : NULL);
	if (ska->save_sk_destruct) {
		ska->save_sk_destruct(sk);
	}
	sna = (struct netmap_stack_adapter *)ska->na;
	/* nm_os_st_data_ready() runs bh_lock_sock_nested() */
	nm_st_unregister_socket(ska);
}

/* Under NMG_LOCK() */
static void
nm_st_bdg_dtor(const struct netmap_vp_adapter *vpna)
{
	struct netmap_stack_adapter *sna;
	int i;

	if (&vpna->up != nm_st_na(&vpna->up))
		return;

	//sna = (struct netmap_stack_adapter *)vpna;
	sna = (struct netmap_stack_adapter *)(void *)(uintptr_t)vpna;
	for (i = 0; i < sna->sk_adapters_max; i++) {
		struct nm_st_sk_adapter *ska = sna->sk_adapters[i];
		if (ska)
			nm_st_unregister_socket(ska);
	}
	nm_os_free(sna->sk_adapters);
	sna->sk_adapters_max = 0;
}

static int
nm_st_register_fd(struct netmap_adapter *na, int fd)
{
	NM_SOCK_T *sk;
	void *file;
	struct nm_st_sk_adapter *ska;
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;
	int on = 1;
	struct sockopt sopt;

	NMG_LOCK();
	/* first check table size */
	if (fd >= sna->sk_adapters_max) {
		struct nm_st_sk_adapter **old = sna->sk_adapters, **new;
		int oldsize = sna->sk_adapters_max;
		int newsize = oldsize ? oldsize * 2 : DEFAULT_SK_ADAPTERS;

		new = nm_os_malloc(sizeof(new) * newsize);
		if (!new) {
			D("failed to extend fd->sk_adapter table");
			NMG_UNLOCK();
			return ENOMEM;
		}
		if (old) {
			memcpy(new, old, sizeof(old) * oldsize);
			nm_os_free(old);
		}
		sna->sk_adapters = new;
		sna->sk_adapters_max = newsize;
	}
	NMG_UNLOCK();

	sk = nm_os_sock_fget(fd, &file);
	if (!sk)
		return EINVAL;
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = TCP_NODELAY;
	sopt.sopt_val = &on;
	sopt.sopt_valsize = sizeof(on);
	if (sosetopt(sk, &sopt) < 0) {
		RD(1, "WARNING: failed sosetopt(TCP_NODELAY)");
	}
	NM_SOCK_LOCK(sk); // kernel_setsockopt() above internally takes this lock
	/* This validation under lock is needed to handle
	 * simultaneous accept/config
	 */
	if (nm_st_sk(sk)) {
		NM_SOCK_UNLOCK(sk);
		nm_os_sock_fput(sk, file);
		D("ska already allocated");
		return EBUSY;
	}
	ska = nm_os_malloc(sizeof(*ska));
	if (!ska) {
		NM_SOCK_UNLOCK(sk);
		nm_os_sock_fput(sk, file);
		return ENOMEM;
	}
	SOCKBUF_LOCK(&sk->so_rcv);
	SAVE_DATA_READY(sk, ska);
	SAVE_DESTRUCTOR(sk, ska);
	ska->na = na;
	ska->sk = sk;
	ska->fd = fd;
	SET_DATA_READY(sk, nm_os_st_data_ready);
	SET_DESTRUCTOR(sk, nm_st_sk_destruct);
	nm_st_wsk(ska, sk);
	sna->sk_adapters[fd] = ska;
	SOCKBUF_UNLOCK(&sk->so_rcv);
	nm_os_st_sb_drain(na, sk);
	NM_SOCK_UNLOCK(sk);
	nm_os_sock_fput(sk, file);
	return 0;
}

static int
nm_st_bdg_config(struct nm_ifreq *ifr)
{
	struct netmap_adapter *na;
	int fd = *(int *)ifr->data;
	struct nmreq_header hdr;
	int error;

	strncpy(hdr.nr_name, ifr->nifr_name, sizeof(hdr.nr_name));
	NMG_LOCK();
	error = netmap_get_bdg_na(&hdr, &na, NULL, 0, NULL);
	NMG_UNLOCK();
	if (!error && na != NULL) {
		error = nm_st_register_fd(na, fd);
	}
	if (na) {
		NMG_LOCK();
		netmap_adapter_put(na);
		NMG_UNLOCK();
	}
	return error;
}

static int
netmap_stack_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_vp_adapter *vpna = (struct netmap_vp_adapter *)na;

	if (onoff) {
		int err;

		if (na->active_fds > 0) {
			return 0;
		}
		err = nm_st_extra_alloc(na);
		if (err) {
			return err;
		}
		VHLEN(na) = sizeof(struct nm_st_cb);
	}
	if (!onoff) {
		struct nm_bridge *b = vpna->na_bdg;

		int i;

		for_bdg_ports(i, b) {
			struct netmap_vp_adapter *slave;
			struct nmreq_header hdr;
			struct nmreq_port_hdr req;

			if (i == 0)
				continue;
			slave = b->bdg_ports[i];
			bzero(&hdr, sizeof(hdr));
			strncpy(hdr.nr_name, slave->up.name,
					sizeof(hdr.nr_name));
			hdr.nr_reqtype = NETMAP_REQ_BDG_DETACH;
			hdr.nr_version = NETMAP_API;
			hdr.nr_body = (uintptr_t)&req;
			nm_bdg_ctl_detach_locked(&hdr, NULL);
		}

		nm_st_extra_free(na);
	}
	return netmap_vp_reg(na, onoff);
}

static int
netmap_stack_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	u_int const head = kring->rhead;
	u_int done;

	if (unlikely(((struct netmap_vp_adapter *)na)->na_bdg == NULL)) {
		done = head;
		return 0;
	}
	done = nm_st_preflush(kring);

	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, kring->nkr_num_slots - 1);
	return 0;
}

static int
netmap_stack_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_stack_adapter *sna =
		(struct netmap_stack_adapter *)kring->na;
	struct nm_bridge *b = sna->up.na_bdg;
	int i, err;
	register_t	intr;

	/* TODO scan only necessary ports */
	err = netmap_vp_rxsync(kring, flags); // reclaim buffers released
	if (err)
		return err;
	if (stack_no_runtocomp)
		return 0;

	intr = intr_disable(); // emulate software interrupt context

	for_bdg_ports(i, b) {
		struct netmap_vp_adapter *vpna = b->bdg_ports[i];
		struct netmap_adapter *na = &vpna->up;
		struct netmap_adapter *hwna;
		u_int first, stride, last, i;
	
		if (netmap_bdg_idx(vpna) == netmap_bdg_idx(&sna->up))
			continue;
		else if (nm_st_is_host(na))
			continue;

		/* We assume the same number of hwna with vpna
		 * (see netmap_bwrap_attach()) */
		hwna = ((struct netmap_bwrap_adapter *)vpna)->hwna;

		/* hw ring(s) to scan */
		first = kring->na->num_rx_rings > 1 ? kring->ring_id : 0;
		stride = kring->na->num_rx_rings;
		last = na->num_rx_rings;
		for (i = first; i < last; i += stride) {
			struct netmap_kring *hwk, *bk, *hk;
		       
			hwk = NMR(hwna, NR_RX)[i];
			bk = NMR(na, NR_TX)[i];
			hk = NMR(hwna, NR_RX)[last +
				(i % nma_get_host_nrings(hwna, NR_RX))];
			/*
			 * bdg_flush has been put off because we do not want
			 * it to run in bdg_config context with bridge wlock
			 * held. Thus, if we have some packets originated by
			 * this NIC ring, just drain it without NIC's rxsync.
			 */
			if (nm_st_get_fwd(bk)->npkts > 0) {
				nm_st_flush(bk);
			} else {
				netmap_bwrap_intr_notify(hwk, 0);
				if (stack_host_batch) {
					netmap_bwrap_intr_notify(hk, 0);
				}
			}
		}
	}
	intr_restore(intr);
	return netmap_vp_rxsync(kring, flags);
}

/* Holds the default callbacks */
struct netmap_bdg_ops default_stack_ops =
			{NULL, nm_st_bdg_config, nm_st_bdg_dtor};
struct nm_bdg_args stack_args = {
	.name = NM_STACK_NAME,
	.vp_size = sizeof(struct netmap_stack_adapter),
	.bwrap_size = sizeof(struct netmap_bwrap_adapter),
	.reg = netmap_stack_reg,
	.txsync = netmap_stack_txsync,
	.rxsync = netmap_stack_rxsync,
	.bwrap_reg = netmap_stack_bwrap_reg,
	.bwrap_txsync = netmap_stack_txsync,
	.bwrap_notify = netmap_bwrap_notify,
	.bwrap_intr_notify = netmap_stack_bwrap_intr_notify,
	.bdg_ops = &default_stack_ops
};

int
netmap_get_stack_na(struct nmreq_header *hdr, struct netmap_adapter **na,
		struct netmap_mem_d *nmd, int create)
{
	int ret = netmap_get_bdg_na(hdr, na, nmd, create, &stack_args);

	/* XXX Use proper interface once we have it */
	if (ret == 0 && *na) {
		struct netmap_vp_adapter *vpna =
			(struct netmap_vp_adapter *)(*na);
		VHLEN(&vpna->up) = sizeof(struct nm_st_cb);
		if (nm_is_bwrap(*na)) {
			struct netmap_bwrap_adapter *bna =
				(struct netmap_bwrap_adapter *)(*na);
			VHLEN(bna->hwna) = VHLEN(&vpna->up);
			if (bna->hwna->na_flags & NAF_HOST_RINGS) {
				VHLEN(&bna->host.up) = VHLEN(&vpna->up);
			}
		}
	}
	return ret;
}
#endif /* WITH_STACK */
