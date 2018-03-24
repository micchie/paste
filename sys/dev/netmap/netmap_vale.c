/*
 * Copyright (C) 2013-2016 Universita` di Pisa
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


/*
 * This module implements the VALE switch for netmap

--- VALE SWITCH ---

NMG_LOCK() serializes all modifications to switches and ports.
A switch cannot be deleted until all ports are gone.

For each switch, an SX lock (RWlock on linux) protects
deletion of ports. When configuring or deleting a new port, the
lock is acquired in exclusive mode (after holding NMG_LOCK).
When forwarding, the lock is acquired in shared mode (without NMG_LOCK).
The lock is held throughout the entire forwarding cycle,
during which the thread may incur in a page fault.
Hence it is important that sleepable shared locks are used.

On the rx ring, the per-port lock is grabbed initially to reserve
a number of slot in the ring, then the lock is released,
packets are copied from source to destination, and then
the lock is acquired again and the receive ring is updated.
(A similar thing is done on the tx ring for NIC and host stack
ports attached to the switch)

 */

/*
 * OS-specific code that is used only within this file.
 * Other OS-specific code that must be accessed by drivers
 * is present in netmap_kern.h
 */

#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */
__FBSDID("$FreeBSD: head/sys/dev/netmap/netmap.c 257176 2013-10-26 17:58:36Z glebius $");

#include <sys/types.h>
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
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/endian.h>
#include <sys/refcount.h>
#include <sys/smp.h>


#define BDG_RWLOCK_T		struct rwlock // struct rwlock

#define	BDG_RWINIT(b)		\
	rw_init_flags(&(b)->bdg_lock, "bdg lock", RW_NOWITNESS)
#define BDG_WLOCK(b)		rw_wlock(&(b)->bdg_lock)
#define BDG_WUNLOCK(b)		rw_wunlock(&(b)->bdg_lock)
#define BDG_RLOCK(b)		rw_rlock(&(b)->bdg_lock)
#define BDG_RTRYLOCK(b)		rw_try_rlock(&(b)->bdg_lock)
#define BDG_RUNLOCK(b)		rw_runlock(&(b)->bdg_lock)
#define BDG_RWDESTROY(b)	rw_destroy(&(b)->bdg_lock)


#elif defined(linux)

#include "bsd_glue.h"

#elif defined(__APPLE__)

#warning OSX support is only partial
#include "osx_glue.h"

#elif defined(_WIN32)
#include "win_glue.h"

#else

#error	Unsupported platform

#endif /* unsupported */

/*
 * common headers
 */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_bdg.h>

#ifdef WITH_VALE

/*
 * bridge_batch is set via sysctl to the max batch size to be
 * used in the bridge. The actual value may be larger as the
 * last packet in the block may overflow the size.
 */
static int bridge_batch = NM_BDG_BATCH; /* bridge batch size */
SYSBEGIN(vars_vale);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, bridge_batch, CTLFLAG_RW, &bridge_batch, 0,
		"Max batch size to be used in the bridge");
SYSEND;

/*
 * this is a slightly optimized copy routine which rounds
 * to multiple of 64 bytes and is often faster than dealing
 * with other odd sizes. We assume there is enough room
 * in the source and destination buffers.
 *
 * XXX only for multiples of 64 bytes, non overlapped.
 */
static inline void
pkt_copy(void *_src, void *_dst, int l)
{
	uint64_t *src = _src;
	uint64_t *dst = _dst;
	if (unlikely(l >= 1024)) {
		memcpy(dst, src, l);
		return;
	}
	for (; likely(l > 0); l-=64) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}
}

static int
nm_bdg_flush(struct nm_bdg_fwd *ft, u_int n,
	struct netmap_vp_adapter *na, u_int ring_nr);


/*
 * main dispatch routine for the bridge.
 * Grab packets from a kring, move them into the ft structure
 * associated to the tx (input) port. Max one instance per port,
 * filtered on input (ioctl, poll or XXX).
 * Returns the next position in the ring.
 */
static int
nm_bdg_preflush(struct netmap_kring *kring, u_int end)
{
	struct netmap_vp_adapter *na =
		(struct netmap_vp_adapter*)kring->na;
	struct netmap_ring *ring = kring->ring;
	struct nm_bdg_fwd *ft;
	u_int ring_nr = kring->ring_id;
	u_int j = kring->nr_hwcur, lim = kring->nkr_num_slots - 1;
	u_int ft_i = 0;	/* start from 0 */
	u_int frags = 1; /* how many frags ? */
	struct nm_bridge *b = na->na_bdg;

	/* To protect against modifications to the bridge we acquire a
	 * shared lock, waiting if we can sleep (if the source port is
	 * attached to a user process) or with a trylock otherwise (NICs).
	 */
	ND("wait rlock for %d packets", ((j > end ? lim+1 : 0) + end) - j);
	if (na->up.na_flags & NAF_BDG_MAYSLEEP)
		BDG_RLOCK(b);
	else if (!BDG_RTRYLOCK(b))
		return j;
	ND(5, "rlock acquired for %d packets", ((j > end ? lim+1 : 0) + end) - j);
	ft = kring->nkr_ft;

	for (; likely(j != end); j = nm_next(j, lim)) {
		struct netmap_slot *slot = &ring->slot[j];
		char *buf;

		ft[ft_i].ft_len = slot->len;
		ft[ft_i].ft_flags = slot->flags;
		ft[ft_i].ft_offset = 0;

		ND("flags is 0x%x", slot->flags);
		/* we do not use the buf changed flag, but we still need to reset it */
		slot->flags &= ~NS_BUF_CHANGED;

		/* this slot goes into a list so initialize the link field */
		ft[ft_i].ft_next = NM_FT_NULL;
		buf = ft[ft_i].ft_buf = (slot->flags & NS_INDIRECT) ?
			(void *)(uintptr_t)slot->ptr : NMB(&na->up, slot);
		if (unlikely(buf == NULL)) {
			RD(5, "NULL %s buffer pointer from %s slot %d len %d",
				(slot->flags & NS_INDIRECT) ? "INDIRECT" : "DIRECT",
				kring->name, j, ft[ft_i].ft_len);
			buf = ft[ft_i].ft_buf = NETMAP_BUF_BASE(&na->up);
			ft[ft_i].ft_len = 0;
			ft[ft_i].ft_flags = 0;
		}
		__builtin_prefetch(buf);
		++ft_i;
		if (slot->flags & NS_MOREFRAG) {
			frags++;
			continue;
		}
		if (unlikely(netmap_verbose && frags > 1))
			RD(5, "%d frags at %d", frags, ft_i - frags);
		ft[ft_i - frags].ft_frags = frags;
		frags = 1;
		if (unlikely((int)ft_i >= bridge_batch))
			ft_i = nm_bdg_flush(ft, ft_i, na, ring_nr);
	}
	if (frags > 1) {
		/* Here ft_i > 0, ft[ft_i-1].flags has NS_MOREFRAG, and we
		 * have to fix frags count. */
		frags--;
		ft[ft_i - 1].ft_flags &= ~NS_MOREFRAG;
		ft[ft_i - frags].ft_frags = frags;
		D("Truncate incomplete fragment at %d (%d frags)", ft_i, frags);
	}
	if (ft_i)
		ft_i = nm_bdg_flush(ft, ft_i, na, ring_nr);
	BDG_RUNLOCK(b);
	return j;
}

/* ----- FreeBSD if_bridge hash function ------- */

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 *
 * http://www.burtleburtle.net/bob/hash/spooky.html
 */
#define mix(a, b, c)                                                    \
do {                                                                    \
        a -= b; a -= c; a ^= (c >> 13);                                 \
        b -= c; b -= a; b ^= (a << 8);                                  \
        c -= a; c -= b; c ^= (b >> 13);                                 \
        a -= b; a -= c; a ^= (c >> 12);                                 \
        b -= c; b -= a; b ^= (a << 16);                                 \
        c -= a; c -= b; c ^= (b >> 5);                                  \
        a -= b; a -= c; a ^= (c >> 3);                                  \
        b -= c; b -= a; b ^= (a << 10);                                 \
        c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static __inline uint32_t
nm_bridge_rthash(const uint8_t *addr)
{
        uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key

        b += addr[5] << 8;
        b += addr[4];
        a += addr[3] << 24;
        a += addr[2] << 16;
        a += addr[1] << 8;
        a += addr[0];

        mix(a, b, c);
#define BRIDGE_RTHASH_MASK	(NM_BDG_HASH-1)
        return (c & BRIDGE_RTHASH_MASK);
}

#undef mix

/*
 * Lookup function for a learning bridge.
 * Update the hash table with the source address,
 * and then returns the destination port index, and the
 * ring in *dst_ring (at the moment, always use ring 0)
 */
uint32_t
netmap_bdg_learning(struct nm_bdg_fwd *ft, uint8_t *dst_ring,
		struct netmap_vp_adapter *na, void *private_data)
{
	uint8_t *buf = ((uint8_t *)ft->ft_buf) + ft->ft_offset;
	u_int buf_len = ft->ft_len - ft->ft_offset;
	struct nm_hash_ent *ht = private_data;
	uint32_t sh, dh;
	u_int dst, mysrc = na->bdg_port;
	uint64_t smac, dmac;
	uint8_t indbuf[12];

	if (buf_len < 14) {
		return NM_BDG_NOPORT;
	}

	if (ft->ft_flags & NS_INDIRECT) {
		if (copyin(buf, indbuf, sizeof(indbuf))) {
			return NM_BDG_NOPORT;
		}
		buf = indbuf;
	}

	dmac = le64toh(*(uint64_t *)(buf)) & 0xffffffffffff;
	smac = le64toh(*(uint64_t *)(buf + 4));
	smac >>= 16;

	/*
	 * The hash is somewhat expensive, there might be some
	 * worthwhile optimizations here.
	 */
	if (((buf[6] & 1) == 0) && (na->last_smac != smac)) { /* valid src */
		uint8_t *s = buf+6;
		sh = nm_bridge_rthash(s); /* hash of source */
		/* update source port forwarding entry */
		na->last_smac = ht[sh].mac = smac;	/* XXX expire ? */
		ht[sh].ports = mysrc;
		if (netmap_verbose)
		    D("src %02x:%02x:%02x:%02x:%02x:%02x on port %d",
			s[0], s[1], s[2], s[3], s[4], s[5], mysrc);
	}
	dst = NM_BDG_BROADCAST;
	if ((buf[0] & 1) == 0) { /* unicast */
		dh = nm_bridge_rthash(buf); /* hash of dst */
		if (ht[dh].mac == dmac) {	/* found dst */
			dst = ht[dh].ports;
		}
	}
	return dst;
}

/*
 * Available space in the ring. Only used in VALE code
 * and only with is_rx = 1
 */
static inline uint32_t
nm_kr_space(struct netmap_kring *k, int is_rx)
{
	int space;

	if (is_rx) {
		int busy = k->nkr_hwlease - k->nr_hwcur;
		if (busy < 0)
			busy += k->nkr_num_slots;
		space = k->nkr_num_slots - 1 - busy;
	} else {
		/* XXX never used in this branch */
		space = k->nr_hwtail - k->nkr_hwlease;
		if (space < 0)
			space += k->nkr_num_slots;
	}
#if 0
	// sanity check
	if (k->nkr_hwlease >= k->nkr_num_slots ||
		k->nr_hwcur >= k->nkr_num_slots ||
		k->nr_tail >= k->nkr_num_slots ||
		busy < 0 ||
		busy >= k->nkr_num_slots) {
		D("invalid kring, cur %d tail %d lease %d lease_idx %d lim %d",			k->nr_hwcur, k->nr_hwtail, k->nkr_hwlease,
			k->nkr_lease_idx, k->nkr_num_slots);
	}
#endif
	return space;
}




/* make a lease on the kring for N positions. return the
 * lease index
 * XXX only used in VALE code and with is_rx = 1
 */
static inline uint32_t
nm_kr_lease(struct netmap_kring *k, u_int n, int is_rx)
{
	uint32_t lim = k->nkr_num_slots - 1;
	uint32_t lease_idx = k->nkr_lease_idx;

	k->nkr_leases[lease_idx] = NR_NOSLOT;
	k->nkr_lease_idx = nm_next(lease_idx, lim);

	if (n > nm_kr_space(k, is_rx)) {
		D("invalid request for %d slots", n);
		panic("x");
	}
	/* XXX verify that there are n slots */
	k->nkr_hwlease += n;
	if (k->nkr_hwlease > lim)
		k->nkr_hwlease -= lim + 1;

	if (k->nkr_hwlease >= k->nkr_num_slots ||
		k->nr_hwcur >= k->nkr_num_slots ||
		k->nr_hwtail >= k->nkr_num_slots ||
		k->nkr_lease_idx >= k->nkr_num_slots) {
		D("invalid kring %s, cur %d tail %d lease %d lease_idx %d lim %d",
			k->na->name,
			k->nr_hwcur, k->nr_hwtail, k->nkr_hwlease,
			k->nkr_lease_idx, k->nkr_num_slots);
	}
	return lease_idx;
}

/*
 *
 * This flush routine supports only unicast and broadcast but a large
 * number of ports, and lets us replace the learn and dispatch functions.
 */
int
nm_bdg_flush(struct nm_bdg_fwd *ft, u_int n, struct netmap_vp_adapter *na,
		u_int ring_nr)
{
	struct nm_bdg_q *dst_ents, *brddst;
	uint16_t num_dsts = 0, *dsts;
	struct nm_bridge *b = na->na_bdg;
	u_int i, me = na->bdg_port;

	/*
	 * The work area (pointed by ft) is followed by an array of
	 * pointers to queues , dst_ents; there are NM_BDG_MAXRINGS
	 * queues per port plus one for the broadcast traffic.
	 * Then we have an array of destination indexes.
	 */
	dst_ents = (struct nm_bdg_q *)(ft + NM_BDG_BATCH_MAX);
	dsts = (uint16_t *)(dst_ents + NM_BDG_MAXPORTS * NM_BDG_MAXRINGS + 1);

	/* first pass: find a destination for each packet in the batch */
	for (i = 0; likely(i < n); i += ft[i].ft_frags) {
		uint8_t dst_ring = ring_nr; /* default, same ring as origin */
		uint16_t dst_port, d_i;
		struct nm_bdg_q *d;
		struct nm_bdg_fwd *start_ft = NULL;

		ND("slot %d frags %d", i, ft[i].ft_frags);

		if (na->up.virt_hdr_len < ft[i].ft_len) {
			ft[i].ft_offset = na->up.virt_hdr_len;
			start_ft = &ft[i];
		} else if (na->up.virt_hdr_len == ft[i].ft_len && ft[i].ft_flags & NS_MOREFRAG) {
			ft[i].ft_offset = ft[i].ft_len;
			start_ft = &ft[i+1];
		} else {
			/* Drop the packet if the virtio-net header is not into the first
			 * fragment nor at the very beginning of the second.
			 */
			continue;
		}
		dst_port = b->bdg_ops->lookup(start_ft, &dst_ring, na, b->private_data);
		if (netmap_verbose > 255)
			RD(5, "slot %d port %d -> %d", i, me, dst_port);
		if (dst_port >= NM_BDG_NOPORT)
			continue; /* this packet is identified to be dropped */
		else if (dst_port == NM_BDG_BROADCAST)
			dst_ring = 0; /* broadcasts always go to ring 0 */
		else if (unlikely(dst_port == me ||
		    !b->bdg_ports[dst_port]))
			continue;

		/* get a position in the scratch pad */
		d_i = dst_port * NM_BDG_MAXRINGS + dst_ring;
		d = dst_ents + d_i;

		/* append the first fragment to the list */
		if (d->bq_head == NM_FT_NULL) { /* new destination */
			d->bq_head = d->bq_tail = i;
			/* remember this position to be scanned later */
			if (dst_port != NM_BDG_BROADCAST)
				dsts[num_dsts++] = d_i;
		} else {
			ft[d->bq_tail].ft_next = i;
			d->bq_tail = i;
		}
		d->bq_len += ft[i].ft_frags;
	}

	/*
	 * Broadcast traffic goes to ring 0 on all destinations.
	 * So we need to add these rings to the list of ports to scan.
	 * XXX at the moment we scan all NM_BDG_MAXPORTS ports, which is
	 * expensive. We should keep a compact list of active destinations
	 * so we could shorten this loop.
	 */
	brddst = dst_ents + NM_BDG_BROADCAST * NM_BDG_MAXRINGS;
	if (brddst->bq_head != NM_FT_NULL) {
		u_int j;
		for (j = 0; likely(j < b->bdg_active_ports); j++) {
			uint16_t d_i;
			i = b->bdg_port_index[j];
			if (unlikely(i == me))
				continue;
			d_i = i * NM_BDG_MAXRINGS;
			if (dst_ents[d_i].bq_head == NM_FT_NULL)
				dsts[num_dsts++] = d_i;
		}
	}

	ND(5, "pass 1 done %d pkts %d dsts", n, num_dsts);
	/* second pass: scan destinations */
	for (i = 0; i < num_dsts; i++) {
		struct netmap_vp_adapter *dst_na;
		struct netmap_kring *kring;
		struct netmap_ring *ring;
		u_int dst_nr, lim, j, d_i, next, brd_next;
		u_int needed, howmany;
		int retry = netmap_txsync_retry;
		struct nm_bdg_q *d;
		uint32_t my_start = 0, lease_idx = 0;
		int nrings;
		int virt_hdr_mismatch = 0;

		d_i = dsts[i];
		ND("second pass %d port %d", i, d_i);
		d = dst_ents + d_i;
		// XXX fix the division
		dst_na = b->bdg_ports[d_i/NM_BDG_MAXRINGS];
		/* protect from the lookup function returning an inactive
		 * destination port
		 */
		if (unlikely(dst_na == NULL))
			goto cleanup;
		if (dst_na->up.na_flags & NAF_SW_ONLY)
			goto cleanup;
		/*
		 * The interface may be in !netmap mode in two cases:
		 * - when na is attached but not activated yet;
		 * - when na is being deactivated but is still attached.
		 */
		if (unlikely(!nm_netmap_on(&dst_na->up))) {
			ND("not in netmap mode!");
			goto cleanup;
		}

		/* there is at least one either unicast or broadcast packet */
		brd_next = brddst->bq_head;
		next = d->bq_head;
		/* we need to reserve this many slots. If fewer are
		 * available, some packets will be dropped.
		 * Packets may have multiple fragments, so we may not use
		 * there is a chance that we may not use all of the slots
		 * we have claimed, so we will need to handle the leftover
		 * ones when we regain the lock.
		 */
		needed = d->bq_len + brddst->bq_len;

		if (unlikely(dst_na->up.virt_hdr_len != na->up.virt_hdr_len)) {
			if (netmap_verbose) {
				RD(3, "virt_hdr_mismatch, src %d dst %d", na->up.virt_hdr_len,
						dst_na->up.virt_hdr_len);
			}
			/* There is a virtio-net header/offloadings mismatch between
			 * source and destination. The slower mismatch datapath will
			 * be used to cope with all the mismatches.
			 */
			virt_hdr_mismatch = 1;
			if (dst_na->mfs < na->mfs) {
				/* We may need to do segmentation offloadings, and so
				 * we may need a number of destination slots greater
				 * than the number of input slots ('needed').
				 * We look for the smallest integer 'x' which satisfies:
				 *	needed * na->mfs + x * H <= x * na->mfs
				 * where 'H' is the length of the longest header that may
				 * be replicated in the segmentation process (e.g. for
				 * TCPv4 we must account for ethernet header, IP header
				 * and TCPv4 header).
				 */
				KASSERT(dst_na->mfs > 0, ("vpna->mfs is 0"));
				needed = (needed * na->mfs) /
						(dst_na->mfs - WORST_CASE_GSO_HEADER) + 1;
				ND(3, "srcmtu=%u, dstmtu=%u, x=%u", na->mfs, dst_na->mfs, needed);
			}
		}

		ND(5, "pass 2 dst %d is %x %s",
			i, d_i, is_vp ? "virtual" : "nic/host");
		dst_nr = d_i & (NM_BDG_MAXRINGS-1);
		nrings = dst_na->up.num_rx_rings;
		if (dst_nr >= nrings)
			dst_nr = dst_nr % nrings;
		kring = dst_na->up.rx_rings[dst_nr];
		ring = kring->ring;
		/* the destination ring may have not been opened for RX */
		if (unlikely(ring == NULL || kring->nr_mode != NKR_NETMAP_ON))
			goto cleanup;
		lim = kring->nkr_num_slots - 1;

retry:

		if (dst_na->retry && retry) {
			/* try to get some free slot from the previous run */
			kring->nm_notify(kring, 0);
			/* actually useful only for bwraps, since there
			 * the notify will trigger a txsync on the hwna. VALE ports
			 * have dst_na->retry == 0
			 */
		}
		/* reserve the buffers in the queue and an entry
		 * to report completion, and drop lock.
		 * XXX this might become a helper function.
		 */
		mtx_lock(&kring->q_lock);
		if (kring->nkr_stopped) {
			mtx_unlock(&kring->q_lock);
			goto cleanup;
		}
		my_start = j = kring->nkr_hwlease;
		howmany = nm_kr_space(kring, 1);
		if (needed < howmany)
			howmany = needed;
		lease_idx = nm_kr_lease(kring, howmany, 1);
		mtx_unlock(&kring->q_lock);

		/* only retry if we need more than available slots */
		if (retry && needed <= howmany)
			retry = 0;

		/* copy to the destination queue */
		while (howmany > 0) {
			struct netmap_slot *slot;
			struct nm_bdg_fwd *ft_p, *ft_end;
			u_int cnt;

			/* find the queue from which we pick next packet.
			 * NM_FT_NULL is always higher than valid indexes
			 * so we never dereference it if the other list
			 * has packets (and if both are empty we never
			 * get here).
			 */
			if (next < brd_next) {
				ft_p = ft + next;
				next = ft_p->ft_next;
			} else { /* insert broadcast */
				ft_p = ft + brd_next;
				brd_next = ft_p->ft_next;
			}
			cnt = ft_p->ft_frags; // cnt > 0
			if (unlikely(cnt > howmany))
			    break; /* no more space */
			if (netmap_verbose && cnt > 1)
				RD(5, "rx %d frags to %d", cnt, j);
			ft_end = ft_p + cnt;
			if (unlikely(virt_hdr_mismatch)) {
				bdg_mismatch_datapath(na, dst_na, ft_p, ring, &j, lim, &howmany);
			} else {
				howmany -= cnt;
				do {
					char *dst, *src = ft_p->ft_buf;
					size_t copy_len = ft_p->ft_len, dst_len = copy_len;

					slot = &ring->slot[j];
					dst = NMB(&dst_na->up, slot);

					ND("send [%d] %d(%d) bytes at %s:%d",
							i, (int)copy_len, (int)dst_len,
							NM_IFPNAME(dst_ifp), j);
					/* round to a multiple of 64 */
					copy_len = (copy_len + 63) & ~63;

					if (unlikely(copy_len > NETMAP_BUF_SIZE(&dst_na->up) ||
						     copy_len > NETMAP_BUF_SIZE(&na->up))) {
						RD(5, "invalid len %d, down to 64", (int)copy_len);
						copy_len = dst_len = 64; // XXX
					}
					if (ft_p->ft_flags & NS_INDIRECT) {
						if (copyin(src, dst, copy_len)) {
							// invalid user pointer, pretend len is 0
							dst_len = 0;
						}
					} else {
						//memcpy(dst, src, copy_len);
						pkt_copy(src, dst, (int)copy_len);
					}
					slot->len = dst_len;
					slot->flags = (cnt << 8)| NS_MOREFRAG;
					j = nm_next(j, lim);
					needed--;
					ft_p++;
				} while (ft_p != ft_end);
				slot->flags = (cnt << 8); /* clear flag on last entry */
			}
			/* are we done ? */
			if (next == NM_FT_NULL && brd_next == NM_FT_NULL)
				break;
		}
		{
		    /* current position */
		    uint32_t *p = kring->nkr_leases; /* shorthand */
		    uint32_t update_pos;
		    int still_locked = 1;

		    mtx_lock(&kring->q_lock);
		    if (unlikely(howmany > 0)) {
			/* not used all bufs. If i am the last one
			 * i can recover the slots, otherwise must
			 * fill them with 0 to mark empty packets.
			 */
			ND("leftover %d bufs", howmany);
			if (nm_next(lease_idx, lim) == kring->nkr_lease_idx) {
			    /* yes i am the last one */
			    ND("roll back nkr_hwlease to %d", j);
			    kring->nkr_hwlease = j;
			} else {
			    while (howmany-- > 0) {
				ring->slot[j].len = 0;
				ring->slot[j].flags = 0;
				j = nm_next(j, lim);
			    }
			}
		    }
		    p[lease_idx] = j; /* report I am done */

		    update_pos = kring->nr_hwtail;

		    if (my_start == update_pos) {
			/* all slots before my_start have been reported,
			 * so scan subsequent leases to see if other ranges
			 * have been completed, and to a selwakeup or txsync.
		         */
			while (lease_idx != kring->nkr_lease_idx &&
				p[lease_idx] != NR_NOSLOT) {
			    j = p[lease_idx];
			    p[lease_idx] = NR_NOSLOT;
			    lease_idx = nm_next(lease_idx, lim);
			}
			/* j is the new 'write' position. j != my_start
			 * means there are new buffers to report
			 */
			if (likely(j != my_start)) {
				kring->nr_hwtail = j;
				still_locked = 0;
				mtx_unlock(&kring->q_lock);
				kring->nm_notify(kring, 0);
				/* this is netmap_notify for VALE ports and
				 * netmap_bwrap_notify for bwrap. The latter will
				 * trigger a txsync on the underlying hwna
				 */
				if (dst_na->retry && retry--) {
					/* XXX this is going to call nm_notify again.
					 * Only useful for bwrap in virtual machines
					 */
					goto retry;
				}
			}
		    }
		    if (still_locked)
			mtx_unlock(&kring->q_lock);
		}
cleanup:
		d->bq_head = d->bq_tail = NM_FT_NULL; /* cleanup */
		d->bq_len = 0;
	}
	brddst->bq_head = brddst->bq_tail = NM_FT_NULL; /* cleanup */
	brddst->bq_len = 0;
	return 0;
}

/* nm_txsync callback for VALE ports */
static int
netmap_vp_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_vp_adapter *na =
		(struct netmap_vp_adapter *)kring->na;
	u_int done;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	if (bridge_batch <= 0) { /* testing only */
		done = head; // used all
		goto done;
	}
	if (!na->na_bdg) {
		done = head;
		goto done;
	}
	if (bridge_batch > NM_BDG_BATCH)
		bridge_batch = NM_BDG_BATCH;

	done = nm_bdg_preflush(kring, head);
done:
	if (done != head)
		D("early break at %d/ %d, tail %d", done, head, kring->nr_hwtail);
	/*
	 * packets between 'done' and 'cur' are left unsent.
	 */
	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, lim);
	if (netmap_verbose)
		D("%s ring %d flags %d", na->up.name, kring->ring_id, flags);
	return 0;
}

/* Holds the default callbacks */
struct netmap_bdg_ops default_vale_ops = {netmap_bdg_learning, NULL, NULL};
struct nm_bdg_args vale_args = {
	.name = NM_BDG_NAME,
	.reg = netmap_vp_reg,
	.txsync = netmap_vp_txsync,
	.rxsync = netmap_vp_rxsync,
	.bwrap_reg = netmap_bwrap_reg,
	.bwrap_txsync = netmap_vp_txsync,
	.bwrap_notify = netmap_bwrap_notify,
	.bwrap_intr_notify = netmap_bwrap_intr_notify,
	.bdg_ops = &default_vale_ops
};

int
netmap_get_vale_na(struct nmreq_header *hdr, struct netmap_adapter **na,
		struct netmap_mem_d *nmd, int create)
{
	return netmap_get_bdg_na(hdr, na, nmd, create, &vale_args);
}


/* creates a persistent VALE port */
int
nm_vi_create(struct nmreq_header *hdr)
{
	struct nmreq_vale_newif *req =
		(struct nmreq_vale_newif *)(uintptr_t)hdr->nr_body;
	int error = 0;
	/* Build a nmreq_register out of the nmreq_vale_newif,
	 * so that we can call netmap_get_bdg_na(). */
	struct nmreq_register regreq;
	bzero(&regreq, sizeof(regreq));
	regreq.nr_tx_slots = req->nr_tx_slots;
	regreq.nr_rx_slots = req->nr_rx_slots;
	regreq.nr_tx_rings = req->nr_tx_rings;
	regreq.nr_rx_rings = req->nr_rx_rings;
	regreq.nr_mem_id = req->nr_mem_id;
	hdr->nr_reqtype = NETMAP_REQ_REGISTER;
	hdr->nr_body = (uintptr_t)&regreq;
	error = netmap_vi_create(hdr, 0 /* no autodelete */);
	hdr->nr_reqtype = NETMAP_REQ_VALE_NEWIF;
	hdr->nr_body = (uintptr_t)req;
        /* Write back to the original struct. */
	req->nr_tx_slots = regreq.nr_tx_slots;
	req->nr_rx_slots = regreq.nr_rx_slots;
	req->nr_tx_rings = regreq.nr_tx_rings;
	req->nr_rx_rings = regreq.nr_rx_rings;
	req->nr_mem_id = regreq.nr_mem_id;
	return error;
}

/* remove a persistent VALE port from the system */
int
nm_vi_destroy(const char *name)
{
	struct ifnet *ifp;
	struct netmap_vp_adapter *vpna;
	int error;

	ifp = ifunit_ref(name);
	if (!ifp)
		return ENXIO;
	NMG_LOCK();
	/* make sure this is actually a VALE port */
	if (!NM_NA_VALID(ifp) || NA(ifp)->nm_register != netmap_vp_reg) {
		error = EINVAL;
		goto err;
	}

	vpna = (struct netmap_vp_adapter *)NA(ifp);

	/* we can only destroy ports that were created via NETMAP_BDG_NEWIF */
	if (vpna->autodelete) {
		error = EINVAL;
		goto err;
	}

	/* also make sure that nobody is using the inferface */
	if (NETMAP_OWNED_BY_ANY(&vpna->up) ||
	    vpna->up.na_refcount > 1 /* any ref besides the one in nm_vi_create()? */) {
		error = EBUSY;
		goto err;
	}

	NMG_UNLOCK();

	D("destroying a persistent vale interface %s", ifp->if_xname);
	/* Linux requires all the references are released
	 * before unregister
	 */
	netmap_detach(ifp);
	if_rele(ifp);
	nm_os_vi_detach(ifp);
	return 0;

err:
	NMG_UNLOCK();
	if_rele(ifp);
	return error;
}

static int
nm_update_info(struct nmreq_register *req, struct netmap_adapter *na)
{
	req->nr_rx_rings = na->num_rx_rings;
	req->nr_tx_rings = na->num_tx_rings;
	req->nr_rx_slots = na->num_rx_desc;
	req->nr_tx_slots = na->num_tx_desc;
	return netmap_mem_get_info(na->nm_mem, &req->nr_memsize, NULL,
					&req->nr_mem_id);
}

/*
 * Create a virtual interface registered to the system.
 * The interface will be attached to a bridge later.
 */
int
netmap_vi_create(struct nmreq_header *hdr, int autodelete)
{
	struct nmreq_register *req = (struct nmreq_register *)(uintptr_t)hdr->nr_body;
	struct ifnet *ifp;
	struct netmap_vp_adapter *vpna;
	struct netmap_mem_d *nmd = NULL;
	int error;

	if (hdr->nr_reqtype != NETMAP_REQ_REGISTER) {
		return EINVAL;
	}

	/* don't include VALE prefix */
	if (nm_bdg_prefix(hdr->nr_name))
		return EINVAL;
	if (strlen(hdr->nr_name) >= IFNAMSIZ) {
		return EINVAL;
	}
	ifp = ifunit_ref(hdr->nr_name);
	if (ifp) { /* already exist, cannot create new one */
		error = EEXIST;
		NMG_LOCK();
		if (NM_NA_VALID(ifp)) {
			int update_err = nm_update_info(req, NA(ifp));
			if (update_err)
				error = update_err;
		}
		NMG_UNLOCK();
		if_rele(ifp);
		return error;
	}
	error = nm_os_vi_persist(hdr->nr_name, &ifp);
	if (error)
		return error;

	NMG_LOCK();
	if (req->nr_mem_id) {
		nmd = netmap_mem_find(req->nr_mem_id);
		if (nmd == NULL) {
			error = EINVAL;
			goto err_1;
		}
	}
	/* netmap_vp_create creates a struct netmap_vp_adapter */
	error = netmap_vp_create(hdr, ifp, nmd, &vpna, &vale_args);
	if (error) {
		D("error %d", error);
		goto err_1;
	}
	/* persist-specific routines */
	vpna->up.nm_bdg_ctl = netmap_vp_bdg_ctl;
	if (!autodelete) {
		netmap_adapter_get(&vpna->up);
	} else {
		vpna->autodelete = 1;
	}
	NM_ATTACH_NA(ifp, &vpna->up);
	/* return the updated info */
	error = nm_update_info(req, &vpna->up);
	if (error) {
		goto err_2;
	}
	ND("returning nr_mem_id %d", req->nr_mem_id);
	if (nmd)
		netmap_mem_put(nmd);
	NMG_UNLOCK();
	ND("created %s", ifp->if_xname);
	return 0;

err_2:
	netmap_detach(ifp);
err_1:
	if (nmd)
		netmap_mem_put(nmd);
	NMG_UNLOCK();
	nm_os_vi_detach(ifp);

	return error;
}
#endif /* WITH_VALE */
