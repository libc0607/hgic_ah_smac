#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "hgics.h"
#include "util.h"

#define HGICS_FLAGS (4)
static u32 hgics_flags[HGICS_FLAGS];
void hgics_flag_new(void *v)
{
    int i = 0;
    for (i = 0; i < HGICS_FLAGS; i++) {
        if (hgics_flags[i] == 0) {
            hgics_flags[i] = (u32)v;
            break;
        }
    }
}
void hgics_flag_del(void *v)
{
    int i = 0;
    for (i = 0; i < HGICS_FLAGS && v; i++) {
        if (hgics_flags[i] == (u32)v) {
            hgics_flags[i] = 0;
            break;
        }
    }
}
int hgics_flag_check(void *v)
{
    int i = 0;
    for (i = 0; i < HGICS_FLAGS && (u32)v; i++) {
        if (hgics_flags[i] == (u32)v) {
            return 1;
        }
    }
    return 0;
}

u16 hgics_get_icmp_seq(struct sk_buff *skb)
{
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    u16 hdrlen = ieee80211_hdrlen(hdr->frame_control);
    u8 *payload = skb->data + hdrlen;
    u16 ethertype = (payload[6] << 8) | payload[7];
    struct iphdr *ip;
    struct icmphdr *icmp;

    ip = (struct iphdr *)(payload + 6 + 2);
    icmp = (struct icmphdr *)(ip + 1);
    if (ethertype == ETH_P_IP && ip->protocol == IPPROTO_ICMP) {
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            return ntohs(icmp->un.echo.sequence);
        }
    }
    return 0xffff;
}

#ifdef __RTOS__
int hgic_ifbus_reinit(const char *ifname)
{
    struct hgics_wdev *hg   = NULL;
    struct net_device *ndev = net_device_get_by_name(ifname);
    if (ndev && ndev->ieee80211_ptr) {
        hg = (struct hgics_wdev *)ndev->ieee80211_ptr->hw->priv;
        if (hg->bus->reinit) {
            return hg->bus->reinit(hg->bus);
        }
    }
    return 0;
}
struct hgic_ota *hgic_devota(struct net_device *dev)
{
    struct hgics_wdev *hg = NULL;

    if (dev == NULL || dev->ieee80211_ptr == NULL) {
        return NULL;
    }
    hg = (struct hgics_wdev *)dev->ieee80211_ptr->hw->priv;
    if (hg == NULL) {
        hgic_err("hg is NULL!!!\n");
        return NULL;
    }
    return &hg->ota;
}
#endif


