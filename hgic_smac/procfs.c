#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "hgics.h"

///////////////////////////////////////////////////////////////////////////////////////////////
static int hgics_status_show(struct seq_file *seq, void *v)
{
    int i = 0;
    struct hgics_wdev *hg = (struct hgics_wdev *)seq->private;

    seq_printf(seq, "fw info:%d.%d.%d.%d, svn version:%d\r\n",
               (hg->fwinfo.version >> 24) & 0xff, (hg->fwinfo.version >> 16) & 0xff,
               (hg->fwinfo.version >> 8) & 0xff, (hg->fwinfo.version & 0xff),
               hg->fwinfo.svn_version);
    seq_printf(seq, "hgics status:\r\n");
    seq_printf(seq, "    STATE:%lx, BUS FLAGS:%lx\r\n", hg->state, hg->bus->flags);
    for (i = 0; i < IEEE80211_NUM_ACS; i++) {
        if (hg->data_txq[i].qlen) {
            seq_printf(seq, "    data_txq[%d]: %d\r\n", i, hg->data_txq[i].qlen);
        }
    }
    if (hg->ctrl.rxq.qlen) {
        seq_printf(seq, "    ctrl_rxq: %d\r\n", hg->ctrl.rxq.qlen);
    }
    if (hg->ctrl.txq.qlen) {
        seq_printf(seq, "    ctrl_txq: %d\r\n", hg->ctrl.txq.qlen);
    }
    if (hg->trans_q.qlen) {
        seq_printf(seq, "    trans_q : %d\r\n", hg->trans_q.qlen);
    }
    if (hg->ack_q.qlen) {
        seq_printf(seq, "    ack_q   : %d\r\n", hg->ack_q.qlen);
    }
    if (hg->evt_list.qlen) {
        seq_printf(seq, "    evt_list   : %d\r\n", hg->evt_list.qlen);
    }
    seq_printf(seq, "    tx_ok:%llu, tx_fail: %llu, tx_dropped: %llu\r\n", 
        hg->status.tx_ok,  hg->status.tx_fail,  hg->status.tx_drop);
    return 0;
}

static int hgics_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, hgics_status_show, PDE_DATA(inode));
}
static const struct proc_ops hgics_pops_status = {
    .proc_open = hgics_status_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/////////////////////////////////////////////////////////////////////////////////////
static int hgics_fwevent_open(struct inode *inode, struct file *file)
{
    return single_open(file, NULL, PDE_DATA(inode));
}
static ssize_t hgics_fwevent_read(struct file *file, char __user *buffer,
                                  size_t count, loff_t *data)
{
    int ret = 0;
    struct sk_buff *skb = NULL;
    struct seq_file   *seq = (struct seq_file *)file->private_data;
    struct hgics_wdev *hg  = (struct hgics_wdev *)seq->private;

    if (down_timeout(&hg->evt_sema, msecs_to_jiffies(100))) {
        return 0;
    }

    if (!skb_queue_empty(&hg->evt_list)) {
        skb = skb_dequeue(&hg->evt_list);
        if (skb) {
            if (!copy_to_user(buffer, skb->data, skb->len)) {
                ret = skb->len;
            }
            kfree_skb(skb);
        }
    }
    return ret;
}
static const struct proc_ops hgics_pops_fwevent = {
    .proc_open = hgics_fwevent_open,
    .proc_read = hgics_fwevent_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

///////////////////////////////////////////////////////////////////////////////////////////
static int hgics_iwpriv_open(struct inode *inode, struct file *file)
{
    return single_open(file, NULL, PDE_DATA(inode));
}

static ssize_t hgics_iwpriv_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *data)
{
    int ret = -1;
    char *buf;
    struct seq_file   *seq = (struct seq_file *)file->private_data;
    struct hgics_wdev *hg  = (struct hgics_wdev *)seq->private;
    struct iwreq wrqin;
    char *ifname, *cmd, *args;

    if (count <= 0) {
        return -EINVAL;
    }

    buf = kzalloc(count + 32, GFP_KERNEL);
    if (buf) {
        ret = copy_from_user(buf, buffer, count);
        if (ret) {
            kfree(buf);
            hgic_err("copy_from_user err: %d\r\n", ret);
            return ret;
        }

        ifname = buf;
        cmd = strchr(ifname, ' ');
        if (cmd == NULL) {
            wrqin.u.data.pointer = buf;
            wrqin.u.data.length  = count;
            ret = hgic_iwpriv_dump(&hg->ctrl, &wrqin);
            if (ret) {
                if (copy_to_user((void *)(buffer + 4), buf, ret <= count ? ret : count)) {
                    kfree(buf);
                    hgic_err("copy_to_user fail\r\n");
                    return -EINVAL;
                }
            }

            if (copy_to_user((void *)buffer, &ret, 4)) {
                kfree(buf);
                hgic_err("copy_to_user fail\r\n");
                return -EINVAL;
            }

            hgic_err("**Empty CMD**\r\n");
            kfree(buf);
            return count;
        }

        *cmd++ = 0;
        args = strchr(cmd, ' ');
        if (args) {
            *args++ = 0;
        }

        memset(&wrqin, 0, sizeof(wrqin));
        wrqin.u.data.pointer = args;
        wrqin.u.data.length  = args ? count - (args - buf) : 0;

        if (strcasecmp(cmd, "get") == 0) {
            ret = hgic_iwpriv_get_proc(&hg->ctrl, 1, &wrqin);
            if (ret == 0 && wrqin.u.data.length) {
                ret = wrqin.u.data.length;
                if (copy_to_user((void *)(buffer + 4), args, ret <= count ? ret : count)) {
                    kfree(buf);
                    hgic_err("copy_to_user fail\r\n");
                    return -EINVAL;
                }
            }
        } else if (strcasecmp(cmd, "set") == 0) {
            ret = hgic_iwpriv_set_proc(&hg->ctrl, 1, &wrqin);
        } else {
            kfree(buf);
            hgic_err("invalid cmd: [%s]\r\n", cmd);
            return -EINVAL;
        }

        if (copy_to_user((void *)buffer, &ret, 4)) {
            kfree(buf);
            hgic_err("copy_to_user fail\r\n");
            return -EINVAL;
        }

        kfree(buf);
        return count;
    }
    return -ENOMEM;
}
static const struct proc_ops hgics_pops_iwpriv = {
    .proc_open = hgics_iwpriv_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_write = hgics_iwpriv_write,
    .proc_release = single_release,
};

///////////////////////////////////////////////////////////////////////////////////////////

void hgics_create_common_procfs(struct hgics_wdev *hg)
{
    hg->proc.status = proc_create_data("status", 0x0444,
                                       hg->proc.rootdir, &hgics_pops_status, hg);
    if (hg->proc.status == NULL) {
        hgic_err("create proc file: status failed\r\n");
    }
    hg->proc.fwevnt = proc_create_data("fwevnt", 0x0444,
                                       hg->proc.rootdir, &hgics_pops_fwevent, hg);
    if (hg->proc.fwevnt == NULL) {
        hgic_err("create proc file: fwevt failed\r\n");
    }
    hg->proc.iwpriv = proc_create_data("iwpriv", 0x0666,
                                       hg->proc.rootdir, &hgics_pops_iwpriv, hg);
    if (hg->proc.iwpriv == NULL) {
        hgic_err("create proc file: fwevt failed\r\n");
    }
}

void hgics_delete_common_procfs(struct hgics_wdev *hg)
{
    if (hg->proc.status) {
        remove_proc_entry("status", hg->proc.rootdir);
        hg->proc.status = NULL;
    }
    if (hg->proc.fwevnt) {
        remove_proc_entry("fwevnt", hg->proc.rootdir);
        hg->proc.fwevnt = NULL;
    }
    if (hg->proc.iwpriv) {
        remove_proc_entry("iwpriv", hg->proc.rootdir);
        hg->proc.iwpriv = NULL;
    }
}

void hgics_create_procfs(struct hgics_wdev *hg)
{
    hgic_dbg("enter\r\n");
    hg->proc.rootdir = proc_mkdir("hgics", NULL);
    if (hg->proc.rootdir == NULL) {
        hgic_err("create proc dir: hgic failed\r\n");
        return;
    }
    hgics_create_common_procfs(hg);
    hg->hghw->ops->create_procfs(hg);
    hgic_dbg("leave\r\n");
}

void hgics_delete_procfs(struct hgics_wdev *hg)
{
    hgic_dbg("enter\r\n");
    if (hg->proc.rootdir) {
        hgics_delete_common_procfs(hg);
        hg->hghw->ops->delete_procfs(hg);
        remove_proc_entry("hgics", NULL);
        hg->proc.rootdir = NULL;
    }
    hgic_dbg("leave\r\n");
}

