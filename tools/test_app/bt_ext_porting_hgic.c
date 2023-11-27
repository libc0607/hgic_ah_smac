#include "tuya_cloud_types.h"
#include "uni_log.h"
#include "tuya_hal_bt.h"
#include "tuya_driver.h"
#include "tuya_hal_semaphore.h"
#include "tuya_hal_system.h"
#include "tuya_hal_thread.h"
#include "tuya_ws_db.h"
#include "bt_ext_porting.h"
#include "bt_uart_drv.h"
#include "mem_pool.h"
#include "string.h"
#include "sys_timer.h"
#include "tuya_os_adapter.h"


enum recv_proc {
    UART_RECV = 0,
    UART_PROC,
};

enum send_state {
    SEND_IDLE = 0,
    SEND_BUSY,
};

STATIC TY_EX_BT_MSG_S       s_btext_msg = {0};
STATIC TY_BT_MSG_CB         bt_msg_cb = NULL;
STATIC ty_bt_scan_info_t    *ble_scan_info = NULL;
STATIC TUYA_EXT_BT_GPIO_IQR_CB g_gpio_irq_cb = NULL;
STATIC TUYA_QUERY_HID_RSSI_CB g_query_rssi_cb = NULL;
STATIC MUTEX_HANDLE         g_bt_ext_mute = NULL;
STATIC TIMER_ID             g_query_rssi_timer = 0;
STATIC BOOL_T               g_hid_bond = FALSE;
STATIC BOOL_T               g_inited = FALSE;

STATIC OPERATE_RET tuya_start_query_rssi(VOID);
STATIC OPERATE_RET tuya_stop_query_rssi(VOID);


STATIC OPERATE_RET tuya_ext_bt_send(BYTE_T *data, UINT8_T len);
STATIC OPERATE_RET tuya_ext_bt_port_init(ty_bt_param_t *p);
STATIC OPERATE_RET tuya_ext_bt_port_deinit(void);
STATIC OPERATE_RET tuya_ext_bt_gap_disconnect(void);
STATIC OPERATE_RET tuya_ext_bt_reset_adv(tuya_ble_data_buf_t *adv, tuya_ble_data_buf_t *scan_resp);
STATIC OPERATE_RET tuya_ext_bt_start_adv(void);
STATIC OPERATE_RET tuya_ext_bt_stop_adv(void);
STATIC OPERATE_RET tuya_ext_bt_assign_scan(ty_bt_scan_info_t *info);
STATIC OPERATE_RET tuya_ext_bt_get_rssi(signed char *rssi);
STATIC OPERATE_RET tuya_ext_bt_start_scan();
STATIC OPERATE_RET tuya_ext_bt_stop_scan();
STATIC OPERATE_RET tuya_ext_bt_setmac(CONST NW_MAC_S *mac);
STATIC OPERATE_RET tuya_ext_bt_getmac(NW_MAC_S *mac);


STATIC TUYA_OS_BT_INTF m_tuya_os_bt_intfs = {
        .port_init      = tuya_ext_bt_port_init,
        .port_deinit    = tuya_ext_bt_port_deinit,
        .gap_disconnect = tuya_ext_bt_gap_disconnect,
        .send           = tuya_ext_bt_send,
        .reset_adv      = tuya_ext_bt_reset_adv,
        .get_rssi       = tuya_ext_bt_get_rssi,
        .start_adv      = tuya_ext_bt_start_adv,
        .stop_adv       = tuya_ext_bt_stop_adv,
        .assign_scan    = tuya_ext_bt_assign_scan,
        .scan_init      = NULL,
        .start_scan     = tuya_ext_bt_start_scan,
        .stop_scan      = tuya_ext_bt_stop_scan,
        .set_mac        = tuya_ext_bt_setmac,
        .get_mac        = tuya_ext_bt_getmac,
};

VOID __print_raw_bytes(BYTE_T* data, INT_T len)
{
    INT_T i = 0;
    for(;i < len;i++){
        printf("%x ", data[i]);
    }
    printf("\n");
}

STATIC NW_MAC_S s_default_mac_addr = {
    .mac = {0x6F,0xDC,0xAB,0xAC,0xDD,0xC7}
};

/**
 * @brief 互斥锁
 *
 * @return STATIC
 */
STATIC VOID tuya_bt_ext_lock(VOID)
{
    if (!g_bt_ext_mute) {
        return;
    }
    tuya_hal_mutex_lock(g_bt_ext_mute);
}

/**
 * @brief 互斥锁
 *
 * @return STATIC
 */
STATIC VOID tuya_bt_ext_unlock(VOID)
{
    if (!g_bt_ext_mute) {
        return;
    }
    tuya_hal_mutex_unlock(g_bt_ext_mute);
}


STATIC INT_T ty_btext_upload_proc(UCHAR_T* data)
{

    BTUART_FRAME_S *ty_frame = (BTUART_FRAME_S *)data;
    ty_frame->len = WORD_SWAP(ty_frame->len);

    TUYA_BTUART_INFO("recv fr_head[0x%x] fr_type[0x%x] fr_len[0x%x]",
                     ty_frame->head, ty_frame->fr_type, ty_frame->len);

    INT_T i = 0;
    for (; i < ty_frame->len; i++)
    {
        TUYA_BTUART_INFO("recv data[%d]: 0x%x", i, ty_frame->data[i]);
    }

    if (bt_msg_cb)
    {
        tuya_ble_data_buf_t databuf;
        databuf.data = ty_frame->data + 1;
        databuf.len = ty_frame->len - 1;
        bt_msg_cb(0, TY_BT_EVENT_RX_DATA, &databuf);
    }

    return OPRT_OK;
}

/*消息处理*/
int tuya_app_recv_attdata(char *data, int len)
{
    tuya_ble_data_buf_t databuf = {data, len};
    if(bt_msg_cb) bt_msg_cb(1, TY_BT_EVENT_RX_DATA, &databuf);    
    return 0;
}

STATIC OPERATE_RET tuya_ext_bt_send(BYTE_T *data, UINT8_T len)
{
    hgics_gatt_notify(0x0A, data, len);
    return OPRT_OK;
}

STATIC OPERATE_RET tuya_ext_bt_port_init(ty_bt_param_t *p)
{
    OPERATE_RET op_ret = OPRT_OK;
    
    TUYA_BTUART_INFO("tuya ext bt port init");

    hgic_iwpriv_blenc_set_advdata("wlan0", p->adv.data, p->adv.len);
    hgic_iwpriv_blenc_set_scanresp("wlan0", p->scan_rsp.data, p->scan_rsp.len);

    if (p) {
        bt_msg_cb  = p->cb;
    }

    return op_ret;

}

STATIC OPERATE_RET tuya_ext_bt_port_deinit(void)
{
    hgic_iwpriv_blenc_start("wlan0", 0, 38);
    return OPRT_OS_ADAPTER_OK;
}

/**
 * @brief 用于断开蓝牙连接
 *
 * @return int 0=成功，非0=失败
 */
STATIC OPERATE_RET tuya_ext_bt_gap_disconnect(void)
{
    RECV_FRAME_S recv = {0};
    OPERATE_RET ret = OPRT_OK;
    
    return ret;
}

/**
 * @brief 用于重置蓝牙广播内容
 *
 * @param[in]       adv
  * @param[in]      scan_resp
 * @return int 0=成功，非0=失败
 */
STATIC OPERATE_RET tuya_ext_bt_reset_adv(tuya_ble_data_buf_t *adv, tuya_ble_data_buf_t *scan_resp)
{
    TUYA_BTUART_INFO("reset adv: ");
    __print_raw_bytes(adv->data, adv->len);
    TUYA_BTUART_INFO("resp: ");
    __print_raw_bytes(scan_resp->data, scan_resp->len);

    hgic_iwpriv_blenc_set_advdata("wlan0", adv->data, adv->len);
    hgic_iwpriv_blenc_set_scanresp("wlan0", scan_resp->data, scan_resp->len);
    return OPRT_OS_ADAPTER_OK;
}

/**
 * @brief 用于启动蓝牙广播
 *
 * @return int 0=成功，非0=失败
 */
STATIC OPERATE_RET tuya_ext_bt_start_adv(void)
{
    TUYA_BTUART_INFO("start adv");
    hgic_iwpriv_blenc_start_adv("wlan0", 1);
    hgic_iwpriv_blenc_start("wlan0", 3, 38);
    return OPRT_OK;
}

/**
 * @brief 用于停止蓝牙广播
 *
 * @return int 0=成功，非0=失败
 */
STATIC OPERATE_RET tuya_ext_bt_stop_adv(void)
{
    TUYA_BTUART_INFO("stop adv");
    hgic_iwpriv_blenc_start_adv("wlan0", 0);
    hgic_iwpriv_blenc_start("wlan0", 0, 38);
    return OPRT_OK;
}

/**
 * @brief 用于扫描蓝牙信标(厂测使用)
 *
 * @param[out]       rssi
 * @return int 0=成功，非0=失败
 */
STATIC OPERATE_RET tuya_ext_bt_assign_scan(ty_bt_scan_info_t *info)
{
    return OPRT_OK;
}

STATIC OPERATE_RET tuya_ext_bt_start_scan()
{
    return OPRT_OS_ADAPTER_BT_SCAN_FAILED;
}

STATIC OPERATE_RET tuya_ext_bt_stop_scan()
{
    return OPRT_OS_ADAPTER_BT_SCAN_FAILED;
}

/**
 * @brief 用于获取蓝牙信号强度
 *
 * @param[out]       rssi
 * @return int 0=成功，非0=失败
 */
STATIC OPERATE_RET tuya_ext_bt_get_rssi(signed char *rssi)
{
    return OPRT_OK;
}

STATIC OPERATE_RET tuya_ext_bt_setmac(CONST NW_MAC_S *mac)
{
    TUYA_BTUART_INFO("tuya_ext_bt_setmac %x:%x:%x:%x:%x:%x",
             mac->mac[0], mac->mac[1], mac->mac[2], mac->mac[3],
             mac->mac[4], mac->mac[5]);
    memcpy(s_default_mac_addr->mac, mac->mac, 6);
    hgic_iwpriv_blenc_set_devaddr("wlan0", mac->mac);
    return OPRT_OS_ADAPTER_OK;
}

STATIC OPERATE_RET tuya_ext_bt_getmac(NW_MAC_S *mac)
{
    OPERATE_RET ret = OPRT_OK;
    memcpy(mac->mac, s_default_mac_addr->mac, 6);
    return OPRT_OS_ADAPTER_OK;
}

STATIC void tuya_get_default_devaddr(char *ifname)
{
    int ret = -1;
    struct ifreq req;

    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock != -1) {
        memset(&req, 0, sizeof(struct ifreq));
        strncpy(req.ifr_name, ifname, strlen(ifname));
        ret = ioctl(sock, SIOCGIFHWADDR, &req);
        if (ret != -1) {
            memcpy(s_default_mac_addr.mac, req.ifr_hwaddr.sa_data, 6);
        }
        close(sock);
    }
    return ret;
}

OPERATE_RET tuya_ext_bt_init(VOID)
{
   tuya_get_default_devaddr("wlan0");
   return tuya_os_adapt_reg_intf(INTF_BT, &m_tuya_os_bt_intfs);
}

