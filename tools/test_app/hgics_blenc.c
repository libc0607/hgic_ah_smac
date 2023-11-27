/**
  ******************************************************************************
  * @file    hgics_blenc.c
  * @author  HUGE-IC Application Team
  * @version V1.0.0
  * @date    2022-05-18
  * @brief   hgic BLE network configure lib
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2022 HUGE-IC</center></h2>
  *
  ******************************************************************************
  */

#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "hgic.h"

#define TUYA_BLE_SERVICE

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define HCI_ACL_HDR_SIZE (4)
#define BT_L2CAP_HDR_SIZE (4)
#define HGICS_GATT_CHARAC_Broadcast (0x01)
#define HGICS_GATT_CHARAC_Read      (0x02)
#define HGICS_GATT_CHARAC_Write_Without_Response (0x04)
#define HGICS_GATT_CHARAC_Write (0x08)
#define HGICS_GATT_CHARAC_Notify (0x10)
#define HGICS_GATT_CHARAC_Indicate (0x20)
#define HGICS_GATT_CHARAC_Authenticated_Signed_Writes (0x40)
#define HGICS_GATT_CHARAC_Extended_Properties (0x80)

typedef int (*hgics_gatt_valhdl)(char *data, int len);
struct hgics_gatt_hdr {
    uint16_t att_hdl;
    uint16_t att_type;
    uint16_t priv_type;
};
struct hgics_gatt_primary_service {
    struct hgics_gatt_hdr hdr;
    uint16_t att_type;
};
struct hgics_gatt_characteristic {
    struct hgics_gatt_hdr hdr;
    uint8_t  properties;
    uint16_t value_hdl;
    uint16_t value_type;
};
struct hgics_gatt_characteristic_value {
    struct hgics_gatt_hdr hdr;
    hgics_gatt_valhdl read_cb;
    hgics_gatt_valhdl write_cb;
};

#define HGICS_GATT_PRIMARY_SVR(hdl, type) struct hgics_gatt_primary_service att##hdl = {\
        .hdr = { \
             .att_hdl = (hdl), \
             .att_type = 0x2800,\
             .priv_type = 1,\
         }, \
        .att_type = (type),\
    }

#define HGICS_GATT_CHARACTER(hdl, flag, v_hdl, v_type) struct hgics_gatt_characteristic att##hdl = {\
        .hdr = { \
             .att_hdl = (hdl), \
             .att_type = 0x2803,\
             .priv_type = 2,\
         }, \
         .properties = (flag),\
         .value_hdl = (v_hdl),\
         .value_type = (v_type),\
    }

#define HGICS_GATT_CHARACTER_VALUE(hdl, type, read, write) struct hgics_gatt_characteristic_value att##hdl = {\
        .hdr = { \
             .att_hdl = (hdl), \
             .att_type = (type),\
             .priv_type = 4,\
         }, \
        .read_cb = (read),\
        .write_cb = (write),\
    }

#define HGICS_GATT_CHARACTER_CCCD(hdl, read, write) struct hgics_gatt_characteristic_value att##hdl = {\
        .hdr = { \
             .att_hdl = (hdl), \
             .att_type = (0x2902),\
             .priv_type = 4,\
         }, \
        .read_cb = (read),\
        .write_cb = (write),\
    }

static inline void put_unaligned_le16(unsigned short val, unsigned char *p)
{
    *p++ = val;
    *p++ = val >> 8;
}
static inline unsigned short get_unaligned_le16(const unsigned char *p)
{
    return p[0] | p[1] << 8;
}

/////////////////////////////////////////////////////////////
/*                  Define GATT Service                    */
/////////////////////////////////////////////////////////////

#ifdef TUYA_BLE_SERVICE //define Tuya Service
extern int tuya_app_recv_attdata(char *data, int len);
HGICS_GATT_PRIMARY_SVR(1, 0x1800);
HGICS_GATT_CHARACTER(2, HGICS_GATT_CHARAC_Read, 3, 0x2a00);
HGICS_GATT_CHARACTER_VALUE(3, 0x2a00, NULL, NULL);
HGICS_GATT_CHARACTER(4, HGICS_GATT_CHARAC_Read, 5, 0x2a01);
HGICS_GATT_CHARACTER_VALUE(5, 0x2a01, NULL, NULL);

HGICS_GATT_PRIMARY_SVR(6, 0x1910);
HGICS_GATT_CHARACTER(7, HGICS_GATT_CHARAC_Write_Without_Response, 8, 0x2b11);
HGICS_GATT_CHARACTER_VALUE(8, 0x2b11, NULL, tuya_app_recv_attdata);
HGICS_GATT_CHARACTER(9, HGICS_GATT_CHARAC_Notify, 10, 0x2b10);
HGICS_GATT_CHARACTER_VALUE(10, 0x2b10, NULL, NULL);
HGICS_GATT_CHARACTER_CCCD(11, NULL, NULL);

static struct hgics_gatt_hdr *att_table[] = { (struct hgics_gatt_hdr *)&att1, 
                                              (struct hgics_gatt_hdr *)&att2, 
                                              (struct hgics_gatt_hdr *)&att3, 
                                              (struct hgics_gatt_hdr *)&att4,
                                              (struct hgics_gatt_hdr *)&att5, 
                                              (struct hgics_gatt_hdr *)&att6,
                                              (struct hgics_gatt_hdr *)&att7, 
                                              (struct hgics_gatt_hdr *)&att8, 
                                              (struct hgics_gatt_hdr *)&att9, 
                                              (struct hgics_gatt_hdr *)&att10,
                                              (struct hgics_gatt_hdr *)&att11
                                             };
#if 1
int tuya_app_recv_attdata(char *data, int len)
{
    printf("Not implemented\n");
}
#endif
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
int hgics_gatt_notify(uint16_t att_hdl, char *data, int len)
{
    char buff[32];
    buff[0] = 0x1B;
    put_unaligned_le16(att_hdl, buff + 1);
    memcpy(buff + 3, data, len);
    hgics_dump_hex("BLE Notify:\r\n", buff, 3 + len, 1);
    return hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, 3 + len);
}

void hgics_gatt_send_ATT_ERROR(uint8_t opcode, uint16_t atthandle, uint8_t err_code)
{
    uint8_t buff[5];
    buff[0] = 0x01;
    buff[1] = opcode;
    put_unaligned_le16(atthandle, buff + 2);
    buff[4] = err_code;
    hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, 5);
}

void hgics_gatt_send_WRITE_RESP(void)
{
    uint8_t opcode = 0x13;
    hgic_iwpriv_blenc_send_gatt_data("wlan0", &opcode, 1);
}

void hgics_gatt_EXCHANGE_MTU_RSP(uint8_t mtu)
{
    uint8_t buff[5];
    buff[0] = 0x03;
    put_unaligned_le16(23, buff + 1);
    hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, 3);
    buff[0] = 0x02;
    hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, 3);
}

void hgics_gatt_READ_REQ(uint16_t att_hdl)
{
    int i = 0;
    int len = 0;
    char resp[32];
    struct hgics_gatt_characteristic_value *v;

    resp[0] = 0x0B;
    for (i = 0; i < ARRAY_SIZE(att_table); i++) {
        if (att_table[i]->att_hdl == att_hdl && att_table[i]->priv_type == 4) {
            v = (struct hgics_gatt_characteristic_value *)att_table[i];
            if (v->read_cb) {
                len = v->read_cb(resp + 1, 23);
            }
            break;
        }
    }

    if (len > 0) {
        hgic_iwpriv_blenc_send_gatt_data("wlan0", resp, 1 + len);
    } else {
        printf("==>ATT_NOT_FOUND: att_hdl=0x%x\r\n", att_hdl);
        hgics_gatt_send_ATT_ERROR(0x0A, att_hdl, 0x0a);
    }
}

void hgics_gatt_WRITE(uint16_t att_hdl, char *att_value, int value_len, uint16_t opcode)
{
    int i = 0;
    struct hgics_gatt_characteristic_value *v;

    for (i = 0; i < ARRAY_SIZE(att_table); i++) {
        if (att_table[i]->att_hdl == att_hdl && att_table[i]->priv_type == 4) {
            v = (struct hgics_gatt_characteristic_value *)att_table[i];
            if (v->write_cb) {
                v->write_cb(att_value, value_len);
            }

            if (opcode >> 8) {
                hgics_gatt_send_WRITE_RESP();
            }
            return;
        }
    }

    printf("==>ATT_NOT_FOUND: att_hdl=0x%x, opcode=0x%x\r\n", att_hdl, opcode & 0xff);
    hgics_gatt_send_ATT_ERROR((opcode & 0xff), att_hdl, 0x0a);
}

void hgics_gatt_FIND_INFORMATION_REQ(uint16_t start_hdl, uint16_t end_hdl)
{
    int i = 0;
    int off = 2;
    char buff[32];

    buff[0] = 0x05;
    buff[1] = 0x1;

    for (i = 0; buff[1] && i < ARRAY_SIZE(att_table); i++) {
        if (att_table[i]->att_hdl >= start_hdl && att_table[i]->att_hdl <= end_hdl) {
            put_unaligned_le16(att_table[i]->att_hdl, buff + off); off += 2;
            put_unaligned_le16(att_table[i]->att_type, buff + off); off += 2;
        }
    }

    if (off > 2) {
        hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, off);
    } else {
        printf("==>ATT_NOT_FOUND: start_hdl=0x%x, end_hdl=0x%x\r\n", start_hdl, end_hdl);
        hgics_gatt_send_ATT_ERROR(0x04, start_hdl, 0x0a);
    }
}

void hgics_gatt_READ_BY_TYPE_REQ(uint16_t start_hdl, uint16_t end_hdl, uint16_t att_type)
{
    int i = 0;
    int off = 2;
    char buff[32];
    struct hgics_gatt_characteristic *c;

    buff[0] = 0x09;
    for (i = 0; i < ARRAY_SIZE(att_table); i++) {
        if (att_table[i]->att_hdl >= start_hdl && att_table[i]->att_hdl <= end_hdl && att_table[i]->att_type == att_type) {
            switch (att_type) {
                case 0x2803: /*read Characteristic*/
                    buff[1] = 0x7;
                    c = (struct hgics_gatt_characteristic *)att_table[i];
                    put_unaligned_le16(c->hdr.att_hdl, buff + off); off += 2;
                    buff[off] = c->properties; off += 1;
                    put_unaligned_le16(c->value_hdl, buff + off); off += 2;
                    put_unaligned_le16(c->value_type, buff + off); off += 2;
                    break;
            };
        }
    }

    if (off > 2) {
        hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, off);
    } else {
        printf("==>ATT_NOT_FOUND: start_hdl=0x%x, end_hdl=0x%x, att_type=0x%x\r\n", start_hdl, end_hdl, att_type);
        hgics_gatt_send_ATT_ERROR(0x08, start_hdl, 0x0a);
    }
}

void hgics_gatt_READ_BY_GROUP_TYPE_REQ(uint16_t start_hdl, uint16_t end_hdl, uint16_t group_type)
{
    int off = 2;
    int i   = 0;
    char buff[32];
    int start_idx = -1;
    int end_indx  = -1;
    struct hgics_gatt_primary_service *p;

    buff[0] = 0x11;
    for (i = 0; i < ARRAY_SIZE(att_table); i++) {
        if (att_table[i]->att_hdl >= start_hdl && att_table[i]->att_hdl <= end_hdl) {
            switch (group_type) {
                case 0x2800: /*read Primary Service*/
                    buff[1] = 0x6;
                    if (att_table[i]->att_type == 0x2800) { //find a primary service
                        if (end_indx > 0) { //last group end
                            p = (struct hgics_gatt_primary_service *)att_table[start_idx];
                            put_unaligned_le16(att_table[end_indx]->att_hdl, buff + off); off += 2;
                            put_unaligned_le16(p->att_type, buff + off); off += 2;
                        }
                        start_idx = i; //new group start
                        put_unaligned_le16(att_table[start_idx]->att_hdl, buff + off); off += 2;
                    }
                    if (start_idx >= 0) end_indx = i;
                    break;
            }
        }
    }

    if (off > 2) {
        p = (struct hgics_gatt_primary_service *)att_table[start_idx];
        put_unaligned_le16(att_table[end_indx]->att_hdl, buff + off); off += 2;
        put_unaligned_le16(p->att_type, buff + off); off += 2;
        hgic_iwpriv_blenc_send_gatt_data("wlan0", buff, off);
    } else {
        printf("==>ATT_NOT_FOUND: start_hdl=0x%x, end_hdl=0x%x, att_type=0x%x\r\n", start_hdl, end_hdl, group_type);
        hgics_gatt_send_ATT_ERROR(0x10, start_hdl, 0x0a);
    }
}

static void hgics_recv_ble_gatt_data(char *data, int len)
{
    unsigned char opcode = data[0];
    switch (opcode) {
        case 0x02: //EXCHANGE_MTU_REQ
            hgics_gatt_EXCHANGE_MTU_RSP(get_unaligned_le16(data + 1));
            break;
        case 0x04: //FIND_INFORMATION_REQ
            hgics_gatt_FIND_INFORMATION_REQ(get_unaligned_le16(data + 1),
                                            get_unaligned_le16(data + 3));
            break;
        case 0x06: //FIND_BY_TYPE_VALUE_REQ
            printf("==>FIND_BY_TYPE_VALUE_REQ: not support\r\n");
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
        case 0x08: //READ_BY_TYPE_REQ
            hgics_gatt_READ_BY_TYPE_REQ(get_unaligned_le16(data + 1),
                                        get_unaligned_le16(data + 3),
                                        get_unaligned_le16(data + 5));
            break;
        case 0x0A: //READ_REQ
            hgics_gatt_READ_REQ(get_unaligned_le16(data + 1));
            break;
        case 0x0C: //READ_BLOB_REQ
            printf("==>READ_BLOB_REQ: not support\r\n");
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
        case 0x0e: //READ_MULTIPLE_REQ
            printf("==>READ_MULTIPLE_REQ: not support\r\n");
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
        case 0x10: // READ_BY_GROUP_TYPE_REQ
            hgics_gatt_READ_BY_GROUP_TYPE_REQ(get_unaligned_le16(data + 1),
                                              get_unaligned_le16(data + 3),
                                              get_unaligned_le16(data + 5));
            break;
        case 0x12: // WRITE_REQ
            hgics_gatt_WRITE(get_unaligned_le16(data + 1), data + 3, len - 3, 0x12 | (1 << 8));
            break;
        case 0x16: // PREPARE_WRITE_REQ
            printf("==>PREPARE_WRITE_REQ: not support\r\n");
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
        case 0x18: // EXECUTE_WRITE_REQ
            printf("==>EXECUTE_WRITE_REQ: not support\r\n");
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
        case 0x52: //WRITE_CMD
            hgics_gatt_WRITE(get_unaligned_le16(data + 1), data + 3, len - 3, 0x52);
            break;
        case 0xD2: //SIGNED_WRITE_CMD
            printf("==>SIGNED_WRITE_CMD: not support\r\n");
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
        default:
            printf("==>unknow opcode: %x: not support\r\n", opcode);
            hgics_gatt_send_ATT_ERROR(opcode, get_unaligned_le16(data + 1), 0x06);
            break;
    }
}

static void hgics_recv_l2cap_data(char type, char *data, int len)
{
    if (get_unaligned_le16(data + 2) /*L2CAP CID*/ == 0x4) {
        hgics_dump_hex("\r\nRECV:\r\n", data + BT_L2CAP_HDR_SIZE, len - BT_L2CAP_HDR_SIZE, 1);
        hgics_recv_ble_gatt_data(data + BT_L2CAP_HDR_SIZE, len - BT_L2CAP_HDR_SIZE);
    }
}

static void hgics_recv_ble_event(char *data, int len)
{
    switch (data[2]) {
        case 0x1:
            printf("BLE Connected\r\n");
            break;
    }
}

static void hgics_recv_bt_event(char *data, int len)
{
    printf("rx BT event: 0x%x\r\n", data[0]);
    switch (data[0]) {
        case 0x05:
            printf("Disconnect\r\n");
            break;
        case 0x3e:
            hgics_recv_ble_event(data, len);
            break;
    }
}

void hgics_proc_bt_data(char *data, int len)
{
    extern struct hgic_fw_info hgics_fwinfo;
    struct hgic_ctrl_hdr *hdr = (struct hgic_ctrl_hdr *)data;

    data += sizeof(struct hgic_ctrl_hdr);
    len  -= sizeof(struct hgic_ctrl_hdr);
    switch (hdr->hci.type) {
        case 0x02: // ACL data
            if (hgics_fwinfo.version > 0x02040000) {
                data += sizeof(struct bt_rx_info);
                len  -= sizeof(struct bt_rx_info);
            }

            data += HCI_ACL_HDR_SIZE;
            len  -= HCI_ACL_HDR_SIZE;
            //hgics_dump_hex("BT ACL DATA:\r\n", data, len, 1);
            hgics_recv_l2cap_data(hdr->hci.type, data, len);
            break;
        case 0x04: // Event
            hgics_recv_bt_event(data, len);
            break;
    }
}

