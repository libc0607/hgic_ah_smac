/**
  ******************************************************************************
  * @file    hgics.c
  * @author  HUGE-IC Application Team
  * @version V1.0.0
  * @date    2022-05-18
  * @brief   hgic smac driver daemon.
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

#include "iwpriv.c"

#define AUTO_RELAY_EN 1
#define BELNC_EN 1

struct hgic_fw_info hgics_fwinfo;

unsigned long hgics_fls(int x)
{
    int r = 32;

    if (!x) {
        return 0;
    }

    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}



void hgics_strcpy(char *dest, char *src, int cnt)
{
    int i = 0;
    while (*src && *src != '\r' && *src != '\n') {
        *dest++ = *src++;
        if (cnt && ++i >= cnt) {
            break;
        }
    }
    *dest = 0;
}

char *hgics_strchr(char *str, char s, int index)
{
    int i = 0;

    while (*str && i != index) {
        if (*str == s) {
            i++;
        }
        str++;
    }

    return (i && i == index) ? str : NULL;
}

int hgics_do_system(char *cmd, char *buff, int size)
{
    int ret  = 0;
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    while (ret < size && fgets(buff + ret, size - ret, fp) != NULL) {
        ret = strlen(buff);
    }

    buff[ret] = 0;
    pclose(fp);
    return strlen(buff);
}

//////////////////////////////////////////////////////////////////////////////////////////////////

static void hgics_parse_blenc_param(u8 *data, int len)
{
    u8 *ptr = data;

#if 1 //sample code
    u8 buff[33];
    u8 cmd[64];
    while (ptr < data + len) {
        switch (ptr[0]) {
            case 1: //SSID
                memset(buff, 0, sizeof(buff));
                memcpy(buff, ptr + 2, ptr[1]);
                printf("SET ssid:%s\r\n", buff);
                sprintf(cmd, "nvram_set ah_ssid %s", buff);
                system(cmd);
                break;
            case 2: //PassWord
                memset(buff, 0, sizeof(buff));
                memcpy(buff, ptr + 2, ptr[1]);
                printf("SET passwd:%s\r\n", buff);
                sprintf(cmd, "nvram_set ah_psk %s", buff);
                system(cmd);
                break;
            case 3: //Keymgmt
                printf("SET keymgmt %s\r\n", ptr[2] ? "WPA-PSK" : "NONE");
                sprintf(cmd, "nvram_set ah_key_mgmt %s", ptr[2] ? "WPA-PSK" : "NONE");
                system(cmd);
                break;
            case 4: //auth
                printf("AUTH %d\r\n", ptr[2]);
                sprintf(cmd, "ifconfig wlan0 %s", ptr[2] ? "up" : "down");
                system(cmd);
                break;
            default:
                printf("Unsupport ID:%d\r\n", ptr[0]);
                break;
        }
        ptr += (ptr[1] + 2);
    }

    hgic_blenc_release();
    hgic_iwpriv_blenc_start("wlan0", 0, 38);
    //restart hostapd or wpa_supplicant
    system("hgic2g.sh");
#endif
}

/*hgic demo protocol*/
static void hgics_recv_blenc_data(uint8 *data, uint32 len)
{
    uint8 *ncdata = NULL;
    uint32 data_len = 0;

    hgics_dump_hex("BLE DATA:\r\n", data, len, 1);
    if (hgic_blenc_parse_data(data, len)) {
        data_len = hgic_blenc_get_data(&ncdata);
        if (data_len && ncdata) {
            hgics_parse_blenc_param(ncdata, data_len);
        }
    }
}

/* customer protocol
   data: BLE PDU data
   len:  data length
*/
static void hgics_recv_customer_ble_data(u8 *data, int len)
{
}

static void hgics_proc_fwevent(u8 *event_data, u32 event_len)
{
    u32   data_len = 0;
    u32   evt_id   = 0;
    char *data     = NULL;
    struct hgic_ctrl_hdr *evt = (struct hgic_ctrl_hdr *)event_data;

    data     = (char *)(evt + 1);
    data_len = event_len - sizeof(struct hgic_ctrl_hdr);
    evt_id   = HDR_EVTID(evt);

    switch (evt_id) {
        case HGIC_EVENT_BLENC_DATA:
#if 1 /*hgic demo protocol*/            
            hgics_recv_blenc_data(data, data_len);
#else 
            /*customer protocol*/            
            hgics_recv_customer_ble_data(data, data_len);
#endif
            break;
        case HGIC_EVENT_HWSCAN_RESULT:
#if AUTO_RELAY_EN
            hgics_relay_check_hwscan_result(data, data_len);
#endif
            break;
    }
}


int main(int argc, char *argv[])
{
    int i = 0;
    int ret = 0;
    int fd  = -1;
    u8 *buff = malloc(4096);
    struct hgic_hdr *hdr;
    char *ssid = NULL;
    int wifi_mode = 0;

    HGIC = "hgics";

    if (buff == NULL) {
        printf("malloc fail\r\n");
        return -1;
    }

    if (argc > 1) {
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "sta") == 0) {
                wifi_mode = 0;
            } else if (strcmp(argv[i], "ap") == 0) {
                wifi_mode = 1;
            } else if (strcmp(argv[i], "apsta") == 0) {
                wifi_mode = 2;
            } else {
                ssid = argv[i];
            }
        }
    }

    hgic_blenc_init();

#if AUTO_RELAY_EN //sample code
    hgics_relay_init(ssid, wifi_mode);
    if (wifi_mode == 2) {
        system("brctl delif br0 eth2");
        system("brctl addif br0 wlan0");
        system("brctl addif br0 wlan1");
        system("ifconfig br0 192.168.1.30");
        system("ifconfig eth2 10.10.10.30");
    }
#endif

__open:
    fd = open("/proc/hgics/fwevnt", O_RDONLY);
    if (fd == -1) {
        sleep(1);
        goto __open;
    }

    //get firmware version
    hgic_iwpriv_get_fwinfo("wlan0", &hgics_fwinfo);
    printf("fw version: %x\r\n", hgics_fwinfo.version);

#if 1 //BLE test code
    do {
        blenc_mode = 3; /*1:广播配网，2:广播配网,支持扫描, 3: BLE协议连接配网*/
        u8 scan_resp[] = {0x04, 0x09, 0x53, 0x53, 0x53,0x19, 0xFF, 0xD0, 0x07, 0x01, 0x03, 0x00, 0x00, 0x0C, 0x00, 0x88, 0xD1, 0xC4, 0x89, 0x2B, 0x56, 0x7D, 0xE5, 0x65, 0xAC, 0xA1, 0x3F, 0x09, 0x1C, 0x43, 0x92};
        u8 adv_data[] = {0x02, 0x01, 0x06,0x03, 0x02, 0x01, 0xA2, 0x14, 0x16, 0x01, 0xA2, 0x01, 0x6B, 0x65, 0x79, 0x79, 0x66, 0x67,0x35, 0x79, 0x33, 0x34, 0x79, 0x71, 0x78, 0x71, 0x67, 0x64};
        //u8 scan_resp[] = {0x04, 0x09,0x5A, 0x5A, 0x5A, 0x19, 0xFF, 0xD0, 0x07, 0x01, 0x03, 0x00, 0x00, 0x0C, 0x00, 0x88, 0xD1, 0xC4, 0x89, 0x2B, 0x56, 0x7D, 0xE5, 0x65, 0xAC, 0xA1, 0x3F, 0x09, 0x1C, 0x43, 0x92};
        //u8 adv_data[] = {0x02, 0x01, 0x06, 0x03, 0x02, 0x01, 0xA2, 0x14, 0x16, 0x01, 0xA2, 0x01, 0x6B, 0x65, 0x79, 0x79, 0x66, 0x67, 0x35, 0x79, 0x33, 0x34, 0x79, 0x71, 0x78, 0x71, 0x67, 0x64};
        //u8 adv_data[] = {0x2,0x1,0x6,0x3,0x2,0x1,0xa2,0x14,0x16,0x1,0xa2,0x0,0x67,0x79,0x75,0x69,0x76,0x61,0x6d,0x33,0x35,0x6b,0x64,0x37,0x72,0x71,0x6c,0x6a};
        //u8 scan_resp[] = {0x3,0x9,0x54,0x59,0x19,0xff,0xd0,0x7,0x9,0x3,0x3,0x0,0xc,0x0,0x8f,0x61,0x62,0x4e,0x3f,0xe1,0x30,0x28,0x9a,0x73,0x17,0xb1,0xea,0x92,0x45,0x33};        
        u8 dev_addr[] = {0x00, 0x12, 0x34, 0x56, 0x78, 0x00};
        //hgic_iwpriv_blenc_set_devaddr("wlan0", dev_addr);
        hgic_iwpriv_blenc_set_advdata("wlan0", adv_data, sizeof(adv_data));
        hgic_iwpriv_blenc_set_scanresp("wlan0", scan_resp, sizeof(scan_resp));
        hgic_iwpriv_blenc_set_adv_interval("wlan0", 100);
        hgic_iwpriv_blenc_start_adv("wlan0", 1);
    } while (0);
#endif

    hdr = (struct hgic_hdr *)buff;
    while (1) {
        ret = read(fd, buff, 4096);
        if (ret > 0) {
            switch (hdr->type) {
                case HGIC_HDR_TYPE_EVENT:
                case HGIC_HDR_TYPE_EVENT2:
                    hgics_proc_fwevent(buff, ret);
                    break;
                case HGIC_HDR_TYPE_BLUETOOTH:
#if BELNC_EN
                    hgics_proc_bt_data(buff, ret);
#endif
                    break;
                default:
                    printf("unknown hdr type:%d\r\n", hdr->type);
                    break;
            }
        } else if (ret == 0) {
#if AUTO_RELAY_EN
            if(wifi_mode == 2){
                hgics_relay_check_status();
            }
#endif
        } else {
            printf("read ret=%d\r\n", ret);
            close(fd);
            goto __open;
        }
    }

    close(fd);
    free(buff);
    return 0;
}

