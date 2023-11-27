#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>

#define UEVENT_BUFFER_SIZE 1024

#define USB_DEV_INFO_PATH           "/sys/bus/usb/devices"
#define SDIO_DEV_INFO_PATH          "/sys/bus/sdio/devices"
#define CMD_RECV_BUF_SIZE 1024

#define ERR_ARG         -2
#define ERR_NONE        -1
#define RET_SUCCESS      0

#define DEV_TYPE_USB     1
#define DEV_TYPE_SDIO    2
#define DEV_TYPE_UNKNOW  3

//#define DEV_DEBUG_PRINTF
#ifdef HUIC_UEVENT_DEBUG_PRINTF
#define HUIC_UEVENT_DEBUG printf
#else
#define	HUIC_UEVENT_DEBUG(...) do{}while(0);
#endif

#define HUIC_UEVENT_CONFIG_PARA_LEN 128
#define DEFAULT_CONFIG_SCRIPT_NAME "s1gstart.sh"

static char script_name[HUIC_UEVENT_CONFIG_PARA_LEN] = {0};

static int hgic_uevent_read_config_file(const char *path)
{
    FILE *fp_config;
    char result_buf[HUIC_UEVENT_CONFIG_PARA_LEN];
    char* script_name_ptr = NULL;
    int  script_name_length = 0;
    if (path == NULL)
    {
        //printf("Config file path is NULL!\n");
        return ERR_ARG;
    }

    fp_config = fopen(path, "r");
    if (fp_config == NULL)
    {
        //printf("Config file read error!\n");
	//perror("fopen error\n");
        return ERR_ARG;
    }

    while (fgets(result_buf, sizeof(result_buf), fp_config) != NULL)
    {
        if (NULL != strstr(result_buf, "script_name:"))
        {
	        script_name_ptr = strrchr(result_buf,':');
	        if(script_name_ptr != NULL)
	        {
	    	    script_name_ptr ++;
				if(script_name_ptr == NULL || script_name_ptr == '\0')
				{
					if (fp_config != NULL)
                	{
                    	fclose(fp_config);
                	}
					return ERR_NONE;
				}
	    	    script_name_length = strlen(script_name_ptr);
                memcpy(script_name, script_name_ptr, script_name_length);
                HUIC_UEVENT_DEBUG("script name found:%s,len:%d\n", script_name,script_name_length);
	    	    if (fp_config != NULL)
                {
                    fclose(fp_config);
                }
                return RET_SUCCESS;
	        }
	        else
            {
                if (fp_config != NULL)
                {
                    fclose(fp_config);
                }
		        HUIC_UEVENT_DEBUG("script name not found\n");
                return ERR_NONE;
	        }
        }
    }
    if (fp_config != NULL)
    {
        fclose(fp_config);
    }
    HUIC_UEVENT_DEBUG("Script name not found!\n");
    return ERR_NONE;
}

static int hgic_uevent_init_hotplug_sock()
{
    const int buffersize = 1024;
    int ret;

    struct sockaddr_nl snl;
    bzero(&snl, sizeof(struct sockaddr_nl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = getpid();
    snl.nl_groups = 1;

    int s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (s == -1)
    {
        perror("socket");
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buffersize, sizeof(buffersize));

    ret = bind(s, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl));
    if (ret < 0)
    {
        perror("bind");
        close(s);
        return -1;
    }

    return s;
}

static int hgic_uevent_cmd_system_result(const char *command, const char *search_str)
{
    FILE *fp_read;
    char result_buf[CMD_RECV_BUF_SIZE] = {0};

    if (command == NULL || search_str == NULL)
    {
        return ERR_ARG;
    }

    memset(result_buf, 0, sizeof(result_buf));
    fp_read = popen(command, "r");

    if (fp_read == NULL)
    {
        //printf("Error:popen() Error!\n");
        return ERR_ARG;
    }

    while (fgets(result_buf, sizeof(result_buf), fp_read) != NULL)
    {
        if (NULL != strstr(result_buf, search_str))
        {
            if (fp_read != NULL)
            {
                fclose(fp_read);
            }
            HUIC_UEVENT_DEBUG("Cmd Responce found!\n");
            return RET_SUCCESS;
        }
    }
    if (fp_read != NULL)
    {
        fclose(fp_read);
    }
    HUIC_UEVENT_DEBUG("Cmd Responce not found!\n");
    return ERR_NONE;

}

static int hgic_uevent_parse_dev_from_netlink_recvbuf(const char *input)
{
    int device  = ERR_NONE;
    int cmd_ret = -1;

    char *dev_pos = NULL;
    char dev_path[400];
    char dev_info_full_path[500];

    if (NULL == input)
    { 
        return ERR_ARG;
    }
    if (NULL == strstr(input, "add@"))
    { 
        return ERR_NONE;
    }

    if (strstr(input, "usb") != NULL)
    {
        device = DEV_TYPE_USB;
    } 
    else if (strstr(input, "mmc") != NULL)
    {   
        device = DEV_TYPE_SDIO;
    }
    else
    {
        //printf("Unknow device type:%s\n", input);
        return DEV_TYPE_UNKNOW;
    }

    HUIC_UEVENT_DEBUG("check input:%s\n", input);

    memset(dev_path, 0, sizeof(dev_path));

    if (device == DEV_TYPE_USB)
    {
        strcpy(dev_path, USB_DEV_INFO_PATH);
        dev_pos = strrchr(input, '/');
        if (dev_pos == NULL)
        {
            //printf("dev_pos null\n");
            return ERR_NONE;
        }
        strcat(dev_path, dev_pos);
        sprintf(dev_info_full_path, "cat %s/uevent", dev_path);
        printf("dev_info_full_path:%s\n", dev_info_full_path);

        if (RET_SUCCESS == hgic_uevent_cmd_system_result(dev_info_full_path, "PRODUCT=a012")
            || RET_SUCCESS == hgic_uevent_cmd_system_result(dev_info_full_path, "PRODUCT=A012"))
        {
            HUIC_UEVENT_DEBUG("Hgic USB device found!!!\n");
            return DEV_TYPE_USB;
        }
        else
        { 
            return DEV_TYPE_UNKNOW;
        }
    } 
    else
    {
        strcpy(dev_path, SDIO_DEV_INFO_PATH);
        dev_pos = strrchr(input, '/');
        if (dev_pos == NULL)
        {
            //printf("dev_pos null\n");
            return ERR_NONE;
        }
        strcat(dev_path, dev_pos);
        sprintf(dev_info_full_path, "cat %s/uevent", dev_path);
        printf("dev_info_full_path:%s\n", dev_info_full_path);
        //cmd_ret = cmd_system_result(dev_info_full_path, "SDIO_ID=A012:6001");
        if (RET_SUCCESS == hgic_uevent_cmd_system_result(dev_info_full_path, "SDIO_ID=A012")
            || RET_SUCCESS == hgic_uevent_cmd_system_result(dev_info_full_path, "SDIO_ID=a012"))
        {
            HUIC_UEVENT_DEBUG("Hgic SDIO device found!!!\n");
            return DEV_TYPE_SDIO;
        } 
        else
        { 
            return DEV_TYPE_UNKNOW;
        }
    }
}

int main(int argc, char *argv[])
{
    int hotplug_sock = hgic_uevent_init_hotplug_sock();

    signal(SIGCHLD, SIG_IGN);

    while (1)
    {
        /* Netlink message buffer */
        char buf[UEVENT_BUFFER_SIZE * 2] = {0};
        recv(hotplug_sock, &buf, sizeof(buf), 0);
        int err_ret = 0;

        err_ret = hgic_uevent_parse_dev_from_netlink_recvbuf(buf);
        if (err_ret != DEV_TYPE_SDIO && err_ret != DEV_TYPE_USB)
        {
            //printf("Not Hgic sdio or usb device\n");
        }
        else
        {
            if (RET_SUCCESS == hgic_uevent_read_config_file("/etc_ro/hguevent_config.txt"))
            {
                printf("do %s\r\n", script_name);
                err_ret = system(script_name);
                if (err_ret < 0 || err_ret == 127)
                {
                    //printf("Run command error!\n");
                }
            }
            else
            {
                printf("do %s\r\n", DEFAULT_CONFIG_SCRIPT_NAME);
                err_ret = system(DEFAULT_CONFIG_SCRIPT_NAME);
                if (err_ret < 0 || err_ret == 127)
                {
                    //printf("Run command error!\n");
                }
            }
        }
    }
    return 0;
}

