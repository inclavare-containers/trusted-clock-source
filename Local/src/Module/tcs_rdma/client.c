#include "common.h"
int main(int argc, char *argv[])
{
    config_t config;
    config.dev_name = "mlx5_0";
    config.ib_port = 1;
    config.cq_size = 1;

    config.mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    config.qp_send_size = 1;
    config.qp_recv_size = 1;
    config.gid_idx = 0;
    config.mk_step = 16;
    config.mk_modulo = 64;
    config.sleep_us = 0;
    int server_count = 1;
    char **server_list = malloc(server_count * sizeof(char*));
    for(int i = 0; i < server_count; i++)
        {
            server_list[i] = malloc(20 * sizeof(char));
            
        }
    uint32_t port_list[2] = {19879, 19878};
    config.mr_size = config.mk_step * config.mk_modulo * server_count;
    
    if(argc > 2)
    {
        sscanf(argv[1], "%s", server_list[0]);
        sscanf(argv[2], "%d", &port_list[0]);
    }
    else{server_list[0] = "192.168.1.70";}
    if(argc > 3)
    {
        sscanf(argv[3], "%d", &config.sleep_us);
    }
    client_main(&config, server_list, port_list, server_count);
    free(server_list);
}