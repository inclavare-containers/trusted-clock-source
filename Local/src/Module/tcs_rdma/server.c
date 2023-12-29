#include "common.h"
int main(int argc, char *argv[])
{
    
    config_t config;
    config.dev_name = "mlx5_0";
    config.ib_port = 1;
    config.cq_size = 1;
    config.mr_size = 1024;
    config.mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    config.qp_send_size = 1;
    config.qp_recv_size = 1;

    config.server_name = NULL;
    config.gid_idx = 0;
    config.mk_step = 16;
    config.mk_modulo = 64;
    config.pack_num = 2000;
    int port = 19875;

    if(argc > 1)
    {
        sscanf(argv[1], "%d", &port);
    }
    if(argc > 2)
    {
        sscanf(argv[2], "%d", &config.pack_num);
    }
    // printf("port = %d", port);
    server_main(&config, port, 1);

}