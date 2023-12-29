
#include "common.h"


/******************************************************************************
* Function: common_resource_init
*
* Input: cr pointer to common_resource to be initialized
*
* Output: 
*
* Returns: 0 on success
*
* Description: Open device and initialize mr, cq
* 
*
*****************************************************************************/
int common_resource_init(common_resource_t *res, config_t *config)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_device *ib_dev = NULL;
    int i;
    int num_devices;
    int rc = 0;
    
    dev_list = ibv_get_device_list(&num_devices);
    if(!dev_list)
    {
        fprintf(stderr, "failed to get IB devices list\n");
        rc = 1;
        goto common_resource_init_exit;
    }
    if(!num_devices)
    {
        fprintf(stderr, "found %d device(s)\n", num_devices);
        rc = 1;
        goto common_resource_init_exit;
    }
    // fprintf(stdout, "found %d device(s)\n", num_devices);
    for(i = 0; i < num_devices; i ++)
    {
        if(!config->dev_name)
        {
            config->dev_name = strdup(ibv_get_device_name(dev_list[i]));
            fprintf(stdout, "device not specified, using first one found: %s\n", config->dev_name);
        }
        /* find the specific device */
        if(!strcmp(ibv_get_device_name(dev_list[i]), config->dev_name))
        {
            ib_dev = dev_list[i];
            break;
        }
    }
    if(!ib_dev)
    {
        fprintf(stderr, "IB device %s wasn't found\n", config->dev_name);
        rc = 1;
        goto common_resource_init_exit;
    }
    res->ib_ctx = ibv_open_device(ib_dev);
    if(!res->ib_ctx)
    {
        fprintf(stderr, "failed to open device %s\n", config->dev_name);
        rc = 1;
        goto common_resource_init_exit;
    }
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;
    // port_attr
    res->ib_port = config->ib_port;
    if(ibv_query_port(res->ib_ctx, res->ib_port, &res->port_attr))
    {
        fprintf(stderr, "ibv_query_port on port %u failed\n", res->ib_port);
        rc = 1;
        goto common_resource_init_exit;
    }
    // pd
    res->pd = ibv_alloc_pd(res->ib_ctx);
    if(!res->pd)
    {
        fprintf(stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        goto common_resource_init_exit;
    }
    // comp_channel
    res->channel = ibv_create_comp_channel(res->ib_ctx);
    if (!res->channel) {
        fprintf(stderr, "failed to create completion channel\n");
        rc = 1;
        goto common_resource_init_exit;
    }
    // cq
    res->cq = ibv_create_cq(res->ib_ctx, config->cq_size, NULL, NULL, 0);
    if(!res->cq)
    {
        fprintf(stderr, "failed to create CQ with %u entries\n", config->cq_size);
        rc = 1;
        goto common_resource_init_exit;
    }
    // mr
    res->buf = (char *) malloc(config->mr_size);
    if(!res->buf)
    {
        fprintf(stderr, "failed to malloc %u bytes to memory buffer\n", config->mr_size);
        rc = 1;
        goto common_resource_init_exit;
    }
    memset(res->buf, 0 , config->mr_size);
    res->mr = ibv_reg_mr(res->pd, res->buf, config->mr_size, config->mr_flags);
    if(!res->mr)
    {
        fprintf(stderr, "ibv_reg_mr failed with mr_flags=0x%x\n", config->mr_flags);
        rc = 1;
        goto common_resource_init_exit;
    }

    common_resource_init_exit:
    
    if(rc)
    {
        /* Error encountered, cleanup */
        common_resource_destroy(res);
        if(dev_list)
        {
            ibv_free_device_list(dev_list);
            dev_list = NULL;
        }
    }
    return rc;

}

int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;
    rc = write(sock, local_data, xfer_size);
 
    if(rc < xfer_size)
    {
        fprintf(stderr, "Failed writing data during sock_sync_data\n");
    }
    else
    {
        rc = 0;
    }
 
    while(!rc && total_read_bytes < xfer_size)
    {
        read_bytes = read(sock, remote_data, xfer_size);
        if(read_bytes > 0)
        {
            total_read_bytes += read_bytes;
        }
        else
        {
            rc = read_bytes;
        }
    }
    return rc;
}

int sock_connect(const char *servername, int port)
{
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;
    struct addrinfo hints =
    {
        .ai_flags    = AI_PASSIVE,
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_STREAM
    };
 
    if(sprintf(service, "%d", port) < 0)
    {
        goto sock_connect_exit;
    }
 
    /* Resolve DNS address, use sockfd as temp storage */
    sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);
    if(sockfd < 0)
    {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd), servername, port);
        goto sock_connect_exit;
    }
 
    /* Search through results and find the one we want */
    for(iterator = resolved_addr; iterator ; iterator = iterator->ai_next)
    {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
        if(sockfd >= 0)
        {
            if(servername)
			{
                /* Client mode. Initiate connection to remote */
                if((tmp=connect(sockfd, iterator->ai_addr, iterator->ai_addrlen)))
                {
                    fprintf(stdout, "failed connect \n");
                    close(sockfd);
                    sockfd = -1;
                }
			}
            else
            {
                /* Server mode. Set up listening socket an accept a connection */
                listenfd = sockfd;
                sockfd = -1;
                if(bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
                {
                    goto sock_connect_exit;
                }
                listen(listenfd, 1);
                sockfd = accept(listenfd, NULL, 0);
            }
        }
    }
 
    sock_connect_exit:
    if(listenfd)
    {
        close(listenfd);
    }
 
    if(resolved_addr)
    {
        freeaddrinfo(resolved_addr);
    }
 
    if(sockfd < 0)
    {
        if(servername)
        {
            fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        }
        else
        {
            perror("server accept");
            fprintf(stderr, "accept() failed\n");
        }
    }
 
    return sockfd;
}

int qp_resource_init(qp_resource_t *qp_res, common_resource_t *res, config_t *config)
{
    int rc = 0;
    struct ibv_qp_init_attr qp_init_attr;
    qp_res->gid_idx = config->gid_idx;
    qp_res->common_resource = res;
    memset(&qp_init_attr, 0, sizeof qp_init_attr);
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = res->cq;
    qp_init_attr.recv_cq = res->cq;
    qp_init_attr.cap.max_send_wr = config->qp_send_size;
    qp_init_attr.cap.max_recv_wr = config->qp_recv_size;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    qp_res->qp = ibv_create_qp(res->pd, &qp_init_attr);
    if(!qp_res->qp)
    {
        fprintf(stderr, "failed to create QP\n");
        rc = 1;
    }
    if(rc)
    {
        if(qp_res->qp)
        {
            ibv_destroy_qp(qp_res->qp);
        }
    }
    
    qp_res->mkrn = (uint16_t)(rand());
    return rc;
}

void qp_resource_destroy(qp_resource_t *qp_res)
{
    if(qp_res)
    {
        if(qp_res->qp)
        {
            ibv_destroy_qp(qp_res->qp);
            qp_res = NULL;
        }
        // if(qp_res->sockfd>0)
        // {
        //     if(close(qp_res->sockfd))
        //     {
        //         fprintf(stderr, "failed to close socket\n");
        //     }
        // }
    }
}

static int modify_qp_to_init(qp_resource_t *qp_res)
{
    struct ibv_qp *qp = qp_res->qp;
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = qp_res->common_resource->ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    rc = ibv_modify_qp(qp, &attr, flags);
    if(rc)
    {
        fprintf(stderr, "failed to modify QP state to INIT\n");
    }
    return rc;
}
 
static int modify_qp_to_rtr(qp_resource_t *qp_res, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid)
{
    struct ibv_qp *qp = qp_res->qp;
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = qp_res->common_resource->ib_port;
    if(qp_res->gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = qp_res->gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }
 
    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    rc = ibv_modify_qp(qp, &attr, flags);
    if(rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
    }
    return rc;
}
 
static int modify_qp_to_rts(qp_resource_t *qp_res)
{
    struct ibv_qp *qp = qp_res->qp;
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    rc = ibv_modify_qp(qp, &attr, flags);
    if(rc)
    {
        fprintf(stderr, "failed to modify QP state to RTS\n");
    }
    return rc;
}

void common_resource_destroy(common_resource_t *res)
{
    if(res)
    {
        if(res->mr)
        {
            ibv_dereg_mr(res->mr);
            res->mr = NULL;
        }
        if(res->buf)
        {
            free(res->buf);
            res->buf = NULL;
        }
        if(res->cq)
        {
            ibv_destroy_cq(res->cq);
            res->cq = NULL;
        }
        if(res->channel)
        {
            ibv_destroy_comp_channel(res->channel);
            res->channel = NULL;
        }
        if(res->pd)
        {
            ibv_dealloc_pd(res->pd);
            res->pd = NULL;
        }
        if(res->ib_ctx)
        {
            ibv_close_device(res->ib_ctx);
            res->ib_ctx = NULL;
        }

    }
}

int connect_tcp(int *sockfd, char* server_name, uint32_t tcp_port)
{
    int rc = 0;
    if(server_name)
    {
        *sockfd = sock_connect(server_name, tcp_port);
        if(*sockfd < 0)
        {
            fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n",
                    server_name, tcp_port);
            rc = -1;
        }
    }
    else
    {
        // fprintf(stdout, "waiting on port %d for TCP connection\n", tcp_port);
        *sockfd = sock_connect(NULL, tcp_port);
        if(*sockfd < 0)
        {
            fprintf(stderr, "failed to establish TCP connection with client on port %d\n",
                    tcp_port);
            rc = -1;
        }
    }

    return rc;
}

int connect_qp(qp_resource_t *qp_res, config_t *config, controlpath_t controlpath, int addr_bias)
{
    common_resource_t *res = qp_res->common_resource;
    metadata_exch_t local_exch;
    metadata_exch_t remote_exch;
    metadata_exch_t tmp_exch;
    union ibv_gid my_gid;
    int rc = 0;
    char temp_char;

    if(qp_res->gid_idx >= 0)
    {
        rc = ibv_query_gid(res->ib_ctx, res->ib_port, qp_res->gid_idx, &my_gid);
        if(rc)
        {
            fprintf(stderr, "could not get gid for port %d, index %d\n", res->ib_port, qp_res->gid_idx);
            goto connect_qp_exit;
        }
    }
    else
    {
        memset(&my_gid, 0, sizeof my_gid);
    }

    local_exch.addr = htonll((uintptr_t)(res->buf + addr_bias));
    local_exch.rkey = htonl(res->mr->rkey);
    local_exch.qpn = htonl(qp_res->qp->qp_num);
    local_exch.mk_step = htonl(config->mk_step);
    local_exch.mk_modulo = htonl(config->mk_modulo);
    local_exch.lid = htons(res->port_attr.lid);
    local_exch.mkrn = htons(qp_res->mkrn);

    
    memcpy(local_exch.gid, &my_gid, 16);
    // fprintf(stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);
    
    if(sock_sync_data(controlpath, sizeof(metadata_exch_t), (char *) &local_exch, (char *) &tmp_exch) < 0)
    {
        fprintf(stderr, "failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }

    remote_exch.addr = ntohll(tmp_exch.addr);
    remote_exch.rkey = ntohl(tmp_exch.rkey);
    remote_exch.qpn = ntohl(tmp_exch.qpn);
    remote_exch.mk_step = htonl(tmp_exch.mk_step);
    remote_exch.mk_modulo = htonl(tmp_exch.mk_modulo);
    remote_exch.lid = ntohs(tmp_exch.lid);
    remote_exch.mkrn = ntohs(tmp_exch.mkrn);

    memcpy(remote_exch.gid, tmp_exch.gid, 16);

    qp_res->remote_exch = remote_exch;

    qp_res->mkrn = qp_res->mkrn ^ qp_res->remote_exch.mkrn;
    qp_res->remote_exch.mkrn = 0;

    /***
    fprintf(stdout, "Local address = 0x%"PRIx64"\n", (uintptr_t)res->buf);
    fprintf(stdout, "Local rkey = 0x%x\n", res->mr->rkey);
    fprintf(stdout, "Local QP number = 0x%x\n", qp_res->qp->qp_num);
    fprintf(stdout, "Local LID = 0x%x\n", res->port_attr.lid);
    fprintf(stdout, "Local MKRN = 0x%x\n", qp_res->mkrn);
    if(config->gid_idx >= 0)
    {
        uint8_t *p = local_exch.gid;
        fprintf(stdout, "Local GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }

    fprintf(stdout, "Remote address = 0x%"PRIx64"\n", remote_exch.addr);
    fprintf(stdout, "Remote rkey = 0x%x\n", remote_exch.rkey);
    fprintf(stdout, "Remote QP number = 0x%x\n", remote_exch.qpn);
    fprintf(stdout, "Remote LID = 0x%x\n", remote_exch.lid);
    if(config->gid_idx >= 0)
    {
        uint8_t *p = remote_exch.gid;
        fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    ***/

    rc = modify_qp_to_init(qp_res);
    if(rc)
    {
        fprintf(stderr, "change QP state to INIT failed\n");
        goto connect_qp_exit;
    }
 
    /* modify the QP to RTR */
    rc = modify_qp_to_rtr(qp_res, remote_exch.qpn, remote_exch.lid, remote_exch.gid);
    if(rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }
 
    /* modify the QP to RTS */
    rc = modify_qp_to_rts(qp_res);
    if(rc)
    {
        fprintf(stderr, "failed to modify QP state to RTS\n");
        goto connect_qp_exit;
    }
    // fprintf(stdout, "QP state was change to RTS\n");
    if(sock_sync_data(controlpath, 1, "Q", &temp_char))  /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error after QPs are were moved to RTS\n");
        rc = 1;
    }
    connect_qp_exit:
    // close(qp_res->sockfd);
    return rc;
}

int post_write(qp_resource_t *qp_res, char *message, int length, int bias)
{
    common_resource_t *res = qp_res->common_resource;
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;
    int rc;
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res->buf;
    sge.length = length;
    sge.lkey = res->mr->lkey;
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_WRITE;
    sr.send_flags = IBV_SEND_SIGNALED;
    memcpy(res->buf, message, length);
    sr.wr.rdma.remote_addr = qp_res->remote_exch.addr + bias;
    sr.wr.rdma.rkey = qp_res->remote_exch.rkey;
    rc = ibv_post_send(qp_res->qp, &sr, &bad_wr);
    if(rc)
    {
        fprintf(stderr, "failed to post SR\n");
    }
    else
    {
        // fprintf(stdout, "-> Message sent:%s\n", message);
    }
    return rc;
}

int poll_completion(qp_resource_t *qp_res)
{
    common_resource_t *res = qp_res->common_resource;
    struct ibv_wc wc;
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    int poll_result;
    int rc = 0;
    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    do
    {
        poll_result = ibv_poll_cq(res->cq, 1, &wc);
        gettimeofday(&cur_time, NULL);
        cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    }
    while((poll_result == 0) && ((cur_time_msec - start_time_msec) < 2000));
 
    if(poll_result < 0)
    {
        /* poll CQ failed */
        fprintf(stderr, "poll CQ failed\n");
        rc = 1;
    }
    else if(poll_result == 0)
    {
        /* the CQ is empty */
        fprintf(stderr, "completion wasn't found in the CQ after timeout\n");
        rc = 1;
    }
    else
    {
        /* CQE found */
        // fprintf(stdout, "-> completion was found in CQ with status 0x%x\n", wc.status);
        /* check the completion status (here we don't care about the completion opcode */
        if(wc.status != IBV_WC_SUCCESS)
        {
            fprintf(stderr, "got bad completion with status: 0x%x, vendor syndrome: 0x%x\n", 
					wc.status, wc.vendor_err);
            rc = 1;
        }
    }
    return rc;
}

int rn_init(rn_queue_t *rn_queue, uint16_t seed)
{
    int i;
    for(i = 0; i < RANDOM_WINDOWS_LENGTH; i++)
    {
        rn_queue->q[i] = -1;
    }
    rn_queue->cur = 0;
    rn_queue->seed = seed;
}

int rn_gen(rn_queue_t *rn_queue, int modulo)
{
    rn_queue->q[rn_queue->cur] = -1;
    int flag = 1;
    int rn;
    int i;
    while(flag)
    {
        flag = 0;
        srand(rn_queue->seed++);
        rn = rand() % modulo;

        for(i = 0; i < RANDOM_WINDOWS_LENGTH; i++)
        {
            if(rn_queue->q[i] == rn)
            {
                flag = 1;
                break;
            }
        }
    }
    
    rn_queue->q[rn_queue->cur] = rn;
    rn_queue->cur = (rn_queue->cur + 1) % RANDOM_WINDOWS_LENGTH;

    // for(i = 0; i < RANDOM_WINDOWS_LENGTH; i++)
    // {
    //     printf("%d ", rn_queue->q[i]);
    // }
    // printf("::%d %d\n", rn_queue->cur, rn);

    return rn;
}

/******************************************************************************
* Function: check_arrival_valid
*
* Input: pointers of datapack received, previous datapack, packet skipped
*
* Output: validation check for datapack received
*
* Returns: 1 on valid
*
* Description: check if the datapack is valid
* 
*
*****************************************************************************/

int check_arrival_valid(datapack_t *datapack, datapack_t *prev, int packet_skipped)
{
    if(prev)
    {
        return (datapack->seq == prev->seq + packet_skipped + 1)
            &&(datapack->timestamp > prev->timestamp)
            && (datapack->timestamp < prev->timestamp + 3000000);
    }
    else    // this datapack is the first received datapack
    {
        return datapack->timestamp > 10000000000;
    }
}

int client_check_arrival(qp_resource_t *qp_res, rn_queue_t *rn_queue, datapack_t *datapack, datapack_t *prev, config_t *config, int addr_bias, int sleepus)
{
    char buf[sizeof(datapack_t)+1];
    int i, j;
    int loop_cnt = 0;
    int cur;
    int modulo = config->mk_modulo;
    int bias;
    int step = config->mk_step;
    int init_flag = 0;
    if(rn_queue->q[0] == -1)    // initialize
    {
        for(i = 0; i < RANDOM_WINDOWS_LENGTH; i++)
            rn_gen(rn_queue, modulo);
        init_flag = 1;
    }
    cur = rn_queue->cur;
    uint64_t start = get_us_time();
    uint64_t now = start;
    while(now < start + 2000000)
    {
        for(i = 0; i < RANDOM_WINDOWS_LENGTH; i++)
        {
            
            bias = rn_queue->q[(cur + i) % RANDOM_WINDOWS_LENGTH] * step;
            
            // printf("--try listening to bias = %d\n", bias);
            memcpy(buf, qp_res->common_resource->buf + bias + addr_bias, step);
            decode_datapack(datapack, buf);
            if(check_arrival_valid(datapack, init_flag?NULL:prev, i))
            {
                printf("%ld, %ld, %ld, %ld, %d\n", datapack->seq, datapack->timestamp, get_us_time()-datapack->timestamp, loop_cnt?((now-start)/loop_cnt):0, loop_cnt);
                // printf("packet received with %d packets skipped\n", i);
                // printf("-> seq = %ld\n", datapack->seq);
                // printf("-> timestamp = %ld\n", datapack->timestamp);
                // printf("-> bias = %d\n", bias + addr_bias);
                for(j = 0; j <= i; j++)
                {
                    bias = rn_queue->q[rn_queue->cur] * step;
                    // printf("flushing bias = %d\n", bias);
                    memset(qp_res->common_resource->buf + bias + addr_bias, 0, step);
                    rn_gen(rn_queue, modulo);
                }
                memcpy(prev, datapack, sizeof(datapack_t));
                return 0;
            }
        }
        loop_cnt++;
        while(now < start + 2000000)
        {
            now = get_us_time();
            if(now - start >= sleepus*loop_cnt)
                break;
        }
    }
    return 1;
}

uint64_t get_us_time()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return ((uint64_t)t.tv_sec) * 1000000 + t.tv_usec; 
}

void encode_datapack(datapack_t* datapack, char* buffer)
{
    memcpy(buffer, datapack, sizeof(datapack_t));
}

void decode_datapack(datapack_t* datapack, char* buffer)
{
    memcpy(datapack, buffer, sizeof(datapack_t));
}

void server_main(config_t *config, uint32_t listen_port, int max_client_count)
{
    srand(time(NULL));
    common_resource_t res;
    controlpath_t controlpath;

    int thread_count_max = max_client_count, thread_count = 0;
    pthread_t *thread_handles;
    thread_handles =(pthread_t *)malloc(thread_count_max * sizeof(pthread_t));

    common_resource_init(&res, config);

    // while(1)
    // {
        if(connect_tcp(&controlpath, NULL, listen_port))
        {
            goto server_main_next;
        }
        branch_param_t *branch_param = malloc(sizeof(branch_param_t));
        branch_param->res = &res;
        branch_param->config = config;
        branch_param->controlpath = controlpath;
        pthread_create(&thread_handles[thread_count], NULL, server_branch, (void *)branch_param);
        // server_branch(&res, config, controlpath);
        thread_count++;
        
        
        server_main_next:
    //     break;
    // }
    pthread_join(thread_handles[0], NULL);
    // printf("thread ended\n");
    server_main_exit:

    common_resource_destroy(&res);
    
}

void *server_branch(void *param)
{
    branch_param_t* branch_param = (branch_param_t*) param;
    common_resource_t *res = branch_param->res;
    config_t *config = branch_param->config;
    controlpath_t controlpath = branch_param->controlpath;
    free(branch_param);
    rn_queue_t rn_queue;
    qp_resource_t qp_res;
    int bias = 0;
    qp_resource_init(&qp_res, res, config);

    if(connect_qp(&qp_res, config, controlpath, 0))
    {
        goto server_exit;
    }
    // printf("mkrn = %d\n", qp_res.mkrn);
    rn_init(&rn_queue, qp_res.mkrn);
    datapack_t datapack;
    datapack.seq = rand();
    datapack.timestamp = 0;
    char message[20] = "";
    for(int i=0;i<config->pack_num;i++)
    {

        bias = rn_gen(&rn_queue, qp_res.remote_exch.mk_modulo);
                
        // sprintf(message, "%ld", get_us_time());
        datapack.seq++;
        datapack.timestamp = get_us_time();
        encode_datapack(&datapack, message);
        
        
        if(rand() % 100 >= 0)
        {
            // printf("packet sent\n");
            // printf("%ld, %ld, %ld, ", datapack.seq, datapack.timestamp, get_us_time()-datapack.timestamp);
            post_write(&qp_res, message, sizeof(datapack_t), bias * qp_res.remote_exch.mk_step);
            // printf("%ld, ", get_us_time()-datapack.timestamp);
            poll_completion(&qp_res);
            // printf("%ld\n", get_us_time()-datapack.timestamp);
            
            usleep((rand()%2000) + 4000);
            
        }
        else
        {
            printf("this packet is assumed to be lost [x]\n");
            usleep(10000);
        }
        // printf("-> seq = %ld\n", datapack.seq);
        // printf("-> timestamp = %ld\n", datapack.timestamp);
        // printf("-> bias = %d\n\n\n", bias * 16);
    }
    server_exit:
    qp_resource_destroy(&qp_res);
}

void client_main(config_t *config, char **server_name_list, uint32_t* port_list, int server_count)
{
    srand(time(NULL));
    common_resource_t res;
    controlpath_t controlpath;
    pthread_t *thread_handles;
    thread_handles =(pthread_t *)malloc(server_count * sizeof(pthread_t));

    common_resource_init(&res, config);
    for(int i = 0; i < server_count; i++)
    {
        if(connect_tcp(&controlpath, server_name_list[i], port_list[i]))
        {
            goto client_main_next;
        }
        branch_param_t *branch_param = malloc(sizeof(branch_param_t));
        branch_param->res = &res;
        branch_param->config = config;
        branch_param->controlpath = controlpath;
        branch_param->index = i;
        pthread_create(&thread_handles[i], NULL, client_branch, (void *)branch_param);
        client_main_next:
        continue;
    }
    for(int i = 0; i < server_count; i++)
    {
        pthread_join(thread_handles[i], NULL);
        // printf("thread %d ended\n", i);
    }
    // if(connect_tcp(&controlpath, config))
    // {
    //     goto client_main_exit;
    // }
    // client_branch(&res, config, controlpath);

    client_main_exit:
    common_resource_destroy(&res);

}

void *client_branch(void *param)
{
    branch_param_t* branch_param = (branch_param_t*) param;
    common_resource_t *res = branch_param->res;
    config_t *config = branch_param->config;
    controlpath_t controlpath = branch_param->controlpath;
    int index = branch_param->index;
    int addr_bias = index * config->mk_step * config->mk_modulo;
    // printf("addr_bias = %d\n", addr_bias);
    free(branch_param);

    qp_resource_t qp_res;
    rn_queue_t rn_queue;
    datapack_t datapack, datapack_prev;

    qp_resource_init(&qp_res, res, config);

    if(connect_qp(&qp_res, config, controlpath, addr_bias))
    {
        goto client_exit;
    }
    // printf("mkrn = %d\n", qp_res.mkrn);
    rn_init(&rn_queue, qp_res.mkrn);
    // printf("client initialization finished\n");
    while(1)
    {
    
        if(client_check_arrival(&qp_res, &rn_queue, &datapack, &datapack_prev, config, addr_bias, config->sleep_us))
        {
            // printf("\n\n[x] thread %d receive arrival failed\n\n", index);
            break;
        }
        else
            // printf("-> thread index = %d\n\n", index);
        ;
    }
    client_exit:
    qp_resource_destroy(&qp_res);
}