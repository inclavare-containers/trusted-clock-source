
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#define RANDOM_WINDOWS_LENGTH 8
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return bswap_64(x);
}
static inline uint64_t ntohll(uint64_t x)
{
    return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return x;
}
static inline uint64_t ntohll(uint64_t x)
{
    return x;
}
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

typedef struct __attribute__((packed)) _datapack_t

{
    uint64_t seq;
    uint64_t timestamp;
} datapack_t;

typedef struct __attribute__((packed)) _metadata_exch_t
{
    uint64_t addr;
    uint32_t rkey;
    uint32_t qpn;
    uint32_t mk_step;
    uint32_t mk_modulo;
    uint16_t lid;
    uint16_t mkrn;
    uint8_t gid[16];
} metadata_exch_t;

typedef int controlpath_t;

typedef struct _config_t
{
    const char *dev_name;
    int ib_port;
    int cq_size;
    int mr_size;
    int mr_flags;
    int qp_send_size;
    int qp_recv_size;
    char *server_name;
    int gid_idx;
    int mk_step;        //step of random access, must be larger than rdma write payload
    int mk_modulo;      //modulo of random access
    int sleep_us;       //for test
    int pack_num;       //for test
} config_t;

typedef struct _common_resource_t
{
    struct ibv_port_attr port_attr;
    struct ibv_context *ib_ctx;
    struct ibv_comp_channel *channel;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_mr *mr;
    char *buf;
    int ib_port;
} common_resource_t;

typedef struct _qp_resource_t
{
    common_resource_t *common_resource;
    struct ibv_qp *qp;
    int gid_idx;
    uint16_t mkrn;
    metadata_exch_t remote_exch;
    controlpath_t controlpath;
} qp_resource_t;

typedef struct _rn_queue_t
{
    int q[RANDOM_WINDOWS_LENGTH];
    int cur;
    uint16_t seed;
} rn_queue_t;

typedef struct _branch_param_t
{
    common_resource_t *res;
    config_t *config;
    controlpath_t controlpath;
    int index;
} branch_param_t;

int common_resource_init(common_resource_t *res, config_t *config);
int qp_resource_init(qp_resource_t *qp_res, common_resource_t *res, config_t *config);
void qp_resource_destroy(qp_resource_t *qp_res);
void common_resource_destroy(common_resource_t *res);
int sock_connect(const char *servername, int port);
int connect_qp(qp_resource_t *qp_res, config_t *config, controlpath_t controlpath, int addr_bias);
int post_write(qp_resource_t *qp_res, char *message, int length, int bias);
int poll_completion(qp_resource_t *qp_res);
int rn_init(rn_queue_t *rn_queue, uint16_t seed);
int rn_gen(rn_queue_t *rn_queue, int modulo);
int client_check_arrival(qp_resource_t *qp_res, rn_queue_t *rn_queue, datapack_t *datapack, datapack_t *prev, config_t *config, int addr_bias, int sleepus);
uint64_t get_us_time();
void encode_datapack(datapack_t *datapack, char *buffer);
void decode_datapack(datapack_t *datapack, char *buffer);
void server_main(config_t *config, uint32_t listen_port, int max_client_count);
void client_main(config_t *config, char **server_name_list, uint32_t* port_list, int server_count);
void *server_branch(void *param);
void *client_branch(void *param);