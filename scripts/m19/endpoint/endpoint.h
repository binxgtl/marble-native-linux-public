#ifndef M19_ENDPOINT_H
#define M19_ENDPOINT_H

enum m19_endpoint_stage {
    M19_ENDPOINT_STAGE_LOAD = 0,
    M19_ENDPOINT_STAGE_SYMBOLS = 1,
    M19_ENDPOINT_STAGE_LOOKUP = 2,
    M19_ENDPOINT_STAGE_DESCRIPTOR = 3,
    M19_ENDPOINT_STAGE_RELEASE = 4,
};

enum m19_endpoint_status {
    M19_ENDPOINT_STATUS_OK = 0,
    M19_ENDPOINT_STATUS_LOAD = 1,
    M19_ENDPOINT_STATUS_SYMBOLS = 2,
    M19_ENDPOINT_STATUS_LOOKUP_NULL = 3,
    M19_ENDPOINT_STATUS_CLASS = 4,
    M19_ENDPOINT_STATUS_ASSOCIATE = 5,
    M19_ENDPOINT_STATUS_DESCRIPTOR = 6,
};

enum m19_endpoint_flag {
    M19_ENDPOINT_F_LOADED = 1u << 0,
    M19_ENDPOINT_F_SYMBOLS = 1u << 1,
    M19_ENDPOINT_F_FOUND = 1u << 2,
    M19_ENDPOINT_F_DESCRIPTOR = 1u << 3,
    M19_ENDPOINT_F_RELEASED = 1u << 4,
};

struct m19_endpoint_result {
    int status;
    int detail_errno;
    unsigned flags;
};

typedef void (*m19_endpoint_progress)(enum m19_endpoint_stage stage,
                                      unsigned flags,
                                      void *opaque);

int m19_endpoint_check(m19_endpoint_progress progress,
                       void *opaque,
                       struct m19_endpoint_result *result);

#endif
