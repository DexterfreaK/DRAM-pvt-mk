#include <stdint.h>

#define PREPARE_TYPE_LEN    33
#define REQUEST_TYPE_LEN    33
#define PREPAREOK_TYPE_LEN  35
#define MYPREPAREOK_TYPE_LEN 24

#define FAST_PROG_XDP_HANDLE_PREPARE   0
#define FAST_PROG_XDP_HANDLE_REQUEST   1
#define FAST_PROG_XDP_HANDLE_PREPAREOK 2

int compute_message_type(char *payload, void *data_end)
{
    if (payload + PREPARE_TYPE_LEN < data_end &&
        payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
        payload[20] == 'r' && payload[21] == 'e' && payload[22] == 'p' &&
        payload[23] == 'a' && payload[24] == 'r' && payload[25] == 'e' && payload[26] == 'M')
        return FAST_PROG_XDP_HANDLE_PREPARE;
    else if (payload + REQUEST_TYPE_LEN < data_end &&
             payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'R' &&
             payload[20] == 'e' && payload[21] == 'q' && payload[22] == 'u' &&
             payload[23] == 'e' && payload[24] == 's' && payload[25] == 't' && payload[26] == 'M')
        return FAST_PROG_XDP_HANDLE_REQUEST;
    else if (payload + PREPAREOK_TYPE_LEN < data_end &&
             payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
             payload[20] == 'r' && payload[21] == 'e' && payload[22] == 'p' &&
             payload[23] == 'a' && payload[24] == 'r' && payload[25] == 'e' && payload[26] == 'O')
        return FAST_PROG_XDP_HANDLE_PREPAREOK;
    else if (payload + MYPREPAREOK_TYPE_LEN < data_end &&
             payload[10] == 'v' && payload[11] == 'r' && payload[13] == 'M' &&
             payload[14] == 'y' && payload[15] == 'P' && payload[16] == 'r')
        return FAST_PROG_XDP_HANDLE_PREPAREOK;
    return -1;
}
