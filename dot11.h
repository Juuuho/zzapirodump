#pragma once

typedef struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}RTHEAD;

typedef struct beacon {
        u_int8_t        bssid[6];
        int             bc_cnt;
        char            essid[256];
}BEACON;