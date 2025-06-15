/*
 * File:  gsm_hss.h
 * Owner: BitEdits Corporation, creators of Skynet/Link32.
 * Copyright: 2025 BitEdits Corporation
 * Desc: Header for LTE HSS in C99, inspired by Skynet/Link32.
 */

#ifndef GSM_HSS_H
#define GSM_HSS_H

#include <stdint.h>
#include <inttypes.h>

#define GSM_HSS_MAX_UES 256
#define GSM_HSS_MAX_IPS 256
#define LTE_FDD_ENB_IND_HE_N_BITS 5
#define LTE_FDD_ENB_IND_HE_MASK 0x1FUL
#define LTE_FDD_ENB_IND_HE_MAX_VALUE 31
#define LTE_FDD_ENB_SEQ_HE_MAX_VALUE 0x07FFFFFFFFFFUL

typedef enum { GSM_HSS_ALGO_XOR, GSM_HSS_ALGO_MILENAGE } GSM_HSS_ALGO;

typedef struct {
    char       name[32];
    uint64_t   imsi;
    GSM_HSS_ALGO algo;
    uint8_t    key[16];
    int        op_configured;
    uint8_t    op[16];
    uint8_t    opc[16];
    uint8_t    amf[2];
    uint8_t    sqn[6];
    int        qci;
    uint8_t    last_rand[16];
    char       ip_addr[16];
} GSM_HSS_UE_CTX;

typedef struct {
    char     db_file[256];
    uint16_t mcc;
    uint16_t mnc;
} GSM_HSS_ARGS;

typedef struct {
    char ip[16];
    uint64_t imsi;
} GSM_HSS_IP_MAP;

typedef struct {
    GSM_HSS_UE_CTX ue_ctx[GSM_HSS_MAX_UES];
    int            ue_count;
    GSM_HSS_IP_MAP ip_to_imsi[GSM_HSS_MAX_IPS];
    int            ip_count;
    char           db_file[256];
    uint16_t       mcc;
    uint16_t       mnc;
} GSM_HSS;

int  gsm_hss_init(const GSM_HSS_ARGS *args);
void gsm_hss_stop(void);
int  gsm_hss_gen_auth_answer(uint64_t imsi, uint8_t *k_asme, uint8_t *autn, uint8_t *rand_out, uint8_t *xres);
int  gsm_hss_get_loc_answer(uint64_t imsi, uint8_t *qci);
int  gsm_hss_resync_sqn(uint64_t imsi, const uint8_t *auts);

#endif /* GSM_HSS_H */

