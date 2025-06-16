/*
 * @file  gsm_pdcp.c
 * @brief LTE HSS implementation in C99, inspired by Skynet/Link32 style.
 *        Manages subscriber data and authentication for LTE networks.
 *
 * @author Grok (generated for SkyNet project)
 * @date 2025-06-16
 * @copyright MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>
#include "gsm_hss.h"

#define LOG(...) printf(__VA_ARGS__)
#define MAX_LINE 256
#define HEX_TO_BYTE(s, buf, len) do { \
    for (int i = 0; i < (len); i++) sscanf((s) + 2 * i, "%2hhx", &(buf)[i]); \
} while (0)
#define BYTE_TO_HEX(buf, len, s) do { \
    for (int i = 0; i < (len); i++) sprintf((s) + 2 * i, "%02x", (buf)[i]); \
} while (0)

/* Static function declarations */
static int read_db_file(const char *filename);
static int write_db_file(const char *filename);
static void gen_auth_milenage(GSM_HSS_UE_CTX *restrict ue, uint8_t *restrict k_asme,
                              uint8_t *restrict autn, uint8_t *restrict rand_out, uint8_t *restrict xres);
static void gen_auth_xor(GSM_HSS_UE_CTX *restrict ue, uint8_t *restrict k_asme,
                         uint8_t *restrict autn, uint8_t *restrict rand_out, uint8_t *restrict xres);
static void resync_sqn_milenage(GSM_HSS_UE_CTX *restrict ue, const uint8_t *restrict auts);
static void increment_ue_sqn(GSM_HSS_UE_CTX *restrict ue);
static void increment_sqn(const uint8_t *restrict sqn, uint8_t *restrict next_sqn);
static void increment_seq_after_resync(GSM_HSS_UE_CTX *restrict ue);
static void gen_rand(uint8_t *restrict rand_out);
static GSM_HSS_UE_CTX *get_ue_ctx(uint64_t imsi);

/* Static HSS instance */
static GSM_HSS gsm_hss = {0};

/* Initialize HSS with database file */
int gsm_hss_init(const GSM_HSS_ARGS *restrict args)
{
    srand(time(NULL));
    strncpy(gsm_hss.db_file, args->db_file, sizeof(gsm_hss.db_file) - 1);
    gsm_hss.mcc = args->mcc;
    gsm_hss.mnc = args->mnc;
    gsm_hss.ue_count = 0;

    if (!read_db_file(gsm_hss.db_file)) {
        LOG("Error: Failed to read DB file %s\n", gsm_hss.db_file);
        return -1;
    }

    LOG("HSS Init: DB=%s, MCC=%d, MNC=%d, Users=%d\n",
        gsm_hss.db_file, gsm_hss.mcc, gsm_hss.mnc, gsm_hss.ue_count);
    return 0;
}

/* Stop HSS and save database */
void gsm_hss_stop(void)
{
    write_db_file(gsm_hss.db_file);
}

/* Generate authentication vectors for IMSI */
int gsm_hss_gen_auth_answer(uint64_t imsi, uint8_t *restrict k_asme, uint8_t *restrict autn,
                            uint8_t *restrict rand_out, uint8_t *restrict xres)
{
    GSM_HSS_UE_CTX *ue = get_ue_ctx(imsi);
    if (!ue) {
        LOG("Error: IMSI %015" PRIu64 " not found\n", imsi);
        return -1;
    }

    if (ue->algo == GSM_HSS_ALGO_MILENAGE)
        gen_auth_milenage(ue, k_asme, autn, rand_out, xres);
    else
        gen_auth_xor(ue, k_asme, autn, rand_out, xres);

    increment_ue_sqn(ue);
    return 0;
}

/* Provide QCI for location update */
int gsm_hss_get_loc_answer(uint64_t imsi, uint8_t *restrict qci)
{
    GSM_HSS_UE_CTX *ue = get_ue_ctx(imsi);
    if (!ue) {
        LOG("Error: IMSI %015" PRIu64 " not found\n", imsi);
        return -1;
    }
    *qci = (uint8_t)ue->qci;
    return 0;
}

/* Resynchronize SQN using AUTS */
int gsm_hss_resync_sqn(uint64_t imsi, const uint8_t *restrict auts)
{
    GSM_HSS_UE_CTX *ue = get_ue_ctx(imsi);
    if (!ue) {
        LOG("Error: IMSI %015" PRIu64 " not found\n", imsi);
        return -1;
    }

    if (ue->algo == GSM_HSS_ALGO_MILENAGE) {
        resync_sqn_milenage(ue, auts);
        increment_seq_after_resync(ue);
        return 0;
    }

    LOG("Error: XOR SQN resync not supported\n");
    return -1;
}

/* Read subscriber database */
static int read_db_file(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char line[MAX_LINE];
    while (fgets(line, MAX_LINE, f)) {
        if (line[0] == '#' || strlen(line) <= 1) continue;

        GSM_HSS_UE_CTX *ue = &gsm_hss.ue_ctx[gsm_hss.ue_count];
        char name[32], algo[8], key[33], op_type[4], op_val[33], amf[5], sqn[13], ip[16];
        uint64_t imsi;
        int qci;

        if (sscanf(line, "%31[^,],%7[^,],%015" SCNu64 ",%32[^,],%3[^,],%32[^,],%4[^,],%12[^,],%d,%15[^,\n]",
                   name, algo, &imsi, key, op_type, op_val, amf, sqn, &qci, ip) != 10) {
            LOG("Error: Invalid CSV line: %s\n", line);
            fclose(f);
            return 0;
        }

        strncpy(ue->name, name, sizeof(ue->name) - 1);
        ue->imsi = imsi;
        ue->algo = strcmp(algo, "mil") == 0 ? GSM_HSS_ALGO_MILENAGE : GSM_HSS_ALGO_XOR;
        HEX_TO_BYTE(key, ue->key, 16);
        ue->op_configured = strcmp(op_type, "op") == 0;
        HEX_TO_BYTE(op_val, ue->op_configured ? ue->op : ue->opc, 16);
        HEX_TO_BYTE(amf, ue->amf, 2);
        HEX_TO_BYTE(sqn, ue->sqn, 6);
        ue->qci = qci;
        strncpy(ue->ip_addr, ip, sizeof(ue->ip_addr) - 1);

        if (ue->op_configured) {
            /* Compute OPc from OP and Key; placeholder for custom crypto */
            memcpy(ue->opc, ue->op, 16); /* Simplified for demo */
        }

        if (strcmp(ip, "dynamic") != 0 && gsm_hss.ip_count < GSM_HSS_MAX_IPS) {
            strncpy(gsm_hss.ip_to_imsi[gsm_hss.ip_count].ip, ip, 15);
            gsm_hss.ip_to_imsi[gsm_hss.ip_count].imsi = imsi;
            gsm_hss.ip_count++;
        }

        if (++gsm_hss.ue_count >= GSM_HSS_MAX_UES) {
            LOG("Error: Max UE count reached (%d)\n", GSM_HSS_MAX_UES);
            break;
        }
    }

    fclose(f);
    return 1;
}

/* Write subscriber database */
static int write_db_file(const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (!f) return 0;

    fprintf(f, "# CSV for UE data: Name,Auth,IMSI,Key,OP_Type,OP/OPc,AMF,SQN,QCI,IP_alloc\n"
               "# Auth: xor/mil, IP_alloc: dynamic or IPv4\n");

    for (int i = 0; i < gsm_hss.ue_count; i++) {
        GSM_HSS_UE_CTX *ue = &gsm_hss.ue_ctx[i];
        char key[33], op_val[33], amf[5], sqn[13];
        BYTE_TO_HEX(ue->key, 16, key);
        BYTE_TO_HEX(ue->op_configured ? ue->op : ue->opc, 16, op_val);
        BYTE_TO_HEX(ue->amf, 2, amf);
        BYTE_TO_HEX(ue->sqn, 6, sqn);

        fprintf(f, "%s,%s,%015" PRIu64 ",%s,%s,%s,%s,%s,%d,%s\n",
                ue->name, ue->algo == GSM_HSS_ALGO_MILENAGE ? "mil" : "xor",
                ue->imsi, key, ue->op_configured ? "op" : "opc", op_val,
                amf, sqn, ue->qci, ue->ip_addr);
    }

    fclose(f);
    return 1;
}

/* Generate Milenage authentication vectors */
static void gen_auth_milenage(GSM_HSS_UE_CTX *restrict ue, uint8_t *restrict k_asme,
                              uint8_t *restrict autn, uint8_t *restrict rand_out, uint8_t *restrict xres)
{
    uint8_t ck[16], ik[16], ak[6], mac[8];
    gen_rand(rand_out);

    /* Placeholder: Implement Milenage with custom crypto */
    for (int i = 0; i < 8; i++) xres[i] = rand_out[i]; /* Demo */
    for (int i = 0; i < 16; i++) { ck[i] = rand_out[i]; ik[i] = rand_out[i]; }
    for (int i = 0; i < 6; i++) ak[i] = rand_out[i];

    for (int i = 0; i < 8; i++) mac[i] = ue->sqn[i % 6];

    for (int i = 0; i < 6; i++) autn[i] = ue->sqn[i] ^ ak[i];
    for (int i = 0; i < 2; i++) autn[6 + i] = ue->amf[i];
    for (int i = 0; i < 8; i++) autn[8 + i] = mac[i];

    uint8_t ak_xor_sqn[6];
    for (int i = 0; i < 6; i++) ak_xor_sqn[i] = ue->sqn[i] ^ ak[i];

    for (int i = 0; i < 32; i++) k_asme[i] = ck[i % 16]; /* Demo */

    memcpy(ue->last_rand, rand_out, 16);
}

/* Generate XOR authentication vectors */
static void gen_auth_xor(GSM_HSS_UE_CTX *restrict ue, uint8_t *restrict k_asme,
                         uint8_t *restrict autn, uint8_t *restrict rand_out, uint8_t *restrict xres)
{
    uint8_t xdout[16], ck[16], ik[16], ak[6], mac[8], cdout[8];
    gen_rand(rand_out);

    for (int i = 0; i < 16; i++) xdout[i] = ue->key[i] ^ rand_out[i];
    for (int i = 0; i < 8; i++) xres[i] = xdout[i];
    for (int i = 0; i < 16; i++) {
        ck[i] = xdout[(i + 1) % 16];
        ik[i] = xdout[(i + 2) % 16];
    }
    for (int i = 0; i < 6; i++) ak[i] = xdout[i + 3];

    for (int i = 0; i < 6; i++) cdout[i] = ue->sqn[i];
    for (int i = 0; i < 2; i++) cdout[6 + i] = ue->amf[i];
    for (int i = 0; i < 8; i++) mac[i] = xdout[i] ^ cdout[i];

    for (int i = 0; i < 6; i++) autn[i] = ue->sqn[i] ^ ak[i];
    for (int i = 0; i < 2; i++) autn[6 + i] = ue->amf[i];
    for (int i = 0; i < 8; i++) autn[8 + i] = mac[i];

    uint8_t ak_xor_sqn[6];
    for (int i = 0; i < 6; i++) ak_xor_sqn[i] = ue->sqn[i] ^ ak[i];

    for (int i = 0; i < 32; i++) k_asme[i] = ck[i % 16]; /* Demo */
    memcpy(ue->last_rand, rand_out, 16);
}

/* Resynchronize SQN for Milenage */
static void resync_sqn_milenage(GSM_HSS_UE_CTX *restrict ue, const uint8_t *restrict auts)
{
    uint8_t ak[6], sqn_ms_xor_ak[6], mac_s[8], sqn_ms[6];
    memcpy(sqn_ms_xor_ak, auts, 6);
    memcpy(mac_s, auts + 6, 8);

    for (int i = 0; i < 6; i++) ak[i] = ue->last_rand[i]; /* Demo */

    for (int i = 0; i < 6; i++) sqn_ms[i] = sqn_ms_xor_ak[i] ^ ak[i];

    memcpy(ue->sqn, sqn_ms, 6);
}

/* Increment UE SQN */
static void increment_ue_sqn(GSM_HSS_UE_CTX *restrict ue)
{
    uint8_t next_sqn[6];
    increment_sqn(ue->sqn, next_sqn);
    memcpy(ue->sqn, next_sqn, 6);
}

/* Increment SQN per 3GPP TS 33.102 Annex C */
static void increment_sqn(const uint8_t *restrict sqn, uint8_t *restrict next_sqn)
{
    uint64_t sqn64 = 0;
    for (int i = 0; i < 6; i++) sqn64 |= (uint64_t)sqn[i] << (5 - i) * 8;

    uint64_t seq = sqn64 >> LTE_FDD_ENB_IND_HE_N_BITS;
    uint64_t ind = sqn64 & LTE_FDD_ENB_IND_HE_MASK;
    seq = (seq + 1) % LTE_FDD_ENB_SEQ_HE_MAX_VALUE;
    ind = (ind + 1) % LTE_FDD_ENB_IND_HE_MAX_VALUE;
    uint64_t next_sqn64 = (seq << LTE_FDD_ENB_IND_HE_N_BITS) | ind;

    for (int i = 0; i < 6; i++) next_sqn[i] = (next_sqn64 >> (5 - i) * 8) & 0xFF;
}

/* Increment SEQ after resync */
static void increment_seq_after_resync(GSM_HSS_UE_CTX *restrict ue)
{
    uint8_t sqn[6], next_sqn[6];
    memcpy(sqn, ue->sqn, 6);
    uint64_t sqn64 = 0;
    for (int i = 0; i < 6; i++) sqn64 |= (uint64_t)sqn[i] << (5 - i) * 8;

    uint64_t seq = sqn64 >> LTE_FDD_ENB_IND_HE_N_BITS;
    uint64_t ind = sqn64 & LTE_FDD_ENB_IND_HE_MASK;
    seq = (seq + 1) % LTE_FDD_ENB_SEQ_HE_MAX_VALUE;
    uint64_t next_sqn64 = (seq << LTE_FDD_ENB_IND_HE_N_BITS) | ind;

    for (int i = 0; i < 6; i++) next_sqn[i] = (next_sqn64 >> (5 - i) * 8) & 0xFF;
    memcpy(ue->sqn, next_sqn, 6);
}

/* Generate random bytes */
static void gen_rand(uint8_t *restrict rand_out)
{
    for (int i = 0; i < 16; i++) rand_out[i] = (uint8_t)(rand() % 256);
}

/* Find UE context by IMSI */
static GSM_HSS_UE_CTX *get_ue_ctx(uint64_t imsi)
{
    for (int i = 0; i < gsm_hss.ue_count; i++)
        if (gsm_hss.ue_ctx[i].imsi == imsi) return &gsm_hss.ue_ctx[i];
    return NULL;
}

/* Test program */
int main(void)
{
    GSM_HSS_ARGS args = { .db_file = "user_db.csv", .mcc = 1, .mnc = 1 };
    if (gsm_hss_init(&args) != 0) {
        LOG("Init failed\n");
        return 1;
    }

    uint8_t k_asme[32], autn[16], rand_out[16], xres[8];
    if (gsm_hss_gen_auth_answer(1010123456789, k_asme, autn, rand_out, xres) == 0) {
        LOG("Auth vectors generated\n");
    } else {
        LOG("Auth generation failed\n");
    }

    gsm_hss_stop();
    return 0;
}
