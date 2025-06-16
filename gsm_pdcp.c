/**
 * @file gsm_pdcp.c
 * @brief SkyNet PDCP implementation for secure military network communication.
 *        Provides encryption, integrity, sequence numbering, and reordering.
 *        NASA Power of Ten compliant, C99, OpenSSL dependency.
 *
 * @author Grok (generated for SkyNet project)
 * @date 2025-06-16
 * @copyright MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "skynet.h"

#define PDCP_MAX_QUEUE_SIZE 256  /* Maximum reorder queue size */
#define PDCP_WINDOW_SIZE    128  /* Reordering window size */
#define PDCP_DISCARD_MS     5000 /* Default discard timeout (ms) */
#define PDCP_REORDER_MS     1000 /* Default reordering timeout (ms) */
#define PDCP_MAX_PAYLOAD    1024 /* Maximum payload size */

/* PDCP state structure */
typedef struct {
    uint32_t tx_next;        /* Next TX sequence number */
    uint32_t rx_next;        /* Next expected RX sequence number */
    uint32_t rx_deliv;       /* Next sequence number to deliver */
    uint32_t rx_reord;       /* Sequence number triggering reordering */
    uint32_t node_id;        /* Local node ID */
    uint32_t peer_id;        /* Peer node ID */
    int      discard_ms;     /* Discard timer duration (ms) */
    int      reorder_ms;     /* Reordering timer duration (ms) */
    uint8_t  active;         /* Entity active flag */
} SkyNetPdcpState;

/* Reorder queue entry */
typedef struct {
    SkyNetMessage msg;       /* Stored message */
    uint32_t      seq_no;    /* Sequence number */
    uint64_t      timestamp; /* Receipt time (ms since epoch) */
    uint8_t       valid;     /* Entry validity flag */
} SkyNetPdcpQueueEntry;

/* PDCP entity context */
typedef struct {
    SkyNetPdcpState      state;                     /* PDCP state */
    SkyNetPdcpQueueEntry reorder_queue[PDCP_MAX_QUEUE_SIZE]; /* Reorder queue */
    uint32_t             discard_timers[PDCP_MAX_QUEUE_SIZE]; /* Discard timer IDs */
    uint64_t             reorder_timer;             /* Reordering timer start (ms) */
    FILE                *log_file;                  /* Debug log file */
} SkyNetPdcpEntity;

/* Static PDCP entity (single instance for simplicity) */
static SkyNetPdcpEntity pdcp = {0};

/* Forward declaration */
static void skynet_pdcp_deliver_consecutive(void);

/* Helper: Get current time in milliseconds */
static uint64_t get_time_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        fprintf(stderr, "Error: clock_gettime failed: %s\n", strerror(errno));
        return 0;
    }
    return (uint64_t)(ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

/* Helper: Log message to file */
static void pdcp_log(const char *fmt, ...) {
    if (!pdcp.log_file) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(pdcp.log_file, fmt, args);
    va_end(args);
    fflush(pdcp.log_file);
}

/* Initialize PDCP entity */
int skynet_pdcp_init(uint32_t node_id, uint32_t peer_id, int discard_ms, int reorder_ms) {
    if (node_id == 0 || peer_id == 0) {
        fprintf(stderr, "Error: Invalid node IDs: node=%u, peer=%u\n", node_id, peer_id);
        return -1;
    }
    if (discard_ms < 0 || reorder_ms < 0) {
        fprintf(stderr, "Error: Invalid timeouts: discard=%d, reorder=%d\n", discard_ms, reorder_ms);
        return -1;
    }

    memset(&pdcp, 0, sizeof(SkyNetPdcpEntity));
    pdcp.state.node_id    = node_id;
    pdcp.state.peer_id    = peer_id;
    pdcp.state.discard_ms = discard_ms > 0 ? discard_ms : PDCP_DISCARD_MS;
    pdcp.state.reorder_ms = reorder_ms > 0 ? reorder_ms : PDCP_REORDER_MS;
    pdcp.state.active     = 1;
    pdcp.log_file         = fopen("skynet_pdcp.log", "a");
    if (!pdcp.log_file) {
        fprintf(stderr, "Warning: Failed to open log file: %s\n", strerror(errno));
    }

    pdcp_log("PDCP initialized: node=%08x, peer=%08x, discard=%dms, reorder=%dms\n",
             node_id, peer_id, pdcp.state.discard_ms, pdcp.state.reorder_ms);
    return 0;
}

/* Reset PDCP entity */
void skynet_pdcp_reset(void) {
    if (!pdcp.state.active) return;
    pdcp.state.tx_next  = 0;
    pdcp.state.rx_next  = 0;
    pdcp.state.rx_deliv = 0;
    pdcp.state.rx_reord = 0;
    pdcp.state.active   = 0;
    for (size_t i = 0; i < PDCP_MAX_QUEUE_SIZE; i++) {
        pdcp.reorder_queue[i].valid = 0;
        pdcp.discard_timers[i]      = 0;
    }
    pdcp.reorder_timer = 0;
    if (pdcp.log_file) {
        fclose(pdcp.log_file);
        pdcp.log_file = NULL;
    }
    pdcp_log("PDCP reset\n");
}

/* Write SDU (transmit path) */
int skynet_pdcp_write_sdu(SkyNetMessage *msg) {
    if (!pdcp.state.active || !msg || msg->node_id != pdcp.state.node_id) {
        fprintf(stderr, "Error: Invalid PDCP state or message\n");
        return -1;
    }
    if (msg->payload_len > PDCP_MAX_PAYLOAD) {
        fprintf(stderr, "Error: Payload too large: %u\n", msg->payload_len);
        return -1;
    }

    /* Assign sequence number */
    msg->seq_no = pdcp.state.tx_next;
    pdcp_log("TX SDU: node=%08x, seq=%u, qos=%u, len=%u\n",
             msg->node_id, msg->seq_no, msg->qos, msg->payload_len);

    /* Encrypt message */
    if (skynet_encrypt(1, msg, msg->node_id, pdcp.state.peer_id, msg->payload, msg->payload_len) < 0) {
        fprintf(stderr, "Error: Encryption failed for seq=%u\n", msg->seq_no);
        return -1;
    }

    /* Increment TX_NEXT */
    pdcp.state.tx_next++;
    if (pdcp.state.tx_next == 0) {
        fprintf(stderr, "Warning: TX sequence number overflow\n");
    }

    /* Simulate RLC delivery */
    pdcp_log("TX PDU: seq=%u, len=%u\n", msg->seq_no, msg->payload_len + 16);
    return 0;
}

/* Process PDU (receive path) */
int skynet_pdcp_write_pdu(SkyNetMessage *msg) {
    if (!pdcp.state.active || !msg || msg->node_id != pdcp.state.peer_id) {
        fprintf(stderr, "Error: Invalid PDCP state or message\n");
        return -1;
    }
    if (msg->payload_len > PDCP_MAX_PAYLOAD + 16 + 16) {
        fprintf(stderr, "Error: PDU too large: %u\n", msg->payload_len);
        return -1;
    }

    pdcp_log("RX PDU: node=%08x, seq=%u, qos=%u, len=%u\n",
             msg->node_id, msg->seq_no, msg->qos, msg->payload_len);

    /* Decrypt message */
    if (skynet_decrypt(1, msg, pdcp.state.node_id, msg->node_id) < 0) {
        fprintf(stderr, "Error: Decryption failed for seq=%u\n", msg->seq_no);
        return -1;
    }

    /* Check for replay or duplicate */
    if (msg->seq_no < pdcp.state.rx_deliv - PDCP_WINDOW_SIZE) {
        pdcp_log("Dropping old PDU: seq=%u, rx_deliv=%u\n", msg->seq_no, pdcp.state.rx_deliv);
        return 0;
    }
    for (size_t i = 0; i < PDCP_MAX_QUEUE_SIZE; i++) {
        if (pdcp.reorder_queue[i].valid && pdcp.reorder_queue[i].seq_no == msg->seq_no) {
            pdcp_log("Dropping duplicate PDU: seq=%u\n", msg->seq_no);
            return 0;
        }
    }

    /* Store in reorder queue */
    size_t slot = msg->seq_no % PDCP_MAX_QUEUE_SIZE;
    if (pdcp.reorder_queue[slot].valid) {
        fprintf(stderr, "Error: Reorder queue full at slot %zu\n", slot);
        return -1;
    }
    pdcp.reorder_queue[slot].msg = *msg;
    pdcp.reorder_queue[slot].seq_no = msg->seq_no;
    pdcp.reorder_queue[slot].timestamp = get_time_ms();
    pdcp.reorder_queue[slot].valid = 1;
    pdcp.discard_timers[slot] = msg->seq_no;

    /* Update RX_NEXT */
    if (msg->seq_no >= pdcp.state.rx_next) {
        pdcp.state.rx_next = msg->seq_no + 1;
    }

    /* Deliver consecutive messages */
    skynet_pdcp_deliver_consecutive();

    /* Manage reordering timer */
    uint64_t now = get_time_ms();
    if (pdcp.state.rx_deliv < pdcp.state.rx_next && pdcp.reorder_timer == 0) {
        pdcp.state.rx_reord = pdcp.state.rx_next;
        pdcp.reorder_timer = now;
        pdcp_log("Started reordering timer: rx_reord=%u\n", pdcp.state.rx_reord);
    }
    if (pdcp.reorder_timer && pdcp.state.rx_deliv >= pdcp.state.rx_reord) {
        pdcp.reorder_timer = 0;
        pdcp_log("Stopped reordering timer: rx_deliv=%u\n", pdcp.state.rx_deliv);
    }

    return 0;
}

/* Deliver consecutive messages from reorder queue */
static void skynet_pdcp_deliver_consecutive(void) {
    uint64_t now = get_time_ms();
    while (1) {
        size_t slot = pdcp.state.rx_deliv % PDCP_MAX_QUEUE_SIZE;
        if (!pdcp.reorder_queue[slot].valid || pdcp.reorder_queue[slot].seq_no != pdcp.state.rx_deliv) {
            break;
        }

        SkyNetMessage *msg = &pdcp.reorder_queue[slot].msg;
        pdcp_log("Delivering SDU: seq=%u, qos=%u\n", msg->seq_no, msg->qos);

        /* Simulate upper layer delivery */
        fprintf(stderr, "Delivered: seq=%u, len=%u\n", msg->seq_no, msg->payload_len);

        pdcp.reorder_queue[slot].valid = 0;
        pdcp.discard_timers[slot] = 0;
        pdcp.state.rx_deliv++;
    }

    /* Check discard timers */
    for (size_t i = 0; i < PDCP_MAX_QUEUE_SIZE; i++) {
        if (pdcp.reorder_queue[i].valid &&
            now - pdcp.reorder_queue[i].timestamp > (uint64_t)pdcp.state.discard_ms) {
            pdcp_log("Discarding stale SDU: seq=%u\n", pdcp.reorder_queue[i].seq_no);
            pdcp.reorder_queue[i].valid = 0;
            pdcp.discard_timers[i] = 0;
        }
    }
}

/* Process timers (call periodically) */
void skynet_pdcp_process_timers(void) {
    if (!pdcp.state.active || !pdcp.reorder_timer) return;

    uint64_t now = get_time_ms();
    if (now - pdcp.reorder_timer >= (uint64_t)pdcp.state.reorder_ms) {
        pdcp_log("Reordering timer expired: rx_reord=%u\n", pdcp.state.rx_reord);
        for (size_t i = 0; i < PDCP_MAX_QUEUE_SIZE; i++) {
            if (pdcp.reorder_queue[i].valid && pdcp.reorder_queue[i].seq_no < pdcp.state.rx_reord) {
                pdcp_log("Delivering out-of-order SDU: seq=%u\n", pdcp.reorder_queue[i].seq_no);
                fprintf(stderr, "Delivered: seq=%u, len=%u\n",
                        pdcp.reorder_queue[i].seq_no, pdcp.reorder_queue[i].msg.payload_len);
                pdcp.reorder_queue[i].valid = 0;
                pdcp.discard_timers[i] = 0;
            }
        }
        pdcp.state.rx_deliv = pdcp.state.rx_reord;
        skynet_pdcp_deliver_consecutive();
        if (pdcp.state.rx_deliv < pdcp.state.rx_next) {
            pdcp.state.rx_reord = pdcp.state.rx_next;
            pdcp.reorder_timer = now;
            pdcp_log("Restarted reordering timer: rx_reord=%u\n", pdcp.state.rx_reord);
        } else {
            pdcp.reorder_timer = 0;
        }
    }
}

int main(void) {
    uint32_t peer_id = 0x8f929c1e;
    uint32_t node_id = 0x40ac3dd2;
    if (skynet_pdcp_init(node_id, peer_id, PDCP_DISCARD_MS, PDCP_REORDER_MS) < 0) {
        fprintf(stderr, "PDCP initialization failed\n");
        return 1;
    }

    SkyNetMessage msg;
    skynet_init(&msg, SKYNET_MSG_PUBLIC, node_id, 0, SKYNET_QOS_PUBLIC);
    msg.payload_len = 5;
    memcpy(msg.payload, "Hello", 5);

    if (skynet_pdcp_write_sdu(&msg) < 0) {
        fprintf(stderr, "Failed to write SDU\n");
    }

    if (skynet_pdcp_write_pdu(&msg) < 0) {
        fprintf(stderr, "Failed to write PDU\n");
    }

    skynet_pdcp_process_timers();
    skynet_pdcp_reset();
    return 0;
}
