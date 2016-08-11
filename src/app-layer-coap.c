/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file COAP application layer detector and parser for learning and
 * COAP pruposes.
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * This implements the application layer for the COAP protocol.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-coap.h"

#if 0
#define WITH_POSIX /* Keep COAP happy */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION
#include <coap_config.h>
#include <coap.h>
#endif

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define COAP_MIN_FRAME_LEN 1

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert COAP any any -> any any (msg:"SURICATA COAP empty message"; \
 *    app-layer-event:COAP.empty_message; sid:X; rev:Y;)
 */
enum {
    COAP_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap COAP_decoder_event_table[] = {
    {"EMPTY_MESSAGE", COAP_DECODER_EVENT_EMPTY_MESSAGE},
};

static COAPTransaction *COAPTxAlloc(COAPState *echo)
{
    COAPTransaction *tx = SCCalloc(1, sizeof(COAPTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void COAPTxFree(void *tx)
{
    COAPTransaction *COAPtx = tx;

    if (COAPtx->request_pdu != NULL) {
        coap_free_type(0, COAPtx->request_pdu);
    }

    if (COAPtx->response_pdu != NULL) {
        coap_free_type(0, COAPtx->response_pdu);
    }

    AppLayerDecoderEventsFreeEvents(&COAPtx->decoder_events);

    SCFree(tx);
}

static void *COAPStateAlloc(void)
{
    SCLogNotice("Allocating COAP state.");
    COAPState *state = SCCalloc(1, sizeof(COAPState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void COAPStateFree(void *state)
{
    COAPState *COAP_state = state;
    COAPTransaction *tx;
    SCLogNotice("Freeing COAP state.");
    while ((tx = TAILQ_FIRST(&COAP_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&COAP_state->tx_list, tx, next);
        COAPTxFree(tx);
    }
    SCFree(COAP_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the COAPState object.
 * \param tx_id the transaction ID to free.
 */
static void COAPStateTxFree(void *state, uint64_t tx_id)
{
    COAPState *echo = state;
    COAPTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        COAPTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int COAPStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, COAP_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "COAP enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *COAPGetEvents(void *state, uint64_t tx_id)
{
    COAPState *COAP_state = state;
    COAPTransaction *tx;

    TAILQ_FOREACH(tx, &COAP_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int COAPHasEvents(void *state)
{
    COAPState *echo = state;
    return echo->events;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_COAP if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto COAPProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    int result;
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_MAX_PDU_SIZE);

    if (pdu != NULL) {
        /* Very simple test - if there is input, this is echo. */
        if (input_len >= COAP_MIN_FRAME_LEN) {
            result = coap_pdu_parse(input, input_len, pdu);

            if (result > 0) {
                coap_free_type(0, pdu);
                SCLogNotice("Detected as ALPROTO_COAP.");
                return ALPROTO_COAP;
            }
        }
        coap_free_type(0, pdu);
    }

    SCLogNotice("Protocol not detected as ALPROTO_COAP.");
    return ALPROTO_UNKNOWN;
}

static int COAPParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    COAPState *echo = state;
    int result;

    SCLogNotice("Parsing COAP request: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_MAX_PDU_SIZE);
    if (pdu != NULL) {
        result = coap_pdu_parse(input, input_len, pdu);

        if (result > 0) {
            /* Allocate a transaction.
             *
             * But note that if a "protocol data unit" is not received in one
             * chunk of data, and the buffering is done on the transaction, we
             * may need to look for the transaction that this newly recieved
             * data belongs to.
             */
            COAPTransaction *tx = COAPTxAlloc(echo);
            if (unlikely(tx == NULL)) {
                SCLogNotice("Failed to allocate new COAP tx.");
                goto end;
            }
            SCLogNotice("Allocated COAP tx %"PRIu64".", tx->tx_id);
    
            /* Make a copy of the request. */
            tx->request_pdu = pdu;
        }
    }

#if 0
    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
            COAP_DECODER_EVENT_EMPTY_MESSAGE);
        echo->events++;
    }
#endif
end:    
    return 0;
}

static int COAPParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    COAPState *echo = state;
    COAPTransaction *tx = NULL, *ttx;;
    int result;

    SCLogNotice("Parsing COAP response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * COAPState object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &echo->tx_list, next) {
        tx = ttx;
    }
    
    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on echo state %p.",
            echo);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on echo state %p.",
        tx->tx_id, echo);

    /* If the protocol requires multiple chunks of data to complete, you may
     * run into the case where you have existing response data.
     *
     * In this case, we just log that there is existing data and free it. But
     * you might want to realloc the buffer and append the data.
     */
    if (tx->response_pdu != NULL) {
        SCLogNotice("WARNING: Transaction already has response data, "
            "existing data will be overwritten.");
        coap_free_type(0, tx->response_pdu);
    }
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_MAX_PDU_SIZE);
    if (pdu != NULL) {
        result = coap_pdu_parse(input, input_len, pdu);

        if (result > 0) {

            /* Make a copy of the response. */
            tx->response_pdu = pdu;

            /* Set the response_done flag for transaction state checking in
             * COAPGetStateProgress(). */
            tx->response_done = 1;
        }
    }

end:
    return 0;
}

static uint64_t COAPGetTxCnt(void *state)
{
    COAPState *echo = state;
    SCLogNotice("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *COAPGetTx(void *state, uint64_t tx_id)
{
    COAPState *echo = state;
    COAPTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void COAPSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    COAPTransaction *tx = (COAPTransaction *)vtx;
    tx->logged |= logger;
}

static int COAPGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    COAPTransaction *tx = (COAPTransaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int COAPGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int COAPGetStateProgress(void *tx, uint8_t direction)
{
    COAPTransaction *echotx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", echotx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && echotx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *COAPGetTxDetectState(void *vtx)
{
    COAPTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int COAPSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    COAPTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterCOAPParsers(void)
{
    char *proto_name = "COAP";
    char coap_default_port[16];

    snprintf(coap_default_port, sizeof(coap_default_port)-1, "%u", COAP_DEFAULT_PORT);

    /* Check if COAP UDP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {

        SCLogNotice("COAP UDP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_COAP, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, coap_default_port,
                ALPROTO_COAP, 0, COAP_MIN_FRAME_LEN, STREAM_TOSERVER,
                COAPProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_COAP, 0, COAP_MIN_FRAME_LEN,
                    COAPProbingParser)) {
                SCLogNotice("No COAP app-layer configuration, enabling COAP"
                    " detection COAP detection on port %s.",
                    coap_default_port);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                    coap_default_port, ALPROTO_COAP, 0,
                    COAP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    COAPProbingParser);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for COAP.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering COAP protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new COAP flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_COAP,
            COAPStateAlloc, COAPStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_COAP,
            STREAM_TOSERVER, COAPParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_COAP,
            STREAM_TOCLIENT, COAPParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_COAP,
            COAPStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_COAP,
            COAPGetTxLogged, COAPSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_COAP,
            COAPGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_COAP,
            COAPGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP,
            ALPROTO_COAP, COAPGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_COAP,
            COAPGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_COAP,
            COAPHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_COAP,
            NULL, COAPGetTxDetectState, COAPSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_COAP,
            COAPStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_COAP,
            COAPGetEvents);
    }
    else {
        SCLogNotice("COAP protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_COAP,
        COAPParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void COAPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
