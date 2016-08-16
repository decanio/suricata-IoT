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
 * \file MQTT application layer detector and parser for learning and
 * MQTT pruposes.
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * This implements the simple application layer for MQTT protocol.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-mqtt.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define MQTT_DEFAULT_PORT "1883"

/* The minimum size for an MQTT message.  This is the smallest size of 
 * a fixed header. */
#define MQTT_MIN_FRAME_LEN 2

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert MQTT any any -> any any (msg:"SURICATA MQTT empty message"; \
 *    app-layer-event:MQTT.empty_message; sid:X; rev:Y;)
 */
enum {
    MQTT_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap MQTT_decoder_event_table[] = {
    {"EMPTY_MESSAGE", MQTT_DECODER_EVENT_EMPTY_MESSAGE},
};

static MQTTTransaction *MQTTTxAlloc(MQTTState *echo)
{
    MQTTTransaction *tx = SCCalloc(1, sizeof(MQTTTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void MQTTTxFree(void *tx)
{
    MQTTTransaction *MQTTtx = tx;

    AppLayerDecoderEventsFreeEvents(&MQTTtx->decoder_events);

    SCFree(tx);
}

static void *MQTTStateAlloc(void)
{
    SCLogDebug("Allocating MQTT state.");
    MQTTState *state = SCCalloc(1, sizeof(MQTTState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void MQTTStateFree(void *state)
{
    MQTTState *MQTT_state = state;
    MQTTTransaction *tx;
    SCLogDebug("Freeing MQTT state.");
    while ((tx = TAILQ_FIRST(&MQTT_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&MQTT_state->tx_list, tx, next);
        MQTTTxFree(tx);
    }
    SCFree(MQTT_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the MQTTState object.
 * \param tx_id the transaction ID to free.
 */
static void MQTTStateTxFree(void *state, uint64_t tx_id)
{
    MQTTState *echo = state;
    MQTTTransaction *tx = NULL, *ttx;

    SCLogDebug("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        MQTTTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int MQTTStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, MQTT_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "MQTT enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *MQTTGetEvents(void *state, uint64_t tx_id)
{
    MQTTState *MQTT_state = state;
    MQTTTransaction *tx;

    TAILQ_FOREACH(tx, &MQTT_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int MQTTHasEvents(void *state)
{
    MQTTState *echo = state;
    return echo->events;
}

static char *MQTTPacketTypeStr(uint8_t packetType)
{
    switch (packetType) {
        case MQTT_CONNECT:
            return "Connect";
        case MQTT_CONNACK:
            return "Connect acknowledgement";
        case MQTT_PUBLISH:
            return "Publish";
        case MQTT_PUBACK:
            return "Publish acknowledgement";
        case MQTT_PUBREC:
            return "Publish received";
        case MQTT_PUBREL:
            return "Publish release";
        case MQTT_PUBCOMP:
            return "Publish complete";
        case MQTT_SUBSCRIBE:
            return "Subscribe";
        case MQTT_SUBACK:
            return "Subscribe acknowledgement";
        case MQTT_UNSUBSCRIBE:
            return "Unsubscribe";
        case MQTT_UNSUBACK:
            return "Unsubscribe acknowledgement";
        case MQTT_PINGREQ:
            return "Ping request";
        case MQTT_PINGRESP:
            return "Ping response";
        case MQTT_DISCONNECT:
            return "Disconnect";
    }
    return "Unknown";
}

static int32_t MQTTParseRemainingLength(uint8_t *input, uint32_t input_len, uint32_t *consumed)
{
    int multiplier = 1;
    int32_t value = 0;
    uint8_t encodedByte;
    uint32_t i = 0;
    do {
        if (i < input_len) {
            encodedByte = input[i++];
            value += (encodedByte & 0x7f) * multiplier;
            if (multiplier > 128*128*128) {
                /* Malformed Remaining Length */
                return -1;
            }
            multiplier *= 128;
        } else {
            /* Ran out of input */
            return -1;
        }
    } while ((encodedByte & 0x80) != 0);
    *consumed += i;
    return value;
}

static int MQTTParseConnect(uint8_t *input, uint32_t input_len, MQTTPdu *pdu)
{
    int rc = 0;
    uint8_t protoLevel;
    if (input_len > 3) {
        uint32_t length;

        length = input[0] << 8;
        length += input[1];

        if (input_len >= 2 + length) {
            protoLevel = input[2 + length];

            if (input_len > length) {
                if ((length == 4) &&
                    (protoLevel == 0x4) &&
                    (strncmp((char *)&input[2], "MQTT", 4) == 0)) {
                    rc = 1;
                } else if ((length == 6) && 
                         (protoLevel == 0x3) &&
                         (strncmp((char *)&input[2], "MQIsdp", 6) == 0)) {
                    rc = 1;
                }
            }
        }
    }
    return rc;
}

static int MQTTPduParse(uint8_t *input, uint32_t input_len, MQTTPdu *pdu)
{
    int32_t remainingLength;
    uint8_t packetType;
    uint8_t packetFlags;
    uint32_t consumed;

    packetType = *input >> 4;
    packetFlags = *input & 0xf;
    consumed = 1;

    remainingLength = MQTTParseRemainingLength(&input[1], input_len - 1, &consumed);
    if (remainingLength > 0) {
        switch (packetType) {
            case MQTT_CONNECT:
                if (packetFlags != 0) {
                    return 0;
                }
                if (input_len - 2 >= (uint32_t)remainingLength) {
                    MQTTParseConnect(&input[consumed], remainingLength, pdu);
                }
                break;
            case MQTT_CONNACK:
            case MQTT_PUBACK:
            case MQTT_PUBREC:
            case MQTT_PUBCOMP:
            case MQTT_SUBACK:
            case MQTT_UNSUBACK:
            case MQTT_PINGREQ:
            case MQTT_PINGRESP:
            case MQTT_DISCONNECT:
                if (packetFlags != 0) {
                    return 0;
                }
                break;
            case MQTT_PUBREL:
            case MQTT_SUBSCRIBE:
            case MQTT_UNSUBSCRIBE:
                if (packetFlags != 0x2) {
                    return 0;
                }
                break;
            case MQTT_PUBLISH:
                break;
            default:
                return 0;
        }
    }

    pdu->packet_type = packetType;

    SCLogNotice("MQTT %s", MQTTPacketTypeStr(packetType));
   
    return consumed + remainingLength;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_MQTT if it looks like MQTT, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto MQTTProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    MQTTPdu pdu;
    int result;

    if (input_len >= MQTT_MIN_FRAME_LEN) {

        result = MQTTPduParse(input, input_len, &pdu);

        if (result > 0) {
            SCLogNotice("Detected as ALPROTO_MQTT.");
            return ALPROTO_MQTT;
        }
    }
    return ALPROTO_UNKNOWN;
}

static int MQTTParseToServer(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    MQTTState *mqtt = state;

    SCLogNotice("Parsing MQTT to Server: len=%"PRIu32, input_len);

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

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, may need to do some buffering here.
     */

    do {
        /* Allocate a transaction.
         *
         * But note that if a "protocol data unit" is not received in one
         * chunk of data, and the buffering is done on the transaction, we
         * may need to look for the transaction that this newly recieved
         * data belongs to.
         */
        MQTTTransaction *tx = MQTTTxAlloc(mqtt);
        if (unlikely(tx == NULL)) {
            SCLogNotice("Failed to allocate new MQTT tx.");
            goto end;
        }
        SCLogDebug("Allocated MQTT tx %"PRIu64".", tx->tx_id);

        /* TBD: add some events signaling parse errors. */    
        if (input_len >= MQTT_MIN_FRAME_LEN) {
            int result = MQTTPduParse(input, input_len, &tx->request_pdu);
            if (result > 0) {

                /* DISCONNECT is unacknowledged.  Immediately mark it done. */
                if (tx->request_pdu.packet_type == MQTT_DISCONNECT) {
                    tx->response_done = 1;
                }
                input += result;
                input_len -= result;
            } else {
                goto end;
            }
        } else {
            goto end;
        }
    } while (input_len > 0);
end:    
    return 0;
}

static int MQTTParseToClient(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    MQTTState *mqtt = state;
    MQTTTransaction *tx = NULL, *ttx;;
    MQTTPdu pdu;

    SCLogNotice("Parsing MQTT to Client.");

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

    do {
        /* TBD: add some events signaling parse errors. */    
        if (input_len >= MQTT_MIN_FRAME_LEN) {
            int result = MQTTPduParse(input, input_len, &pdu);
            if (result > 0) {
                if (pdu.packet_type == MQTT_PUBLISH) {
                    MQTTTransaction *tx = MQTTTxAlloc(mqtt);
                    if (likely(tx != NULL)) {
                        SCLogDebug("Allocated MQTT tx %"PRIu64".", tx->tx_id);
                        tx->request_pdu.packet_type = pdu.packet_type;
                        /* Mark PUBLISH done.  TBD: need to look at QOS value */
                        tx->response_done = 1;
                    }
                    input += result;
                    input_len -= result;

                } else {
                    /* Look up the existing transaction for this response. */
                    int found = 0;
                    TAILQ_FOREACH(ttx, &mqtt->tx_list, next) {
                        tx = ttx;
                        switch(pdu.packet_type) {
                            case MQTT_CONNACK:
                                if (tx->request_pdu.packet_type == MQTT_CONNECT)
                                    found = 1;
                                break;
                            case MQTT_PUBACK:
                                if (tx->request_pdu.packet_type == MQTT_PUBLISH)
                                    found = 1;
                                break;
                            case MQTT_PUBREL:
                            case MQTT_PUBCOMP:
                                break;
                            case MQTT_SUBACK:
                                if (tx->request_pdu.packet_type == MQTT_SUBSCRIBE)
                                    found = 1;
                                break;
                            case MQTT_PINGRESP:
                                if (tx->request_pdu.packet_type == MQTT_PINGREQ)
                                    found = 1;
                                break;
                            default:
                                break;
                        }
                        if (found)
                            break;
                    }
    
                    if (tx == NULL) {
                        SCLogNotice("Failed to find transaction for response on MQTT state %p.",
                            mqtt);
                        goto end;
                    }

                    SCLogNotice("Found transaction %"PRIu64" for response on MQTT state %p.",
                        tx->tx_id, mqtt);

                    tx->response_pdu.packet_type = pdu.packet_type;

                    /* Set the response_done flag for transaction state checking in
                     * MQTTGetStateProgress(). */
                    tx->response_done = 1;
                }

                input += result;
                input_len -= result;

            } else {
                goto end;
            }
        } else {
        }

    } while (input_len > 0);

end:
    return 0;
}

static uint64_t MQTTGetTxCnt(void *state)
{
    MQTTState *echo = state;
    SCLogDebug("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *MQTTGetTx(void *state, uint64_t tx_id)
{
    MQTTState *echo = state;
    MQTTTransaction *tx;

    SCLogDebug("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogDebug("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void MQTTSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    MQTTTransaction *tx = (MQTTTransaction *)vtx;
    tx->logged |= logger;
}

static int MQTTGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    MQTTTransaction *tx = (MQTTTransaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int MQTTGetAlstateProgressCompletionStatus(uint8_t direction) {
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
static int MQTTGetStateProgress(void *tx, uint8_t direction)
{
    MQTTTransaction *echotx = tx;

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
static DetectEngineState *MQTTGetTxDetectState(void *vtx)
{
    MQTTTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int MQTTSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    MQTTTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterMQTTParsers(void)
{
    char *proto_name = "mqtt";

    /* Check if MQTT TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("MQTT TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_MQTT, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, MQTT_DEFAULT_PORT,
                ALPROTO_MQTT, 0, MQTT_MIN_FRAME_LEN, STREAM_TOSERVER,
                MQTTProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_MQTT, 0, MQTT_MIN_FRAME_LEN,
                    MQTTProbingParser)) {
                SCLogNotice("No MQTT app-layer configuration, enabling MQTT"
                    " detection TCP detection on port %s.",
                    MQTT_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    MQTT_DEFAULT_PORT, ALPROTO_MQTT, 0,
                    MQTT_MIN_FRAME_LEN, STREAM_TOSERVER,
                    MQTTProbingParser);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for MQTT.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering MQTT protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new MQTT flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTStateAlloc, MQTTStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MQTT,
            STREAM_TOSERVER, MQTTParseToServer);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MQTT,
            STREAM_TOCLIENT, MQTTParseToClient);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTGetTxLogged, MQTTSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_MQTT,
            MQTTGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_MQTT, MQTTGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_MQTT,
            NULL, MQTTGetTxDetectState, MQTTSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_MQTT,
            MQTTGetEvents);
    }
    else {
        SCLogNotice("MQTT protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MQTT,
        MQTTParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void MQTTParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
