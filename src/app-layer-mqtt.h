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

#ifndef __APP_LAYER_MQTT_H__
#define __APP_LAYER_MQTT_H__

#include "detect-engine-state.h"

#include "queue.h"

void RegisterMQTTParsers(void);
void MQTTParserRegisterTests(void);

#define MQTT_CONNECT      1
#define MQTT_CONNACK      2
#define MQTT_PUBLISH      3
#define MQTT_PUBACK       4
#define MQTT_PUBREC       5
#define MQTT_PUBREL       6
#define MQTT_PUBCOMP      7
#define MQTT_SUBSCRIBE    8
#define MQTT_SUBACK       9
#define MQTT_UNSUBSCRIBE  10
#define MQTT_UNSUBACK     11
#define MQTT_PINGREQ      12
#define MQTT_PINGRESP     13
#define MQTT_DISCONNECT   14

#define MQTT_CONN_ACCEPTED 0
#define MQTT_CONN_BAD_VER  1
#define MQTT_CONN_ID_REJ   2
#define MQTT_CONN_SRV_UNAVAIL 3
#define MQTT_CONN_BAD_LOGIN 4
#define MQTT_CONN_NOT_AUTH 5

#define MQTT_PING_ACKED   0
#define MQTT_PING_LOST    1
typedef struct MQTTPdu_ {
    uint8_t   packet_type; /**< Control packet type */
    union {
        struct {
            uint8_t return_code;
        } ConnAck;
        struct {
            uint16_t packet_identifier;
            uint16_t topic_length;
            uint8_t *topic;
        } Subscribe;
        struct {
            uint16_t topic_length;
            uint16_t data_length;
            uint8_t *blob;
        } Publish;
        struct {
            uint8_t status;
        } Ping;
    };
} MQTTPdu;

typedef struct MQTTTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    MQTTPdu  request_pdu;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    MQTTPdu  response_pdu;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(MQTTTransaction_) next;

} MQTTTransaction;

typedef struct MQTTState_ {

    TAILQ_HEAD(, MQTTTransaction_) tx_list; /**< List of MQTT transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} MQTTState;


#endif /* __APP_LAYER_MQTT_H__ */
