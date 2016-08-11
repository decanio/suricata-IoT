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

#ifndef __APP_LAYER_COAP_H__
#define __APP_LAYER_COAP_H__

#include "detect-engine-state.h"

#include "queue.h"

#define WITH_POSIX /* Keep COAP happy */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION
#include <coap_config.h>
#include <coap.h>

void RegisterCOAPParsers(void);
void COAPParserRegisterTests(void);

typedef struct COAPTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    coap_pdu_t *request_pdu;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    coap_pdu_t *response_pdu;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(COAPTransaction_) next;

} COAPTransaction;

typedef struct COAPState_ {

    TAILQ_HEAD(, COAPTransaction_) tx_list; /**< List of COAP transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} COAPState;

#endif /* __APP_LAYER_COAP_H__ */
