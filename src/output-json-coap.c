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

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-coap.h"

#ifdef HAVE_LIBJANSSON

#define min(a,b) (((a)<(b))?(a):(b))

typedef struct LogCOAPFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogCOAPFileCtx;

typedef struct LogCOAPLogThread_ {
    LogCOAPFileCtx *COAPlog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogCOAPLogThread;

static char *JsonCOAPCodeStr(uint8_t code)
{
    switch (code) {
        case COAP_REQUEST_GET:
            return "GET";
        case COAP_REQUEST_POST:
            return "POST";
        case COAP_REQUEST_PUT:
            return "PUT";
        case COAP_REQUEST_DELETE:
            return "DELETE";
        default:
            return coap_response_phrase(code);
    }
}

static int JsonCOAPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    COAPTransaction *COAPtx = tx;
    LogCOAPLogThread *thread = thread_data;
    json_t *js, *COAPjs;

    SCLogDebug("Logging COAP transaction %"PRIu64".", COAPtx->tx_id);
    
    int dir = (COAPtx->request_pdu->hdr->type == COAP_MESSAGE_CON)? 1 : 0;
#if 0
    /* direction still needs to be flipped
     * need to set Packet as TO_CLIENT */
    if (dir && PKT_IS_TOSERVER(p)) {
        p->flowflags &= !FLOW_PKT_TOSERVER;
        p->flowflags |= FLOW_PKT_TOCLIENT;
    }
#endif

    js = CreateJSONHeader((Packet *)p, dir, "coap");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    COAPjs = json_object();
    if (unlikely(COAPjs == NULL)) {
        goto error;
    }

    json_object_set_new(COAPjs, "mid", json_integer(htons(COAPtx->request_pdu->hdr->id)));

    if (COAPtx->request_pdu->hdr->type == COAP_MESSAGE_CON) {
        json_object_set_new(COAPjs, "code", json_string(JsonCOAPCodeStr(COAPtx->request_pdu->hdr->code)));
        int token_length = min(COAPtx->request_pdu->hdr->token_length, 8);
        if (token_length > 0) {
            int i;
            char token_str[8 * 3 + 1];
            for (i = 0; i < token_length; i++) {
                sprintf(&token_str[i * 3], "%02x ", COAPtx->request_pdu->hdr->token[i]);
            }
            token_str[(i * 3) - 1] = '\0';
            json_object_set_new(COAPjs, "tkn", json_string(token_str));
        }
        switch (COAPtx->request_pdu->hdr->code) {
            case COAP_REQUEST_GET:
            case COAP_REQUEST_POST:
            case COAP_REQUEST_PUT:
            case COAP_REQUEST_DELETE: {
                char uriPath[COAP_MAX_PDU_SIZE];
                int token_offset = token_length;
                int offset = 0;
                while ((COAPtx->request_pdu->hdr->token[token_offset] != '\0') &&
                       (COAPtx->request_pdu->hdr->token[token_offset] != 0xff)) {
                    int optLength = COAPtx->request_pdu->hdr->token[token_offset] & 0xf;
                    if (optLength > 0) {
                        uriPath[offset] = '/';
                        strncpy(&uriPath[offset+1], (char *)&COAPtx->request_pdu->hdr->token[token_offset+1] , optLength);
                        offset += optLength + 1;
                        uriPath[offset] = '\0';
                        token_offset += optLength + 1;
                    } else {
                        break;
                    }
                }
                if (offset > 0) {
                    json_object_set_new(COAPjs, "uri", json_string(uriPath));
                }
            }
            break;
        }
        json_object_set_new(COAPjs, "rsp_code", json_string(JsonCOAPCodeStr(COAPtx->response_pdu->hdr->code)));
    } else if (COAPtx->response_pdu->hdr->type == COAP_MESSAGE_CON) {
        json_object_set_new(COAPjs, "code", json_string(JsonCOAPCodeStr(COAPtx->response_pdu->hdr->code)));
        int token_length = min(COAPtx->response_pdu->hdr->token_length, 8);
        if (token_length > 0) {
            int i;
            char token_str[8 * 3 + 1];
            for (i = 0; i < token_length; i++) {
                sprintf(&token_str[i * 3], "%02x ", COAPtx->response_pdu->hdr->token[i]);
            }
            token_str[(i * 3) - 1] = '\0';
            json_object_set_new(COAPjs, "tkn", json_string(token_str));
        }
    }

    json_object_set_new(js, "coap", COAPjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->COAPlog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    if (COAPjs != NULL) {
        json_decref(COAPjs);
    }
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputCOAPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogCOAPFileCtx *COAPlog_ctx = (LogCOAPFileCtx *)output_ctx->data;
    SCFree(COAPlog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputCOAPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogCOAPFileCtx *COAPlog_ctx = SCCalloc(1, sizeof(*COAPlog_ctx));
    if (unlikely(COAPlog_ctx == NULL)) {
        return NULL;
    }
    COAPlog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(COAPlog_ctx);
        return NULL;
    }
    output_ctx->data = COAPlog_ctx;
    output_ctx->DeInit = OutputCOAPLogDeInitCtxSub;

    SCLogDebug("COAP log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_COAP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonCOAPLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogCOAPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogCOAP.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->COAPlog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonCOAPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogCOAPLogThread *thread = (LogCOAPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void TmModuleJsonCOAPLogRegister(void)
{
    if (ConfGetNode("app-layer.protocols.coap") == NULL) {
        return;
    }

    tmm_modules[TMM_JSONCOAPLOG].name = "JsonCOAPLog";
    tmm_modules[TMM_JSONCOAPLOG].ThreadInit = JsonCOAPLogThreadInit;
    tmm_modules[TMM_JSONCOAPLOG].ThreadDeinit = JsonCOAPLogThreadDeinit;
    tmm_modules[TMM_JSONCOAPLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONCOAPLOG].cap_flags = 0;
    tmm_modules[TMM_JSONCOAPLOG].flags = TM_FLAG_LOGAPI_TM;

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule("eve-log", "JsonCOAPLog", "eve-log.coap",
        OutputCOAPLogInitSub, ALPROTO_COAP, JsonCOAPLogger);

    SCLogDebug("COAP JSON logger registered.");
}

#else /* No JSON support. */

static TmEcode JsonCOAPLogThreadInit(ThreadVars *t, void *initdata,
    void **data)
{
    SCLogInfo("Cannot initialize JSON output for COAP. "
        "JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonCOAPLogRegister(void)
{
    tmm_modules[TMM_JSONCOAPLOG].name = "JsonCOAPLog";
    tmm_modules[TMM_JSONCOAPLOG].ThreadInit = JsonCOAPLogThreadInit;
}

#endif /* HAVE_LIBJANSSON */
