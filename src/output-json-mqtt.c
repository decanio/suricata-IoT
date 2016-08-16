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

#include "app-layer-mqtt.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogMQTTFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogMQTTFileCtx;

typedef struct LogMQTTLogThread_ {
    LogMQTTFileCtx *MQTTlog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogMQTTLogThread;

static char *MQTTPacketTypeStr(uint8_t packetType)
{
    switch (packetType) {
        case MQTT_CONNECT:
        case MQTT_CONNACK:
            return "connect";
        case MQTT_PUBLISH:
        case MQTT_PUBACK:
        case MQTT_PUBREC:
        case MQTT_PUBCOMP:
            return "publish";
        case MQTT_SUBSCRIBE:
        case MQTT_SUBACK:
            return "subscribe";
        case MQTT_UNSUBSCRIBE:
        case MQTT_UNSUBACK:
            return "unsubscribe";
        case MQTT_PINGREQ:
        case MQTT_PINGRESP:
            return "ping";
        case MQTT_DISCONNECT:
            return "disconnect";
        default:
            return "unknown";
    }
}

static char *MQTTConnAckRetCodeStr(uint8_t return_code)
{
    switch (return_code) {
        case MQTT_CONN_ACCEPTED:
            return "accepted";
        case MQTT_CONN_BAD_VER:
            return "refused bad version";
        case MQTT_CONN_ID_REJ:
            return "refused bad version";
        case MQTT_CONN_SRV_UNAVAIL:
            return "refused server unavailable";
        case MQTT_CONN_BAD_LOGIN:
            return "refused bad username or password";
        case MQTT_CONN_NOT_AUTH:
            return "refused not authorized";
        default:
            return "unknown";
    }
}


static int JsonMQTTLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    MQTTTransaction *MQTTtx = tx;
    LogMQTTLogThread *thread = thread_data;
    json_t *js, *MQTTjs;
    char *s;

    SCLogNotice("Logging MQTT transaction %"PRIu64".", MQTTtx->tx_id);
    
    js = CreateJSONHeader((Packet *)p, 0, "mqtt");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    MQTTjs = json_object();
    if (unlikely(MQTTjs == NULL)) {
        goto error;
    }

    json_object_set_new(MQTTjs, "command", json_string(MQTTPacketTypeStr(MQTTtx->request_pdu.packet_type)));
    switch (MQTTtx->request_pdu.packet_type) {
        case MQTT_CONNECT:
            json_object_set_new(MQTTjs, "reply", json_string(MQTTConnAckRetCodeStr(MQTTtx->response_pdu.ConnAck.return_code)));

            break;
        case MQTT_SUBSCRIBE:
            s = BytesToString(MQTTtx->request_pdu.Subscribe.topic, 
                              MQTTtx->request_pdu.Subscribe.topic_length);
            if (s != NULL) {
                json_object_set_new(MQTTjs, "topic", json_string(s));
                SCFree(s);
            }
            break;
        case MQTT_PUBLISH:
            s = BytesToString(MQTTtx->request_pdu.Publish.blob, 
                              MQTTtx->request_pdu.Publish.topic_length);
            if (s != NULL) {
                json_object_set_new(MQTTjs, "topic", json_string(s));
                SCFree(s);
            }
            /* TBD: check to make sure each character is printable */
            s = BytesToString(&MQTTtx->request_pdu.Publish.blob[MQTTtx->request_pdu.Publish.topic_length], 
                              MQTTtx->request_pdu.Publish.data_length);
            if (s != NULL) {
                json_object_set_new(MQTTjs, "message", json_string(s));
                SCFree(s);
            }
            break;
            break;
        case MQTT_PINGREQ:
            json_object_set_new(MQTTjs, "status", json_string((MQTTtx->response_pdu.Ping.status == MQTT_PING_ACKED) ? "acked" : "lost"));
            break;
        default:
            break;
    }

    json_object_set_new(js, "mqtt", MQTTjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->MQTTlog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    if (MQTTjs != NULL) {
        json_decref(MQTTjs);
    }
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputMQTTLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogMQTTFileCtx *MQTTlog_ctx = (LogMQTTFileCtx *)output_ctx->data;
    SCFree(MQTTlog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputMQTTLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogMQTTFileCtx *MQTTlog_ctx = SCCalloc(1, sizeof(*MQTTlog_ctx));
    if (unlikely(MQTTlog_ctx == NULL)) {
        return NULL;
    }
    MQTTlog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(MQTTlog_ctx);
        return NULL;
    }
    output_ctx->data = MQTTlog_ctx;
    output_ctx->DeInit = OutputMQTTLogDeInitCtxSub;

    SCLogNotice("MQTT log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MQTT);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonMQTTLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogMQTTLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogMQTT.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->MQTTlog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonMQTTLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMQTTLogThread *thread = (LogMQTTLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void TmModuleJsonMQTTLogRegister(void)
{
    if (ConfGetNode("app-layer.protocols.mqtt") == NULL) {
        return;
    }

    tmm_modules[TMM_JSONMQTTLOG].name = "JsonMQTTLog";
    tmm_modules[TMM_JSONMQTTLOG].ThreadInit = JsonMQTTLogThreadInit;
    tmm_modules[TMM_JSONMQTTLOG].ThreadDeinit = JsonMQTTLogThreadDeinit;
    tmm_modules[TMM_JSONMQTTLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONMQTTLOG].cap_flags = 0;
    tmm_modules[TMM_JSONMQTTLOG].flags = TM_FLAG_LOGAPI_TM;

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule("eve-log", "JsonMQTTLog", "eve-log.mqtt",
        OutputMQTTLogInitSub, ALPROTO_MQTT, JsonMQTTLogger);

    SCLogNotice("MQTT JSON logger registered.");
}

#else /* No JSON support. */

static TmEcode JsonMQTTLogThreadInit(ThreadVars *t, void *initdata,
    void **data)
{
    SCLogInfo("Cannot initialize JSON output for MQTT. "
        "JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonMQTTLogRegister(void)
{
    tmm_modules[TMM_JSONMQTTLOG].name = "JsonMQTTLog";
    tmm_modules[TMM_JSONMQTTLOG].ThreadInit = JsonMQTTLogThreadInit;
}

#endif /* HAVE_LIBJANSSON */
