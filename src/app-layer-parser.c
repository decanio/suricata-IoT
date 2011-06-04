/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Generic App-layer parsing functions.
 */

#include "suricata-common.h"
#include "debug.h"
#include "util-unittest.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"

#include "detect-engine-state.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"

#include "util-spm.h"

#include "util-debug.h"

static uint16_t app_layer_sid = 0;
static AppLayerProto al_proto_table[ALPROTO_MAX];   /**< Application layer protocol
                                                       table mapped to their
                                                       corresponding parsers */

#define MAX_PARSERS 100
static AppLayerParserTableElement al_parser_table[MAX_PARSERS];
static uint16_t al_max_parsers = 0; /* incremented for every registered parser */

static Pool *al_result_pool = NULL;
static SCMutex al_result_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifdef DEBUG
static uint32_t al_result_pool_elmts = 0;
#endif /* DEBUG */


/** \brief Alloc a AppLayerParserResultElmt func for the pool */
static void *AlpResultElmtPoolAlloc(void *null)
{
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)SCMalloc
                                    (sizeof(AppLayerParserResultElmt));
    if (e == NULL)
        return NULL;

    memset(e, 0, sizeof(AppLayerParserResultElmt));

#ifdef DEBUG
    al_result_pool_elmts++;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
    return e;
}

static void AlpResultElmtPoolFree(void *e)
{
    AppLayerParserResultElmt *re = (AppLayerParserResultElmt *)e;

    if (re->flags & ALP_RESULT_ELMT_ALLOC) {
        if (re->data_ptr != NULL)
            SCFree(re->data_ptr);
    }
    SCFree(re);

#ifdef DEBUG
    al_result_pool_elmts--;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
}

static AppLayerParserResultElmt *AlpGetResultElmt(void)
{
    SCMutexLock(&al_result_pool_mutex);
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)PoolGet(al_result_pool);
    SCMutexUnlock(&al_result_pool_mutex);

    if (e == NULL) {
        return NULL;
    }
    e->next = NULL;
    return e;
}

static void AlpReturnResultElmt(AppLayerParserResultElmt *e)
{
    if (e->flags & ALP_RESULT_ELMT_ALLOC) {
        if (e->data_ptr != NULL)
            SCFree(e->data_ptr);
    }
    e->flags = 0;
    e->data_ptr = NULL;
    e->data_len = 0;
    e->next = NULL;

    SCMutexLock(&al_result_pool_mutex);
    PoolReturn(al_result_pool, (void *)e);
    SCMutexUnlock(&al_result_pool_mutex);
}

static void AlpAppendResultElmt(AppLayerParserResult *r, AppLayerParserResultElmt *e)
{
    if (r->head == NULL) {
        r->head = e;
        r->tail = e;
        r->cnt = 1;
    } else {
        r->tail->next = e;
        r->tail = e;
        r->cnt++;
    }
}

/**
 *  \param alloc Is ptr alloc'd (1) or a ptr to static mem (0).
 *  \retval -1 error
 *  \retval 0 ok
 */
static int AlpStoreField(AppLayerParserResult *output, uint16_t idx,
                         uint8_t *ptr, uint32_t len, uint8_t alloc)
{
    SCEnter();

    AppLayerParserResultElmt *e = AlpGetResultElmt();
    if (e == NULL) {
        SCLogError(SC_ERR_POOL_EMPTY, "App layer \"al_result_pool\" is empty");
        SCReturnInt(-1);
    }

    if (alloc == 1)
        e->flags |= ALP_RESULT_ELMT_ALLOC;

    e->name_idx = idx;
    e->data_ptr = ptr;
    e->data_len = len;
    AlpAppendResultElmt(output, e);

    SCReturnInt(0);
}

/** \brief Parse a field up to we reach the size limit
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldBySize(AppLayerParserResult *output, AppLayerParserState *pstate,
                        uint16_t field_idx, uint32_t size, uint8_t *input,
                        uint32_t input_len, uint32_t *offset)
{
    SCEnter();

    if ((pstate->store_len + input_len) < size) {
        if (pstate->store_len == 0) {
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        } else {
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }
    } else {
        if (pstate->store_len == 0) {
            int r = AlpStoreField(output, field_idx, input, size, /* static mem */0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            (*offset) += size;

            SCReturnInt(1);
        } else {
            uint32_t diff = size - pstate->store_len;

            pstate->store = SCRealloc(pstate->store, (diff + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, diff);
            pstate->store_len += diff;

            int r = AlpStoreField(output, field_idx, pstate->store,
                                  pstate->store_len, /* alloc mem */1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            (*offset) += diff;

            pstate->store = NULL;
            pstate->store_len = 0;

            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/** \brief Parse a field up to the EOF
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByEOF(AppLayerParserResult *output, AppLayerParserState *pstate,
                       uint16_t field_idx, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    if (pstate->store_len == 0) {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len 0 and EOF");

            int r = AlpStoreField(output, field_idx, input, input_len, 0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            SCReturnInt(1);
        } else {
            SCLogDebug("store_len 0 but no EOF");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len %" PRIu32 " and EOF", pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            int r = AlpStoreField(output, field_idx, pstate->store, pstate->store_len, 1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            pstate->store = NULL;
            pstate->store_len = 0;

            SCReturnInt(1);
        } else {
            SCLogDebug("store_len %" PRIu32 " but no EOF", pstate->store_len);

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }

    }

    SCReturnInt(0);
}

/** \brief Parse a field up to a delimeter.
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByDelimiter(AppLayerParserResult *output, AppLayerParserState *pstate,
                            uint16_t field_idx, const uint8_t *delim, uint8_t delim_len,
                            uint8_t *input, uint32_t input_len, uint32_t *offset)
{
    SCEnter();
    SCLogDebug("pstate->store_len %" PRIu32 ", delim_len %" PRIu32 "",
                pstate->store_len, delim_len);

    if (pstate->store_len == 0) {
        uint8_t *ptr = SpmSearch(input, input_len, (uint8_t*)delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            SCLogDebug(" len %" PRIu32 "", len);

            int r = AlpStoreField(output, field_idx, input, len, 0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            (*offset) += (len + delim_len);
            SCReturnInt(1);
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                SCLogDebug("delim not found and EOF");
                SCReturnInt(0);
            }

            SCLogDebug("delim not found, continue");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        uint8_t *ptr = SpmSearch(input, input_len, (uint8_t*)delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            SCLogDebug("len %" PRIu32 " + %" PRIu32 " = %" PRIu32 "", len,
                        pstate->store_len, len + pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, len);
            pstate->store_len += len;

            int r = AlpStoreField(output, field_idx, pstate->store,
                                  pstate->store_len, 1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            pstate->store = NULL;
            pstate->store_len = 0;

            (*offset) += (len + delim_len);
            SCReturnInt(1);
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                /* if the input len is smaller than the delim len we search the
                 * pstate->store since we may match there. */
                if (delim_len > input_len) {
                    /* delimiter field not found, so store the result for the
                     * next run */
                    pstate->store = SCRealloc(pstate->store, (input_len +
                                            pstate->store_len));
                    if (pstate->store == NULL)
                        SCReturnInt(-1);

                    memcpy(pstate->store+pstate->store_len, input, input_len);
                    pstate->store_len += input_len;
                    SCLogDebug("input_len < delim_len, checking pstate->store");

                    if (pstate->store_len >= delim_len) {
                        ptr = SpmSearch(pstate->store, pstate->store_len, (uint8_t*)delim,
                                        delim_len);
                        if (ptr != NULL) {
                            SCLogDebug("now we found the delim");

                            uint32_t len = ptr - pstate->store;
                            int r = AlpStoreField(output, field_idx,
                                                  pstate->store, len, 1);
                            if (r == -1) {
                                SCLogError(SC_ERR_ALPARSER, "Failed to store "
                                           "field value");
                                SCReturnInt(-1);
                            }

                            pstate->store = NULL;
                            pstate->store_len = 0;

                            (*offset) += (input_len);

                            SCLogDebug("offset %" PRIu32 "", (*offset));
                            SCReturnInt(1);
                        }
                        goto free_and_return;
                    }
                    goto free_and_return;
                }
            free_and_return:
                SCLogDebug("not found and EOF, so free what we have so far.");
                SCFree(pstate->store);
                pstate->store = NULL;
                pstate->store_len = 0;
                SCReturnInt(0);
            }

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            /* if the input len is smaller than the delim len we search the
             * pstate->store since we may match there. */
            if (delim_len > input_len && delim_len <= pstate->store_len) {
                SCLogDebug("input_len < delim_len, checking pstate->store");

                ptr = SpmSearch(pstate->store, pstate->store_len, (uint8_t*)delim, delim_len);
                if (ptr != NULL) {
                    SCLogDebug("now we found the delim");

                    uint32_t len = ptr - pstate->store;
                    int r = AlpStoreField(output, field_idx, pstate->store, len, 1);
                    if (r == -1) {
                        SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                        SCReturnInt(-1);
                    }
                    pstate->store = NULL;
                    pstate->store_len = 0;

                    (*offset) += (input_len);

                    SCLogDebug("ffset %" PRIu32 "", (*offset));
                    SCReturnInt(1);
                }
            }
        }

    }

    SCReturnInt(0);
}

/** app layer id counter */
static uint8_t al_module_id = 0;

/** \brief Get a unique app layer id
 */
uint8_t AppLayerRegisterModule(void) {
    uint8_t id = al_module_id;
    al_module_id++;
    return id;
}

uint8_t AppLayerGetStorageSize(void) {
    return al_module_id;
}

/** \brief Get the Parsers id for storing the parser state.
 *
 * \retval Parser subsys id
 */
uint16_t AppLayerParserGetStorageId(void)
{
    return app_layer_sid;
}

uint16_t AppLayerGetProtoByName(const char *name)
{
    uint8_t u = 1;
    SCLogDebug("looking for name %s", name);

    for ( ; u < ALPROTO_MAX; u++) {
        if (al_proto_table[u].name == NULL)
            continue;

        SCLogDebug("name %s proto %"PRIu16"",
            al_proto_table[u].name, u);

        if (strcasecmp(name,al_proto_table[u].name) == 0) {
            SCLogDebug("match, returning %"PRIu16"", u);
            return u;
        }
    }

    return ALPROTO_UNKNOWN;
}

/** \brief Description: register a parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 * \param max_outputs max number of unique outputs the parser can generate
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterParser(char *name, uint16_t proto, uint16_t parser_id,
                           int (*AppLayerParser)(Flow *f, void *protocol_state,
                            AppLayerParserState *parser_state, uint8_t *input,
                            uint32_t input_len, AppLayerParserResult *output),
                            char *dependency)
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].proto = proto;
    al_parser_table[al_max_parsers].parser_local_id = parser_id;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    SCLogDebug("registered %p at proto %" PRIu32 ", al_proto_table idx "
               "%" PRIu32 ", storage_id %" PRIu32 ", parser_local_id %" PRIu32 "",
                AppLayerParser, proto, al_max_parsers,
                al_proto_table[proto].storage_id, parser_id);
    return 0;
}

/** \brief Description: register a protocol parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterProto(char *name, uint8_t proto, uint8_t flags,
                         int (*AppLayerParser)(Flow *f, void *protocol_state,
                         AppLayerParserState *parser_state, uint8_t *input,
                         uint32_t input_len, AppLayerParserResult *output))
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    al_proto_table[proto].name = name;

    /* create proto, direction -- parser mapping */
    if (flags & STREAM_TOSERVER) {
        al_proto_table[proto].to_server = al_max_parsers;
    } else if (flags & STREAM_TOCLIENT) {
        al_proto_table[proto].to_client = al_max_parsers;
    }

    if (al_proto_table[proto].storage_id == 0) {
        al_proto_table[proto].storage_id = AppLayerRegisterModule();
    }

    SCLogDebug("registered %p at proto %" PRIu32 " flags %02X, al_proto_table "
                "idx %" PRIu32 ", storage_id %" PRIu32 " %s", AppLayerParser, proto,
                flags, al_max_parsers, al_proto_table[proto].storage_id, name);
    return 0;
}

void AppLayerRegisterStateFuncs(uint16_t proto, void *(*StateAlloc)(void),
                                void (*StateFree)(void *))
{
    al_proto_table[proto].StateAlloc = StateAlloc;
    al_proto_table[proto].StateFree = StateFree;
}

void AppLayerRegisterTransactionIdFuncs(uint16_t proto,
        void (*StateUpdateTransactionId)(void *state, uint16_t *), void (*StateTransactionFree)(void *, uint16_t))
{
    al_proto_table[proto].StateUpdateTransactionId = StateUpdateTransactionId;
    al_proto_table[proto].StateTransactionFree = StateTransactionFree;
}

/** \brief Indicate to the app layer parser that a logger is active
 *         for this protocol.
 */
void AppLayerRegisterLogger(uint16_t proto) {
    al_proto_table[proto].logger = TRUE;
}


uint16_t AlpGetStateIdx(uint16_t proto)
{
    return al_proto_table[proto].storage_id;
}

AppLayerParserStateStore *AppLayerParserStateStoreAlloc(void)
{
    AppLayerParserStateStore *s = (AppLayerParserStateStore *)SCMalloc
                                    (sizeof(AppLayerParserStateStore));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(AppLayerParserStateStore));

    /* when we start, we're working with transaction id 1 */
    s->avail_id = 1;

    return s;
}

/** \brief free a AppLayerParserStateStore structure
 *  \param s AppLayerParserStateStore structure to free */
void AppLayerParserStateStoreFree(AppLayerParserStateStore *s)
{
    if (s->to_server.store != NULL)
        SCFree(s->to_server.store);
    if (s->to_client.store != NULL)
        SCFree(s->to_client.store);

    SCFree(s);
}

static void AppLayerParserResultCleanup(AppLayerParserResult *result)
{
    AppLayerParserResultElmt *e = result->head;
    while (e != NULL) {
        AppLayerParserResultElmt *next_e = e->next;

        result->head = next_e;
        if (next_e == NULL)
            result->tail = NULL;
        result->cnt--;

        AlpReturnResultElmt(e);
        e = next_e;
    }
}

static int AppLayerDoParse(Flow *f, void *app_layer_state, AppLayerParserState *parser_state,
                           uint8_t *input, uint32_t input_len, uint16_t parser_idx,
                           uint16_t proto)
{
    SCEnter();
    int retval = 0;
    AppLayerParserResult result = { NULL, NULL, 0 };

    SCLogDebug("parser_idx %" PRIu32 "", parser_idx);
    //printf("--- (%u)\n", input_len);
    //PrintRawDataFp(stdout, input,input_len);
    //printf("---\n");

    /* invoke the parser */
    int r = al_parser_table[parser_idx].AppLayerParser(f, app_layer_state,
                                       parser_state, input, input_len, &result);
    if (r < 0) {
        if (r == -1) {
            AppLayerParserResultCleanup(&result);
            SCReturnInt(-1);
        } else {
            BUG_ON(r);  /* this is not supposed to happen!! */
        }
    }

    /* process the result elements */
    AppLayerParserResultElmt *e = result.head;
    for (; e != NULL; e = e->next) {
        SCLogDebug("e %p e->name_idx %" PRIu32 ", e->data_ptr %p, e->data_len "
                   "%" PRIu32 ", map_size %" PRIu32 "", e, e->name_idx,
                   e->data_ptr, e->data_len, al_proto_table[proto].map_size);

        /* no parser defined for this field. */
        if (e->name_idx >= al_proto_table[proto].map_size ||
                al_proto_table[proto].map[e->name_idx] == NULL)
        {
            SCLogDebug("no parser for proto %" PRIu32 ", parser_local_id "
                        "%" PRIu32 "", proto, e->name_idx);
            continue;
        }

        uint16_t idx = al_proto_table[proto].map[e->name_idx]->parser_id;

        /* prepare */
        uint16_t tmp = parser_state->parse_field;
        parser_state->parse_field = 0;
        parser_state->flags |= APP_LAYER_PARSER_EOF;

        r = AppLayerDoParse(f, app_layer_state, parser_state, e->data_ptr,
                            e->data_len, idx, proto);

        /* restore */
        parser_state->flags &= ~APP_LAYER_PARSER_EOF;
        parser_state->parse_field = tmp;

        /* bail out on a serious error */
        if (r < 0) {
            if (r == -1) {
                retval = -1;
                break;
            } else {
                BUG_ON(r);
            }
        }
    }

    AppLayerParserResultCleanup(&result);
    SCReturnInt(retval);
}

/** \brief remove obsolete (inspected and logged) transactions */
static int AppLayerTransactionsCleanup(AppLayerProto *p, AppLayerParserStateStore *parser_state_store, void *app_layer_state) {
    SCEnter();

    uint16_t obsolete = 0;

    if (p->StateTransactionFree == NULL) {
        SCLogDebug("no StateTransactionFree function");
        goto end;
    }

    if (p->logger == TRUE) {
        uint16_t low = (parser_state_store->logged_id < parser_state_store->inspect_id) ?
            parser_state_store->logged_id : parser_state_store->inspect_id;

        obsolete = low - parser_state_store->base_id;

        SCLogDebug("low %"PRIu16" (logged %"PRIu16", inspect %"PRIu16"), base_id %"PRIu16", obsolete %"PRIu16", avail_id %"PRIu16,
                low, parser_state_store->logged_id, parser_state_store->inspect_id, parser_state_store->base_id, obsolete, parser_state_store->avail_id);
    } else {
        obsolete = parser_state_store->inspect_id - parser_state_store->base_id;
    }

    SCLogDebug("obsolete transactions: %"PRIu16, obsolete);

    /* call the callback on the obsolete transactions */
    while ((obsolete--)) {
        p->StateTransactionFree(app_layer_state, parser_state_store->base_id);
        parser_state_store->base_id++;
    }

    SCLogDebug("base_id %"PRIu16, parser_state_store->base_id);

end:
    SCReturnInt(0);
}

#ifdef DEBUG
uint32_t applayererrors = 0;
uint32_t applayerhttperrors = 0;
#endif

/**
 * \brief Layer 7 Parsing main entry point.
 *
 * \param f Properly initialized and locked flow.
 * \param proto L7 proto, e.g. ALPROTO_HTTP
 * \param flags Stream flags
 * \param input Input L7 data
 * \param input_len Length of the input data.
 *
 * \retval -1 error
 * \retval 0 ok
 */
int AppLayerParse(Flow *f, uint8_t proto, uint8_t flags, uint8_t *input,
                  uint32_t input_len)
{
    SCEnter();

    uint16_t parser_idx = 0;
    AppLayerProto *p = &al_proto_table[proto];
    TcpSession *ssn = NULL;

    /* Used only if it's TCP */
    ssn = f->protoctx;

    /** Do this check before calling AppLayerParse */
    if (flags & STREAM_GAP) {
        SCLogDebug("stream gap detected (missing packets), this is not yet supported.");
        goto error;
    }

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = NULL;

    if (f->aldata != NULL) {
        parser_state_store = (AppLayerParserStateStore *)
                                                    f->aldata[app_layer_sid];
        if (parser_state_store == NULL) {
            parser_state_store = AppLayerParserStateStoreAlloc();
            if (parser_state_store == NULL)
                goto error;

            f->aldata[app_layer_sid] = (void *)parser_state_store;
        }
    } else {
        SCLogDebug("No App Layer Data");
        /* Nothing is there to clean up, so just return from here after setting
         * up the no reassembly flags */
        FlowSetSessionNoApplayerInspectionFlag(f);

        SCReturnInt(-1);
    }

    parser_state_store->version++;
    SCLogDebug("app layer state version incremented to %"PRIu16,
            parser_state_store->version);

    AppLayerParserState *parser_state = NULL;
    if (flags & STREAM_TOSERVER) {
        SCLogDebug("to_server msg (flow %p)", f);

        parser_state = &parser_state_store->to_server;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_server;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            SCLogDebug("using parser %" PRIu32 " we stored before (to_server)",
                        parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    } else {
        SCLogDebug("to_client msg (flow %p)", f);

        parser_state = &parser_state_store->to_client;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_client;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            SCLogDebug("using parser %" PRIu32 " we stored before (to_client)",
                        parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    }

    if (parser_idx == 0 || parser_state->flags & APP_LAYER_PARSER_DONE) {
        SCLogDebug("no parser for protocol %" PRIu32 "", proto);
        SCReturnInt(0);
    }

    if (flags & STREAM_EOF)
        parser_state->flags |= APP_LAYER_PARSER_EOF;

    /* See if we already have a 'app layer' state */
    void *app_layer_state = NULL;
    app_layer_state = f->aldata[p->storage_id];

    if (app_layer_state == NULL) {
        /* lock the allocation of state as we may
         * alloc more than one otherwise */
        app_layer_state = p->StateAlloc();
        if (app_layer_state == NULL) {
            goto error;
        }

        f->aldata[p->storage_id] = app_layer_state;
        SCLogDebug("alloced new app layer state %p (p->storage_id %u, name %s)",
                app_layer_state, p->storage_id, al_proto_table[f->alproto].name);
    } else {
        SCLogDebug("using existing app layer state %p (p->storage_id %u, name %s))",
                app_layer_state, p->storage_id, al_proto_table[f->alproto].name);
    }

    /* invoke the recursive parser, but only on data. We may get empty msgs on EOF */
    if (input_len > 0) {
        int r = AppLayerDoParse(f, app_layer_state, parser_state, input, input_len,
                parser_idx, proto);
        if (r < 0)
            goto error;
    }

    /* set the packets to no inspection and reassembly if required */
    if (parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        FlowSetNoPayloadInspectionFlag(f);
        FlowSetSessionNoApplayerInspectionFlag(f);

        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (parser_state->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
            if (ssn != NULL) {
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                        flags & STREAM_TOCLIENT ? 1 : 0);
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                        flags & STREAM_TOSERVER ? 1 : 0);
            }
        }
    }

    /* update the transaction id */
    if (p->StateUpdateTransactionId != NULL) {
        p->StateUpdateTransactionId(app_layer_state, &parser_state_store->avail_id);

        /* next, see if we can get rid of transactions now */
        AppLayerTransactionsCleanup(p, parser_state_store, app_layer_state);
    }
    if (parser_state->flags & APP_LAYER_PARSER_EOF) {
        SCLogDebug("eof, flag Transaction id's");
        parser_state_store->id_flags |= APP_LAYER_TRANSACTION_EOF;
    }

    SCReturnInt(0);
error:
    if (ssn != NULL) {
#ifdef DEBUG
        applayererrors++;
        if (f->alproto == ALPROTO_HTTP)
            applayerhttperrors++;
#endif
        /* Set the no app layer inspection flag for both
         * the stream in this Flow */
        FlowSetSessionNoApplayerInspectionFlag(f);

        if (f->src.family == AF_INET) {
            char src[16];
            char dst[16];
            inet_ntop(AF_INET, (const void*)&f->src.addr_data32[0], src,
                      sizeof (src));
            inet_ntop(AF_INET, (const void*)&f->dst.addr_data32[0], dst,
                      sizeof (dst));

            SCLogError(SC_ERR_ALPARSER, "Error occured in parsing \"%s\" app layer "
                "protocol, using network protocol %"PRIu8", source IP "
                "address %s, destination IP address %s, src port %"PRIu16" and "
                "dst port %"PRIu16"", al_proto_table[f->alproto].name,
                f->proto, src, dst, f->sp, f->dp);
        } else {
            char dst6[46];
            char src6[46];

            inet_ntop(AF_INET6, (const void*)&f->src.addr_data32, src6,
                      sizeof (src6));
            inet_ntop(AF_INET6, (const void*)&f->dst.addr_data32, dst6,
                      sizeof (dst6));

            SCLogError(SC_ERR_ALPARSER, "Error occured in parsing \"%s\" app layer "
                "protocol, using network protocol %"PRIu8", source IPv6 "
                "address %s, destination IPv6 address %s, src port %"PRIu16" and "
                "dst port %"PRIu16"", al_proto_table[f->alproto].name,
                f->proto, src6, dst6, f->sp, f->dp);
        }
    }

    SCReturnInt(-1);
}

/** \brief get the base transaction id */
int AppLayerTransactionGetBaseId(Flow *f) {
    SCEnter();

    /* Get the parser state (if any) */
    if (f->aldata == NULL) {
        SCLogDebug("no aldata");
        goto error;
    }

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->aldata[app_layer_sid];

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    SCReturnInt((int)parser_state_store->base_id);

error:
    SCReturnInt(-1);
}

/** \brief get the base transaction id */
int AppLayerTransactionGetInspectId(Flow *f) {
    SCEnter();

    /* Get the parser state (if any) */
    if (f->aldata == NULL) {
        SCLogDebug("no aldata");
        goto error;
    }

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->aldata[app_layer_sid];

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    SCReturnInt((int)parser_state_store->inspect_id);

error:
    SCReturnInt(-1);
}

/** \brief get the highest loggable transaction id */
int AppLayerTransactionGetLoggableId(Flow *f) {
    SCEnter();

    /* Get the parser state (if any) */
    if (f->aldata == NULL) {
        SCLogDebug("no aldata");
        goto error;
    }

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->aldata[app_layer_sid];

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    int id = 0;

    if (parser_state_store->id_flags & APP_LAYER_TRANSACTION_EOF) {
        SCLogDebug("eof, return current transaction as well");
        id = (int)(parser_state_store->avail_id);
    } else {
        id = (int)(parser_state_store->avail_id - 1);
    }

    SCReturnInt(id);

error:
    SCReturnInt(-1);
}

/** \brief get the highest loggable transaction id */
void AppLayerTransactionUpdateLoggedId(Flow *f) {
    SCEnter();

    /* Get the parser state (if any) */
    if (f->aldata == NULL) {
        SCLogDebug("no aldata");
        goto error;
    }

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->aldata[app_layer_sid];

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    parser_state_store->logged_id++;
    SCReturn;

error:
    SCReturn;
}
/** \brief get the highest loggable transaction id */
int AppLayerTransactionGetLoggedId(Flow *f) {
    SCEnter();

    /* Get the parser state (if any) */
    if (f->aldata == NULL) {
        SCLogDebug("no aldata");
        goto error;
    }

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->aldata[app_layer_sid];

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    SCReturnInt((int)parser_state_store->logged_id);

error:
    SCReturnInt(-1);
}

/**
 *  \brief get the version of the state in a direction
 *
 *  \param f LOCKED flow
 *  \param direction STREAM_TOSERVER or STREAM_TOCLIENT
 */
uint16_t AppLayerGetStateVersion(Flow *f) {
    SCEnter();
    uint16_t version = 0;
    AppLayerParserStateStore *parser_state_store = NULL;

    /* Get the parser state (if any) */
    if (f->aldata != NULL) {
        parser_state_store = (AppLayerParserStateStore *)f->aldata[app_layer_sid];
        if (parser_state_store != NULL) {
            version = parser_state_store->version;
        }
    }

    SCReturnUInt(version);
}

/**
 *  \param f LOCKED flow
 *  \param direction STREAM_TOSERVER or STREAM_TOCLIENT
 *
 *  \retval 2 current transaction done, new available
 *  \retval 1 current transaction done, no new (yet)
 *  \retval 0 current transaction is not done yet
 */
int AppLayerTransactionUpdateInspectId(Flow *f, char direction)
{
    SCEnter();

    int r = 0;

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = NULL;

    if (f->aldata != NULL) {
        parser_state_store = (AppLayerParserStateStore *)f->aldata[app_layer_sid];
        if (parser_state_store != NULL) {
            /* update inspect_id and see if it there are other transactions
             * as well */

            SCLogDebug("avail_id %"PRIu16", inspect_id %"PRIu16,
                    parser_state_store->avail_id, parser_state_store->inspect_id);

            if (direction == STREAM_TOSERVER)
                parser_state_store->id_flags |= APP_LAYER_TRANSACTION_TOSERVER;
            else
                parser_state_store->id_flags |= APP_LAYER_TRANSACTION_TOCLIENT;

            if ((parser_state_store->inspect_id+1) < parser_state_store->avail_id &&
                    (parser_state_store->id_flags & APP_LAYER_TRANSACTION_TOCLIENT) &&
                    (parser_state_store->id_flags & APP_LAYER_TRANSACTION_TOSERVER))
            {
                parser_state_store->id_flags &=~ APP_LAYER_TRANSACTION_TOCLIENT;
                parser_state_store->id_flags &=~ APP_LAYER_TRANSACTION_TOSERVER;

                parser_state_store->inspect_id++;
                if (parser_state_store->inspect_id < parser_state_store->avail_id) {
                    /* done and more transactions available */
                    r = 2;

                    SCLogDebug("inspect_id %"PRIu16", avail_id %"PRIu16,
                            parser_state_store->inspect_id,
                            parser_state_store->avail_id);
                } else {
                    /* done but no more transactions available */
                    r = 1;

                    SCLogDebug("inspect_id %"PRIu16", avail_id %"PRIu16,
                            parser_state_store->inspect_id,
                            parser_state_store->avail_id);
                }
            }
        }
    }

    SCReturnInt(r);
}

void RegisterAppLayerParsers(void)
{
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    app_layer_sid = AppLayerRegisterModule();

    /** setup result pool
     * \todo Per thread pool */
    al_result_pool = PoolInit(1000,250,AlpResultElmtPoolAlloc,NULL,AlpResultElmtPoolFree);

    RegisterHTPParsers();
    RegisterSSLParsers();
    RegisterSMBParsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    RegisterSSHParsers();
    RegisterSMTPParsers();

    /** IMAP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_IMAP, "|2A 20|OK|20|", 5, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_IMAP, "1|20|capability", 12, 0, STREAM_TOSERVER);

    /** MSN Messenger */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOSERVER);

    /** Jabber */
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOCLIENT);
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOSERVER);

    return;
}

void AppLayerParserCleanupState(Flow *f)
{
    if (f == NULL) {
        SCLogDebug("no flow");
        return;
    }
    if (f->alproto >= ALPROTO_MAX) {
        SCLogDebug("app layer proto unknown");
        return;
    }

    /* free the parser protocol state */
    AppLayerProto *p = &al_proto_table[f->alproto];
    if (p->StateFree != NULL && f->aldata != NULL) {
        if (f->aldata[p->storage_id] != NULL) {
            SCLogDebug("calling StateFree");
            p->StateFree(f->aldata[p->storage_id]);
            f->aldata[p->storage_id] = NULL;
        }
    }

    /* free the app layer parser api state */
    if (f->aldata != NULL) {
        if (f->aldata[app_layer_sid] != NULL) {
            SCLogDebug("calling AppLayerParserStateStoreFree");
            AppLayerParserStateStoreFree(f->aldata[app_layer_sid]);
            f->aldata[app_layer_sid] = NULL;
        }

        //StreamTcpDecrMemuse((uint32_t)(StreamL7GetStorageSize() * sizeof(void *)));
        SCFree(f->aldata);
        f->aldata = NULL;
    }
}

/** \brief Create a mapping between the individual parsers local field id's
 *         and the global field parser id's.
 *
 */
void AppLayerParsersInitPostProcess(void)
{
    uint16_t u16 = 0;

    /* build local->global mapping */
    for (u16 = 1; u16 <= al_max_parsers; u16++) {
        /* no local parser */
        if (al_parser_table[u16].parser_local_id == 0)
            continue;

        if (al_parser_table[u16].parser_local_id >
                al_proto_table[al_parser_table[u16].proto].map_size)
        {
            al_proto_table[al_parser_table[u16].proto].map_size =
                                           al_parser_table[u16].parser_local_id;
        }
        SCLogDebug("map_size %" PRIu32 "", al_proto_table
                                        [al_parser_table[u16].proto].map_size);
    }

    /* for each proto, alloc the map array */
    for (u16 = 0; u16 < ALPROTO_MAX; u16++) {
        if (al_proto_table[u16].map_size == 0)
            continue;

        al_proto_table[u16].map_size++;
        al_proto_table[u16].map = (AppLayerLocalMap **)SCMalloc
                                    (al_proto_table[u16].map_size *
                                        sizeof(AppLayerLocalMap *));
        if (al_proto_table[u16].map == NULL) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered in AppLayerParsersInitPostProcess. Exiting...");
            exit(EXIT_FAILURE);
        }
        memset(al_proto_table[u16].map, 0, al_proto_table[u16].map_size *
                sizeof(AppLayerLocalMap *));

        uint16_t u = 0;
        for (u = 1; u <= al_max_parsers; u++) {
            /* no local parser */
            if (al_parser_table[u].parser_local_id == 0)
                continue;

            if (al_parser_table[u].proto != u16)
                continue;

            uint16_t parser_local_id = al_parser_table[u].parser_local_id;
            SCLogDebug("parser_local_id: %" PRIu32 "", parser_local_id);

            if (parser_local_id < al_proto_table[u16].map_size) {
                al_proto_table[u16].map[parser_local_id] = SCMalloc(sizeof(AppLayerLocalMap));
                if (al_proto_table[u16].map[parser_local_id] == NULL) {
                    exit(EXIT_FAILURE);
                }

                al_proto_table[u16].map[parser_local_id]->parser_id = u;
            }
        }
    }

    for (u16 = 0; u16 < ALPROTO_MAX; u16++) {
        if (al_proto_table[u16].map_size == 0)
            continue;

        if (al_proto_table[u16].map == NULL)
            continue;

        uint16_t x = 0;
        for (x = 0; x < al_proto_table[u16].map_size; x++) {
            if (al_proto_table[u16].map[x] == NULL)
                continue;

           SCLogDebug("al_proto_table[%" PRIu32 "].map[%" PRIu32 "]->parser_id:"
                      " %" PRIu32 "", u16, x, al_proto_table[u16].map[x]->parser_id);
        }
    }
}

/********************************Probing Parsers*******************************/

//AppLayerProbingParser *probing_parsers = NULL;

static AppLayerProbingParserElement *
AppLayerCreateAppLayerProbingParserElement(const char *al_proto_name,
                                           uint16_t al_proto,
                                           uint16_t min_depth,
                                           uint16_t max_depth,
                                           uint16_t port,
                                           uint8_t priority,
                                           uint8_t top,
                                           uint16_t (*AppLayerProbingParser)
                                           (uint8_t *input, uint32_t input_len))
{
    AppLayerProbingParserElement *pe = SCMalloc(sizeof(AppLayerProbingParserElement));
    if (pe == NULL) {
        return NULL;
    }

    pe->al_proto_name = al_proto_name;
    pe->al_proto = al_proto;
    pe->min_depth = min_depth;
    pe->max_depth = max_depth;
    pe->port = port;
    pe->priority = priority;
    pe->top = top;
    pe->ProbingParser = AppLayerProbingParser;
    pe->next = NULL;

    if (max_depth != 0 && min_depth > max_depth) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  min_depth > max_depth");
        goto error;
    }
    if (al_proto <= ALPROTO_UNKNOWN || al_proto >= ALPROTO_MAX) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to register "
                   "the probing parser.  Invalid alproto - %d", al_proto);
        goto error;
    }
    if (AppLayerProbingParser == NULL) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  Probing parser func NULL");
        goto error;
    }

    return pe;
 error:
    SCFree(pe);
    return NULL;
}

static void AppLayerInsertNewProbingParserElement(AppLayerProbingParser **probing_parsers,
                                                  AppLayerProbingParserElement *new_pe,
                                                  uint8_t flags)
{
    AppLayerProbingParser *pp = probing_parsers[0];
    while (pp != NULL) {
        if (pp->port == new_pe->port) {
            break;
        }
        pp = pp->next;
    }

    if (pp == NULL) {
        AppLayerProbingParser *new_pp = SCMalloc(sizeof(AppLayerProbingParser));
        if (new_pp == NULL)
            return;
        memset(new_pp, 0, sizeof(AppLayerProbingParser));

        new_pp->port = new_pe->port;

        if (probing_parsers[0] == NULL) {
            probing_parsers[0] = new_pp;
        } else {
            AppLayerProbingParser *pp = probing_parsers[0];
            while (pp->next != NULL) {
                pp = pp->next;
            }
            pp->next = new_pp;
        }

        pp = new_pp;
    }

    AppLayerProbingParserElement *pe = NULL;
    if (flags & STREAM_TOSERVER) {
        pe = pp->toserver;
    } else {
        pe = pp->toclient;
    }

    if (pe == NULL) {
        if (flags & STREAM_TOSERVER) {
            pp->toserver = new_pe;
            pp->toserver_max_depth = new_pe->max_depth;
        } else {
            pp->toclient = new_pe;
            pp->toclient_max_depth = new_pe->max_depth;
        }
    } else {
        uint8_t break_priority;
        if (new_pe->top) {
            break_priority = new_pe->priority;
        } else {
            break_priority = new_pe->priority + 1;
        }

        AppLayerProbingParserElement *prev_pe = pe;
        while (pe != NULL) {
            if (pe->priority < break_priority) {
                prev_pe = pe;
                pe = pe->next;
                continue;
            }
            break;
        }
        if (prev_pe == pe) {
            if (flags & STREAM_TOSERVER) {
                new_pe->next = pp->toserver;
                pp->toserver = new_pe;
            } else {
                new_pe->next = pp->toclient;
                pp->toclient = new_pe;
            }
        } else {
            new_pe->next = prev_pe->next;
            prev_pe->next = new_pe;
        }

        if (flags & STREAM_TOSERVER) {
            if (new_pe->max_depth == 0) {
                pp->toserver_max_depth = 0;
            } else {
                if (pp->toserver_max_depth != 0 &&
                    pp->toserver_max_depth < new_pe->max_depth) {
                    pp->toserver_max_depth = new_pe->max_depth;
                }
            }
        } else {
            if (new_pe->max_depth == 0) {
                pp->toclient_max_depth = 0;
            } else {
                if (pp->toclient_max_depth != 0 &&
                    pp->toclient_max_depth < new_pe->max_depth) {
                    pp->toclient_max_depth = new_pe->max_depth;
                }
            }
        } /* else - if (flags & STREAM_TOSERVER) */

    } /* else - if (pe == NULL) */

    return;
}

void AppLayerPrintProbingParsers(AppLayerProbingParser *pp)
{
    AppLayerProbingParserElement *pe = NULL;

    printf("\n");
    while (pp != NULL) {
        printf("Port: %"PRIu16 "\n", pp->port);
        printf("    to_server: max-depth: %"PRIu16 "\n", pp->toserver_max_depth);
        pe = pp->toserver;
        while (pe != NULL) {
            printf("        name: %s\n", pe->al_proto_name);

            if (pe->al_proto == ALPROTO_HTTP)
                printf("        alproto: ALPROTO_HTTP\n");
            else if (pe->al_proto == ALPROTO_FTP)
                printf("        alproto: ALPROTO_FTP\n");
            else if (pe->al_proto == ALPROTO_SMTP)
                printf("        alproto: ALPROTO_SMTP\n");
            else if (pe->al_proto == ALPROTO_TLS)
                printf("        alproto: ALPROTO_TLS\n");
            else if (pe->al_proto == ALPROTO_SSH)
                printf("        alproto: ALPROTO_SSH\n");
            else if (pe->al_proto == ALPROTO_IMAP)
                printf("        alproto: ALPROTO_IMAP\n");
            else if (pe->al_proto == ALPROTO_MSN)
                printf("        alproto: ALPROTO_MSN\n");
            else if (pe->al_proto == ALPROTO_JABBER)
                printf("        alproto: ALPROTO_JABBER\n");
            else if (pe->al_proto == ALPROTO_SMB)
                printf("        alproto: ALPROTO_SMB\n");
            else if (pe->al_proto == ALPROTO_SMB2)
                printf("        alproto: ALPROTO_SMB2\n");
            else if (pe->al_proto == ALPROTO_DCERPC)
                printf("        alproto: ALPROTO_DCERPC\n");
            else if (pe->al_proto == ALPROTO_DCERPC_UDP)
                printf("        alproto: ALPROTO_DCERPC_UDP\n");
            else
                printf("impossible\n");

            printf("        port: %"PRIu16 "\n", pe->port);

            if (pe->priority == APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
                printf("        priority: HIGH\n");
            else if (pe->priority == APP_LAYER_PROBING_PARSER_PRIORITY_MEDIUM)
                printf("        priority: MEDIUM\n");
            else if (pe->priority == APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
                printf("        priority: LOW\n");
            else
                printf("        priority: impossible\n");

            printf("        top: %"PRIu8 "\n", pe->top);

            printf("        min_depth: %"PRIu32 "\n", pe->min_depth);
            printf("        max_depth: %"PRIu32 "\n", pe->max_depth);

            printf("\n");
            pe = pe->next;
        }
        printf("    to_client: max-depth: %"PRIu16 "\n", pp->toclient_max_depth);
        pp = pp->next;
    }

    return;
}

void AppLayerRegisterProbingParser(AlpProtoDetectCtx *ctx,
                                   uint16_t port,
                                   uint16_t ip_proto,
                                   const char *al_proto_name,
                                   uint16_t al_proto,
                                   uint16_t min_depth,
                                   uint16_t max_depth,
                                   uint8_t flags,
                                   uint8_t priority,
                                   uint8_t top,
                                   uint16_t (*ProbingParser)
                                   (uint8_t *input, uint32_t input_len))
{
    AppLayerProbingParser **probing_parsers = &ctx->probing_parsers;
    AppLayerProbingParserElement *pe = NULL;
    AppLayerProbingParser *pp = AppLayerGetProbingParsers(probing_parsers[0],
                                                          ip_proto, port);
    if (pp != NULL) {
        if (flags & STREAM_TOSERVER) {
            pe = pp->toserver;
        } else {
            pe = pp->toclient;
        }
    }

    /* check if this parser has already been registered for this port + dir */
    if (pe != NULL) {
        AppLayerProbingParserElement *tmp_pe = pe;
        while (tmp_pe != NULL) {
            if (pe->al_proto == al_proto ||
                strcmp(pe->al_proto_name, al_proto_name) == 0) {
                /* looks like we have it registered for this port + dir */
                SCLogWarning(SC_ERR_ALPARSER, "App layer probing parser already "
                             "registered for this port, direction");
                return;
            }
            tmp_pe = tmp_pe->next;
        }
    }

    /* Get a new parser element */
    AppLayerProbingParserElement *new_pe =
        AppLayerCreateAppLayerProbingParserElement(al_proto_name, al_proto,
                                                   min_depth, max_depth,
                                                   port, priority, top,
                                                   ProbingParser);
    if (new_pe == NULL)
        return;

    AppLayerInsertNewProbingParserElement(probing_parsers, new_pe, flags);
    return;
}

void AppLayerFreeProbingParsers(AppLayerProbingParser *probing_parsers)
{
    while (probing_parsers != NULL) {
        AppLayerProbingParserElement *pe;
        AppLayerProbingParserElement *next_pe;

        pe = probing_parsers->toserver;
        while (pe != NULL) {
            next_pe = pe->next;
            SCFree(pe);
            pe = next_pe;
        }

        pe = probing_parsers->toclient;
        while (pe != NULL) {
            next_pe = pe->next;
            SCFree(pe);
            pe = next_pe;
        }

        probing_parsers = probing_parsers->next;
    }

    return;
}

/**************************************Unittests*******************************/

#ifdef UNITTESTS

typedef struct TestState_ {
    uint8_t test;
}TestState;

/**
 *  \brief  Test parser function to test the memory deallocation of app layer
 *          parser of occurence of an error.
 */
static int TestProtocolParser(Flow *f, void *test_state, AppLayerParserState *pstate,
                                     uint8_t *input, uint32_t input_len,
                                     AppLayerParserResult *output)
{
    return -1;
}

/** \brief Function to allocates the Test protocol state memory
 */
static void *TestProtocolStateAlloc(void)
{
    void *s = SCMalloc(sizeof(TestState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(TestState));
    return s;
}

/** \brief Function to free the Test Protocol state memory
 */
static void TestProtocolStateFree(void *s)
{
    SCFree(s);
}

/** \test   Test the deallocation of app layer parser memory on occurance of
 *          error in the parsing process.
 */
static int AppLayerParserTest01 (void)
{
    int result = 0;
    Flow f;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    TcpSession ssn;
    struct in_addr addr;
    struct in_addr addr1;
    Address src;
    Address dst;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_TEST;
    f.protoctx = (void *)&ssn;

    inet_pton(AF_INET, "1.2.3.4", &addr.s_addr);
    src.family = AF_INET;
    src.addr_data32[0] = addr.s_addr;
    inet_pton(AF_INET, "4.3.2.1", &addr1.s_addr);
    dst.family = AF_INET;
    dst.addr_data32[0] = addr1.s_addr;
    f.src = src;
    f.dst = dst;
    f.sp = htons(20);
    f.dp = htons(40);
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: ", r);
        goto end;
    }

    if (!(f.flags & FLOW_NO_APPLAYER_INSPECTION))
    {
        printf("flag should have been set, but is not: ");
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test   Test the deallocation of app layer parser memory on occurance of
 *          error in the parsing process for UDP.
 */
static int AppLayerParserTest02 (void)
{
    int result = 1;
    Flow f;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    struct in_addr addr;
    struct in_addr addr1;
    Address src;
    Address dst;

    memset(&f, 0, sizeof(f));
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    f.alproto = ALPROTO_TEST;

    inet_pton(AF_INET, "1.2.3.4", &addr.s_addr);
    src.family = AF_INET;
    src.addr_data32[0] = addr.s_addr;
    inet_pton(AF_INET, "4.3.2.1", &addr1.s_addr);
    dst.family = AF_INET;
    dst.addr_data32[0] = addr1.s_addr;
    f.src = src;
    f.dst = dst;
    f.sp = htons(20);
    f.dp = htons(40);
    f.proto = IPPROTO_UDP;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: \n", r);
        result = 0;
        goto end;
    }

end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    return result;
}

uint16_t ProbingParserDummyForTesting(uint8_t *input, uint32_t input_len)
{
    return 0;
}
static int AppLayerProbingParserTest01(void)
{
    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    if (ctx.probing_parsers == NULL)
        return 0;

    AlpProtoTestDestroy(&ctx);
    return 1;
}

static int AppLayerProbingParserTest02(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest03(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest04(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest05(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest06(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest07(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest08(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest09(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest10(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest11(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 15)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next == NULL)
        goto end;
    if (pp->next->toserver->next->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp - second one */
    pe = pp->next->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest12(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 15)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next == NULL)
        goto end;
    if (pp->next->toserver->next->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp - second one */
    pe = pp->next->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest13(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 15)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next == NULL)
        goto end;
    if (pp->next->toserver->next->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp - second one */
    pe = pp->next->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerPrintProbingParsers(ctx.probing_parsers);

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

#endif /* UNITESTS */

void AppLayerParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("AppLayerParserTest01", AppLayerParserTest01, 1);
    UtRegisterTest("AppLayerParserTest02", AppLayerParserTest02, 1);
    UtRegisterTest("AppLayerProbingParserTest01", AppLayerProbingParserTest01, 1);
    UtRegisterTest("AppLayerProbingParserTest02", AppLayerProbingParserTest02, 1);
    UtRegisterTest("AppLayerProbingParserTest03", AppLayerProbingParserTest03, 1);
    UtRegisterTest("AppLayerProbingParserTest04", AppLayerProbingParserTest04, 1);
    UtRegisterTest("AppLayerProbingParserTest05", AppLayerProbingParserTest05, 1);
    UtRegisterTest("AppLayerProbingParserTest06", AppLayerProbingParserTest06, 1);
    UtRegisterTest("AppLayerProbingParserTest07", AppLayerProbingParserTest07, 1);
    UtRegisterTest("AppLayerProbingParserTest08", AppLayerProbingParserTest08, 1);
    UtRegisterTest("AppLayerProbingParserTest09", AppLayerProbingParserTest09, 1);
    UtRegisterTest("AppLayerProbingParserTest10", AppLayerProbingParserTest10, 1);
    UtRegisterTest("AppLayerProbingParserTest11", AppLayerProbingParserTest11, 1);
    UtRegisterTest("AppLayerProbingParserTest12", AppLayerProbingParserTest12, 1);
    UtRegisterTest("AppLayerProbingParserTest13", AppLayerProbingParserTest13, 1);
#endif /* UNITTESTS */

    return;
}
