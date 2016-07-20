/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_PARSER_H__
#define __APP_LAYER_PARSER_H__

#include "app-layer-events.h"
#include "detect-engine-state.h"
#include "util-file.h"

#define APP_LAYER_PARSER_EOF                    0x01
#define APP_LAYER_PARSER_NO_INSPECTION          0x02
#define APP_LAYER_PARSER_NO_REASSEMBLY          0x04
#define APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD  0x08


/***** transaction handling *****/

/** \brief Function ptr type for getting active TxId from a flow
 *  Used by AppLayerTransactionGetActive.
 */
typedef uint64_t (*GetActiveTxIdFunc)(Flow *f, uint8_t flags);

/** \brief Register GetActiveTxId Function
 *
 */
void RegisterAppLayerGetActiveTxIdFunc(GetActiveTxIdFunc FuncPtr);

/** \brief active TX retrieval for normal ops: so with detection and logging
 *
 *  \retval tx_id lowest tx_id that still needs work
 *
 *  This is the default function.
 */
uint64_t AppLayerTransactionGetActiveDetectLog(Flow *f, uint8_t flags);

/** \brief active TX retrieval for logging only ops
 *
 *  \retval tx_id lowest tx_id that still needs work
 */
uint64_t AppLayerTransactionGetActiveLogOnly(Flow *f, uint8_t flags);


int AppLayerParserSetup(void);

int AppLayerParserDeSetup(void);

typedef struct AppLayerParserThreadCtx_ AppLayerParserThreadCtx;

/**
 * \brief Gets a new app layer protocol's parser thread context.
 *
 * \retval Non-NULL pointer on success.
 *         NULL pointer on failure.
 */
AppLayerParserThreadCtx *AppLayerParserThreadCtxAlloc(void);

/**
 * \brief Destroys the app layer parser thread context obtained
 *        using AppLayerParserThreadCtxAlloc().
 *
 * \param tctx Pointer to the thread context to be destroyed.
 */
void AppLayerParserThreadCtxFree(AppLayerParserThreadCtx *tctx);

/**
 * \brief Given a protocol name, checks if the parser is enabled in
 *        the conf file.
 *
 * \param alproto_name Name of the app layer protocol.
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AppLayerParserConfParserEnabled(const char *ipproto,
                                    const char *alproto_name);

/***** Parser related registration *****/

/**
 * \brief Register app layer parser for the protocol.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerParserRegisterParser(uint8_t ipproto, AppProto alproto,
                      uint8_t direction,
                      int (*Parser)(Flow *f, void *protocol_state,
                                    AppLayerParserState *pstate,
                                    uint8_t *buf, uint32_t buf_len,
                                    void *local_storage));
void AppLayerParserRegisterParserAcceptableDataDirection(uint8_t ipproto,
                                              AppProto alproto,
                                              uint8_t direction);
void AppLayerParserRegisterStateFuncs(uint8_t ipproto, AppProto alproto,
                           void *(*StateAlloc)(void),
                           void (*StateFree)(void *));
void AppLayerParserRegisterLocalStorageFunc(uint8_t ipproto, AppProto proto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *));
void AppLayerParserRegisterGetFilesFunc(uint8_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t));
void AppLayerParserRegisterGetEventsFunc(uint8_t ipproto, AppProto proto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t));
void AppLayerParserRegisterHasEventsFunc(uint8_t ipproto, AppProto alproto,
                              int (*StateHasEvents)(void *));
void AppLayerParserRegisterLoggerFuncs(uint8_t ipproto, AppProto alproto,
                         int (*StateGetTxLogged)(void *, void *, uint32_t),
                         void (*StateSetTxLogged)(void *, void *, uint32_t));
void AppLayerParserRegisterLogger(uint8_t ipproto, AppProto alproto);
void AppLayerParserRegisterTruncateFunc(uint8_t ipproto, AppProto alproto,
                             void (*Truncate)(void *, uint8_t));
void AppLayerParserRegisterGetStateProgressFunc(uint8_t ipproto, AppProto alproto,
    int (*StateGetStateProgress)(void *alstate, uint8_t direction));
void AppLayerParserRegisterTxFreeFunc(uint8_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t));
void AppLayerParserRegisterGetTxCnt(uint8_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate));
void AppLayerParserRegisterGetTx(uint8_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id));
void AppLayerParserRegisterGetStateProgressCompletionStatus(AppProto alproto,
    int (*StateGetStateProgressCompletionStatus)(uint8_t direction));
void AppLayerParserRegisterGetEventInfo(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type));
void AppLayerParserRegisterDetectStateFuncs(uint8_t ipproto, AppProto alproto,
        int (*StateHasTxDetectState)(void *alstate),
        DetectEngineState *(*GetTxDetectState)(void *tx),
        int (*SetTxDetectState)(void *alstate, void *tx, DetectEngineState *));

/***** Get and transaction functions *****/

void *AppLayerParserGetProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto);
void AppLayerParserDestroyProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto,
                                          void *local_data);


uint64_t AppLayerParserGetTransactionLogId(AppLayerParserState *pstate);
void AppLayerParserSetTransactionLogId(AppLayerParserState *pstate);
void AppLayerParserSetTxLogged(uint8_t ipproto, AppProto alproto, void *alstate,
                               void *tx, uint32_t logger);
int AppLayerParserGetTxLogged(uint8_t ipproto, AppProto alproto, void *alstate,
                              void *tx, uint32_t logger);
uint64_t AppLayerParserGetTransactionInspectId(AppLayerParserState *pstate, uint8_t direction);
void AppLayerParserSetTransactionInspectId(AppLayerParserState *pstate,
                                const uint8_t ipproto, const AppProto alproto, void *alstate,
                                const uint8_t flags);
AppLayerDecoderEvents *AppLayerParserGetDecoderEvents(AppLayerParserState *pstate);
void AppLayerParserSetDecoderEvents(AppLayerParserState *pstate, AppLayerDecoderEvents *devents);
AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint8_t ipproto, AppProto alproto, void *alstate,
                                        uint64_t tx_id);
uint16_t AppLayerParserGetStateVersion(AppLayerParserState *pstate);
FileContainer *AppLayerParserGetFiles(uint8_t ipproto, AppProto alproto,
                           void *alstate, uint8_t direction);
int AppLayerParserGetStateProgress(uint8_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction);
uint64_t AppLayerParserGetTxCnt(uint8_t ipproto, AppProto alproto, void *alstate);
void *AppLayerParserGetTx(uint8_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id);
int AppLayerParserGetStateProgressCompletionStatus(AppProto alproto, uint8_t direction);
int AppLayerParserGetEventInfo(uint8_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type);

uint64_t AppLayerParserGetTransactionActive(uint8_t ipproto, AppProto alproto, AppLayerParserState *pstate, uint8_t direction);

uint8_t AppLayerParserGetFirstDataDir(uint8_t ipproto, AppProto alproto);

int AppLayerParserSupportsTxDetectState(uint8_t ipproto, AppProto alproto);
int AppLayerParserHasTxDetectState(uint8_t ipproto, AppProto alproto, void *alstate);
DetectEngineState *AppLayerParserGetTxDetectState(uint8_t ipproto, AppProto alproto, void *tx);
int AppLayerParserSetTxDetectState(uint8_t ipproto, AppProto alproto, void *alstate, void *tx, DetectEngineState *s);

/***** General *****/

int AppLayerParserParse(AppLayerParserThreadCtx *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, uint8_t *input, uint32_t input_len);
void AppLayerParserSetEOF(AppLayerParserState *pstate);
int AppLayerParserHasDecoderEvents(uint8_t ipproto, AppProto alproto, void *alstate, AppLayerParserState *pstate,
                        uint8_t flags);
int AppLayerParserIsTxAware(AppProto alproto);
int AppLayerParserProtocolIsTxAware(uint8_t ipproto, AppProto alproto);
int AppLayerParserProtocolIsTxEventAware(uint8_t ipproto, AppProto alproto);
int AppLayerParserProtocolSupportsTxs(uint8_t ipproto, AppProto alproto);
int AppLayerParserProtocolHasLogger(uint8_t ipproto, AppProto alproto);
void AppLayerParserTriggerRawStreamReassembly(Flow *f);

/***** Cleanup *****/

void AppLayerParserStateCleanup(uint8_t ipproto, AppProto alproto, void *alstate, AppLayerParserState *pstate);

void AppLayerParserRegisterProtocolParsers(void);


void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint8_t flag);
int AppLayerParserStateIssetFlag(AppLayerParserState *pstate, uint8_t flag);

void AppLayerParserStreamTruncated(uint8_t ipproto, AppProto alproto, void *alstate,
                        uint8_t direction);



AppLayerParserState *AppLayerParserStateAlloc(void);
void AppLayerParserStateFree(AppLayerParserState *pstate);



#ifdef DEBUG
void AppLayerParserStatePrintDetails(AppLayerParserState *pstate);
#endif

#ifdef AFLFUZZ_APPLAYER
int AppLayerParserRequestFromFile(AppProto alproto, char *filename);
int AppLayerParserFromFile(AppProto alproto, char *filename);
#endif

/***** Unittests *****/

#ifdef UNITTESTS
void AppLayerParserRegisterProtocolUnittests(uint8_t ipproto, AppProto alproto,
                                  void (*RegisterUnittests)(void));
void AppLayerParserRegisterUnittests(void);
void AppLayerParserBackupParserTable(void);
void AppLayerParserRestoreParserTable(void);
#endif

#endif /* __APP_LAYER_PARSER_H__ */
