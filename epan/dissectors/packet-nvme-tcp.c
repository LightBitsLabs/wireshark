/* packet-nvme-rdma.c
 * Routines for NVM Express over Fabrics(RDMA) dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
NVM Express is high speed interface for accessing solid state drives.
NVM Express specifications are maintained by NVM Express industry
association at http://www.nvmexpress.org.

This file adds support to dissect NVM Express over fabrics packets
for RDMA. This adds very basic support for dissecting commands
completions.

Current dissection supports dissection of
(a) NVMe cmd and cqe
(b) NVMe Fabric command and cqe
As part of it, it also calculates cmd completion latencies.

This protocol is similar to iSCSI and SCSI dissection where iSCSI is
transport protocol for carying SCSI commands and responses. Similarly
NVMe Fabrics - RDMA transport protocol carries NVMe commands.

     +----------+
     |   NVMe   |
     +------+---+
            |
+-----------+---------+
|   NVMe Fabrics      |
+----+-----------+----+
     |           |
+----+---+   +---+----+  +---+---+
|  RDMA  |   |   FC   |  |  TCP  |
+--------+   +--------+  +--------+

References:
NVMe Express fabrics specification is located at
http://www.nvmexpress.org/wp-content/uploads/NVMe_over_Fabrics_1_0_Gold_20160605.pdf

NVMe Express specification is located at
http://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_2a.pdf

NVM Express RDMA TCP port assigned by IANA that maps to RDMA IP service
TCP port can be found at
http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=NVM+Express

*/
#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>

#include "packet-tcp.h"
#include "packet-nvme.h"


static int proto_nvme_tcp = -1;
//static dissector_handle_t tcp_handler;
static dissector_handle_t nvmet_tcp_handle;

//static int proto_tcp = -1;

//
//#define SID_ULP_MASK   0x00000000FF000000
//#define SID_PROTO_MASK 0x0000000000FF0000
//#define SID_PORT_MASK  0x000000000000FFFF
//
//#define SID_ULP         0x01
//#define SID_PROTO_TCP   0x06
#define NVME_TCP_PORT_RANGE    "4420" /* IANA registered */
//
//#define SID_MASK (SID_ULP_MASK | SID_PROTO_MASK)
//#define SID_ULP_TCP ((SID_ULP << 3 * 8) | (SID_PROTO_TCP << 2 * 8))
//
#define NVME_FABRICS_TCP "NVMe Fabrics TCP"
#define NVME_TCP_HEADER_SIZE 8
//
//#define NVME_FABRIC_CMD_SIZE NVME_CMD_SIZE
//#define NVME_FABRIC_CQE_SIZE NVME_CQE_SIZE
//
//#define NVME_FABRIC_OPC 0x7F
//
//#define NVME_FCTYPE_CONNECT   0x1
//#define NVME_FCTYPE_AUTH_RECV 0x6
//#define NVME_FCTYPE_PROP_GET  0x4
//#define NVME_FCTYPE_PROP_SET  0x0
//
//static const value_string fctype_tbl[] = {
//    { NVME_FCTYPE_CONNECT,       "Connect"},
//    { NVME_FCTYPE_PROP_GET,      "Property Get"},
//    { NVME_FCTYPE_PROP_SET,      "Property Set"},
//    { NVME_FCTYPE_AUTH_RECV,     "Authentication Recv"},
//    { 0, NULL}
//};

enum nvme_tcp_pdu_type {
	nvme_tcp_icreq		= 0x0,
	nvme_tcp_icresp		= 0x1,
	nvme_tcp_h2c_term	= 0x2,
	nvme_tcp_c2h_term	= 0x3,
	nvme_tcp_cmd		= 0x4,
	nvme_tcp_rsp		= 0x5,
	nvme_tcp_h2c_data	= 0x6,
	nvme_tcp_c2h_data	= 0x7,
	nvme_tcp_r2t		= 0x9,
};

static const value_string nvme_tcp_pdu_type_vals[] = {
  { nvme_tcp_icreq,       "ICREQ"},
  { nvme_tcp_icresp,      "ICRESP"},
  { nvme_tcp_h2c_term,    "H2CTerm "},
  { nvme_tcp_c2h_term,    "C2HTerm"},
  { nvme_tcp_cmd,    	  "Command"},
  { nvme_tcp_rsp,    	  "Response"},
  { nvme_tcp_h2c_data,    "H2CData"},
  { nvme_tcp_c2h_data,    "C2HData"},
  { nvme_tcp_r2t,    	  "Ready To Transmit"},
  { 0, NULL }
};

enum nvmf_capsule_command {
	nvme_fabrics_type_property_set	= 0x00,
	nvme_fabrics_type_connect	= 0x01,
	nvme_fabrics_type_property_get	= 0x04,
};

static const value_string nvme_fabrics_cmd_type_vals[] = {
	{ nvme_fabrics_type_connect,       "Connect"},
	{ nvme_fabrics_type_property_get,  "Property Get"},
	{ nvme_fabrics_type_property_set,  "Property Set"},
	{ 0, NULL}
};

static const value_string attr_size_tbl[] = {
    { 0,       "4 bytes"},
    { 1,       "8 bytes"},
    { 0, NULL}
};

static const value_string prop_offset_tbl[] = {
    { 0x0,      "Controller Capabilities"},
    { 0x8,      "Version"},
    { 0xc,      "Reserved"},
    { 0x10,     "Reserved"},
    { 0x14,     "Controller Configuration"},
    { 0x18,     "Reserved"},
    { 0x1c,     "Controller Status"},
    { 0x20,     "NVM Subsystem Reset"},
    { 0x24,     "Reserved"},
    { 0x28,     "Reserved"},
    { 0x30,     "Reserved"},
    { 0x38,     "Reserved"},
    { 0x3c,     "Reserved"},
    { 0x40,     "Reserved"},
    { 0, NULL}
};


enum nvme_tcp_digest_option {
	NVME_TCP_HDR_DIGEST_ENABLE	= (1 << 0),
	NVME_TCP_DATA_DIGEST_ENABLE	= (1 << 1),
};

/*
 * Fabrics subcommands.
 */
enum nvmf_fabrics_opcode {
	nvme_fabrics_command		= 0x7f,
};

#define NVME_FABRIC_CMD_SIZE NVME_CMD_SIZE
#define NVME_FABRIC_CQE_SIZE NVME_CQE_SIZE



//
//static const value_string prop_offset_tbl[] = {
//    { 0x0,      "Controller Capabilities"},
//    { 0x8,      "Version"},
//    { 0xc,      "Reserved"},
//    { 0x10,     "Reserved"},
//    { 0x14,     "Controller Configuration"},
//    { 0x18,     "Reserved"},
//    { 0x1c,     "Controller Status"},
//    { 0x20,     "NVM Subsystem Reset"},
//    { 0x24,     "Reserved"},
//    { 0x28,     "Reserved"},
//    { 0x30,     "Reserved"},
//    { 0x38,     "Reserved"},
//    { 0x3c,     "Reserved"},
//    { 0x40,     "Reserved"},
//    { 0, NULL}
//};
//
//static const value_string attr_size_tbl[] = {
//    { 0,       "4 bytes"},
//    { 1,       "8 bytes"},
//    { 0, NULL}
//};
//
struct nvme_tcp_q_ctx {
    gboolean	      hdr_digest;
    gboolean	      data_digest;
    struct nvme_q_ctx n_q_ctx;
};


struct nvme_tcp_cmd_ctx {
    struct nvme_cmd_ctx n_cmd_ctx;
    guint8 fctype;    /* fabric cmd type */
};


static int hf_nvme_tcp_type = -1;
static int hf_nvme_tcp_flags = -1;
static int hf_nvme_tcp_hlen = -1;
static int hf_nvme_tcp_pdo = -1;
static int hf_nvme_tcp_plen = -1;


/* NVMe tcp icreq/icresp fields */
static int hf_nvme_tcp_icreq = -1;
static int hf_nvme_tcp_icreq_pfv  = -1;
static int hf_nvme_tcp_icreq_maxr2t  = -1;
static int hf_nvme_tcp_icreq_hpda  = -1;
// FIXME: split digest into 2 header and data
static int hf_nvme_tcp_icreq_digest  = -1;
static int hf_nvme_tcp_icresp = -1;
static int hf_nvme_tcp_icresp_pfv = -1;
static int hf_nvme_tcp_icresp_cpda = -1;
static int hf_nvme_tcp_icresp_digest = -1;
static int hf_nvme_tcp_icresp_maxdata = -1;


/* NVMe fabrics command */
static int hf_nvme_fabrics_cmd = -1;
static int hf_nvme_fabrics_cmd_opc = -1;
static int hf_nvme_fabrics_cmd_rsvd1 = -1;
static int hf_nvme_fabrics_cmd_cid = -1;
static int  hf_nvme_fabrics_cmd_fctype = -1;
static int hf_nvme_fabrics_cmd_generic_rsvd1 = -1;
static int hf_nvme_fabrics_cmd_generic_field = -1;

/* NVMe fabrics connect command  */
static int hf_nvme_fabrics_cmd_connect_rsvd2 = -1;
static int hf_nvme_fabrics_cmd_connect_sgl1 = -1;
static int hf_nvme_fabrics_cmd_connect_recfmt = -1;
static int hf_nvme_fabrics_cmd_connect_qid = -1;
static int hf_nvme_fabrics_cmd_connect_sqsize = -1;
static int hf_nvme_fabrics_cmd_connect_cattr = -1;
static int hf_nvme_fabrics_cmd_connect_rsvd3 = -1;
static int hf_nvme_fabrics_cmd_connect_kato = -1;
static int hf_nvme_fabrics_cmd_connect_rsvd4 = -1;

/* NVMe fabrics data */
static int hf_nvme_fabrics_from_host_unknown_data = -1;

/* NVMe fabrics connect command data*/
static int hf_nvme_fabrics_cmd_data = -1;
static int hf_nvme_fabrics_cmd_connect_data_hostid = -1;
static int hf_nvme_fabrics_cmd_connect_data_cntlid = -1;
static int hf_nvme_fabrics_cmd_connect_data_rsvd4 = -1;
static int hf_nvme_fabrics_cmd_connect_data_subnqn = -1;
static int hf_nvme_fabrics_cmd_connect_data_hostnqn = -1;
static int hf_nvme_fabrics_cmd_connect_data_rsvd5 = -1;



//static int hf_nvme_fabrics_cmd_connect_rsvd1 = -1;
//static int hf_nvme_fabrics_cmd_connect_rsvd1 = -1;


    //dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvme_rdma_cmd_connect_sgl1, NULL);
    /*proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_recfmt, cmd_tvb,
                        40, 2, ENC_LITTLE_ENDIAN);*/
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_qid, cmd_tvb,
//                        42, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_sqsize, cmd_tvb,
//                        44, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_cattr, cmd_tvb,
//                        46, 1, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd2, cmd_tvb,
//                        47, 1, ENC_NA);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_kato, cmd_tvb,
//                        48, 4, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd3, cmd_tvb,
//                        52, 12, ENC_NA);


//static int hf_nvme_rdma_from_host_unknown_data = -1;
//
//static int hf_nvme_rdma_cmd_opc = -1;
//static int hf_nvme_rdma_cmd_rsvd = -1;

//static int hf_nvme_rdma_cmd_fctype = -1;
//static int hf_nvme_rdma_cmd_connect_rsvd1 = -1;
//static int hf_nvme_rdma_cmd_connect_sgl1 = -1;
//static int hf_nvme_rdma_cmd_connect_recfmt = -1;
//static int hf_nvme_rdma_cmd_connect_qid = -1;
//static int hf_nvme_rdma_cmd_connect_sqsize = -1;
//static int hf_nvme_rdma_cmd_connect_cattr = -1;
//static int hf_nvme_rdma_cmd_connect_rsvd2 = -1;
//static int hf_nvme_rdma_cmd_connect_kato = -1;
//static int hf_nvme_rdma_cmd_connect_rsvd3 = -1;
//static int hf_nvme_rdma_cmd_data = -1;
//static int hf_nvme_rdma_cmd_connect_data_hostid = -1;
//static int hf_nvme_rdma_cmd_connect_data_cntlid = -1;
//static int hf_nvme_rdma_cmd_connect_data_rsvd = -1;
//static int hf_nvme_rdma_cmd_connect_data_subnqn = -1;
//static int hf_nvme_rdma_cmd_connect_data_hostnqn = -1;
//static int hf_nvme_rdma_cmd_connect_data_rsvd1 = -1;
//
//static int hf_nvme_rdma_cmd_prop_attr_rsvd = -1;
static int hf_nvme_fabrics_cmd_prop_attr_rsvd1 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_size = -1;
static int hf_nvme_fabrics_cmd_prop_attr_rsvd2 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_offset = -1;
static int hf_nvme_fabrics_cmd_prop_attr_rsvd3 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_get_rsvd4 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_4B_value = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_4B_value_rsvd = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_8B_value = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_rsvd3 = -1;




//static int hf_nvme_rdma_cmd_prop_attr_set_4B_value = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_4B_value_rsvd = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_8B_value = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_rsvd3 = -1;
//
//static int hf_nvme_rdma_cmd_generic_rsvd1 = -1;
//static int hf_nvme_rdma_cmd_generic_field = -1;




/* tracking Cmd and its respective CQE */
static int hf_nvme_fabrics_cmd_pkt = -1;
static int hf_nvme_fabrics_cqe_pkt = -1;
static int hf_nvme_fabrics_cmd_latency = -1;
static int hf_nvme_fabrics_cmd_qid = -1;






//
//struct nvme_rdma_cmd_ctx {
//    struct nvme_cmd_ctx n_cmd_ctx;
//    guint8 fctype;    /* fabric cmd type */
//};
//
//void proto_reg_handoff_nvme_rdma(void);
//void proto_register_nvme_rdma(void);
//
//static int proto_nvme_tcp = -1;
//static dissector_handle_t tcp_handler;
//static dissector_handle_t tcp;
//static int proto_tcp = -1;
//
/////* NVMe Fabrics RDMA CM Private data */
////static int hf_nvme_rdma_cm_req_recfmt = -1;
////static int hf_nvme_rdma_cm_req_qid = -1;
////static int hf_nvme_rdma_cm_req_hrqsize = -1;
////static int hf_nvme_rdma_cm_req_hsqsize = -1;
////static int hf_nvme_rdma_cm_req_reserved = -1;
////
////static int hf_nvme_rdma_cm_rsp_recfmt = -1;
////static int hf_nvme_rdma_cm_rsp_crqsize = -1;
////static int hf_nvme_rdma_cm_rsp_reserved = -1;
////
////static int hf_nvme_rdma_cm_rej_recfmt = -1;
////static int hf_nvme_rdma_cm_rej_status = -1;
////static int hf_nvme_rdma_cm_rej_reserved = -1;
//
///* NVMe Fabric Cmd */
//static int hf_nvme_rdma_cmd = -1;
//static int hf_nvme_rdma_from_host_unknown_data = -1;
//
//static int hf_nvme_rdma_cmd_opc = -1;
//static int hf_nvme_rdma_cmd_rsvd = -1;
//static int hf_nvme_rdma_cmd_cid = -1;
//static int hf_nvme_rdma_cmd_fctype = -1;
//static int hf_nvme_rdma_cmd_connect_rsvd1 = -1;
//static int hf_nvme_rdma_cmd_connect_sgl1 = -1;
//static int hf_nvme_rdma_cmd_connect_recfmt = -1;
//static int hf_nvme_rdma_cmd_connect_qid = -1;
//static int hf_nvme_rdma_cmd_connect_sqsize = -1;
//static int hf_nvme_rdma_cmd_connect_cattr = -1;
//static int hf_nvme_rdma_cmd_connect_rsvd2 = -1;
//static int hf_nvme_rdma_cmd_connect_kato = -1;
//static int hf_nvme_rdma_cmd_connect_rsvd3 = -1;
//static int hf_nvme_rdma_cmd_data = -1;
//static int hf_nvme_rdma_cmd_connect_data_hostid = -1;
//static int hf_nvme_rdma_cmd_connect_data_cntlid = -1;
//static int hf_nvme_rdma_cmd_connect_data_rsvd = -1;
//static int hf_nvme_rdma_cmd_connect_data_subnqn = -1;
//static int hf_nvme_rdma_cmd_connect_data_hostnqn = -1;
//static int hf_nvme_rdma_cmd_connect_data_rsvd1 = -1;
//
//static int hf_nvme_rdma_cmd_prop_attr_rsvd = -1;
//static int hf_nvme_rdma_cmd_prop_attr_rsvd1 = -1;
//static int hf_nvme_rdma_cmd_prop_attr_size = -1;
//static int hf_nvme_rdma_cmd_prop_attr_rsvd2 = -1;
//static int hf_nvme_rdma_cmd_prop_attr_offset = -1;
//static int hf_nvme_rdma_cmd_prop_attr_get_rsvd3 = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_4B_value = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_4B_value_rsvd = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_8B_value = -1;
//static int hf_nvme_rdma_cmd_prop_attr_set_rsvd3 = -1;
//
//static int hf_nvme_rdma_cmd_generic_rsvd1 = -1;
//static int hf_nvme_rdma_cmd_generic_field = -1;
//
/* NVMe Fabric CQE */
static int hf_nvme_fabrics_cqe = -1;
static int hf_nvme_fabrics_cqe_sts = -1;
static int hf_nvme_fabrics_cqe_sqhd = -1;
static int hf_nvme_fabrics_cqe_rsvd = -1;
static int hf_nvme_fabrics_cqe_cid = -1;
static int hf_nvme_fabrics_cqe_status = -1;
static int hf_nvme_fabrics_cqe_status_rsvd = -1;

static int hf_nvme_fabrics_cqe_connect_cntlid = -1;
static int hf_nvme_fabrics_cqe_connect_authreq = -1;
static int hf_nvme_fabrics_cqe_connect_rsvd = -1;
static int hf_nvme_fabrics_cqe_prop_set_rsvd = -1;
static int hf_nvme_tcp_to_host_unknown_data = -1;
//
///* tracking Cmd and its respective CQE */
//static int hf_nvme_rdma_cmd_pkt = -1;
//static int hf_nvme_rdma_cqe_pkt = -1;
//static int hf_nvme_rdma_cmd_latency = -1;
//static int hf_nvme_rdma_cmd_qid = -1;
//
///* Initialize the subtree pointers */
////static gint ett_cm = -1;
//static gint ett_data = -1;
//
static gint ett_nvme_tcp = -1;
static gint ett_nvme_tcp_icqreq = -1;
static gint ett_nvme_tcp_icqresp = -1;
static gint ett_nvme_fabrics = -1;
static gint ett_nvme_fabrics_data = -1;
static range_t *gPORT_RANGE;
//
//static conversation_infiniband_data *get_conversion_data(conversation_t *conv)
//{
//    conversation_infiniband_data *conv_data;
//
//    conv_data = (conversation_infiniband_data *)conversation_get_proto_data(conv, proto_ib);
//    if (!conv_data)
//        return NULL;
//
//    if ((conv_data->service_id & SID_MASK) != SID_ULP_TCP)
//        return NULL;   /* the service id doesn't match that of TCP ULP - nothing for us to do here */
//
//    if (!(value_is_in_range(gPORT_RANGE, (guint32)(conv_data->service_id & SID_PORT_MASK))))
//        return NULL;   /* the port doesn't match that of NVM Express Fabrics - nothing for us to do here */
//    return conv_data;
//}
//
//static conversation_t*
//find_ib_conversation(packet_info *pinfo, conversation_infiniband_data **uni_conv_data)
//{
//    conversation_t *conv;
//    conversation_infiniband_data *conv_data;
//
//    conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
//                             ENDPOINT_IBQP, pinfo->destport, pinfo->destport,
//                             NO_ADDR_B|NO_PORT_B);
//    if (!conv)
//        return NULL;   /* nothing to do with no conversation context */
//
//    conv_data = get_conversion_data(conv);
//    *uni_conv_data = conv_data;
//    if (!conv_data)
//        return NULL;
//
//    /* now that we found unidirectional conversation, find bidirectional
//     * conversation, so that we can relate to nvme q.
//     */
//    return find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
//                             ENDPOINT_IBQP, pinfo->srcport, pinfo->destport, 0);
//}
//
//static guint16 find_nvme_qid(packet_info *pinfo)
//{
//    conversation_t *conv;
//    conversation_infiniband_data *conv_data;
//    guint16 qid;
//
//    conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
//                             ENDPOINT_IBQP, pinfo->destport, pinfo->destport,
//                             NO_ADDR_B|NO_PORT_B);
//    if (!conv)
//        return 0;   /* nothing to do with no conversation context */
//
//    conv_data = get_conversion_data(conv);
//    if (!conv_data)
//        return 0;
//
//    if (conv_data->client_to_server == FALSE) {
//        memcpy(&qid, &conv_data->mad_private_data[178], 2);
//        return qid;
//    }
//    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->src,
//                             ENDPOINT_IBQP, conv_data->src_qp, conv_data->src_qp,
//                             NO_ADDR_B|NO_PORT_B);
//    if (!conv)
//        return 0;
//    conv_data = get_conversion_data(conv);
//    if (!conv_data)
//        return 0;
//    memcpy(&qid, &conv_data->mad_private_data[178], 2);
//    return qid;
//}
//



//static struct nvme_tcp_q_ctx*
//get_nvme_tcp_conversation_data(packet_info *pinfo, conversation_t **conversation)
//{
//	struct nvme_tcp_q_ctx *q_ctx;
//
//	*conversation = find_or_create_conversation(pinfo);
//
//	/* Retrieve information from conversation
//	* or add it if it isn't there yet
//	*/
//	q_ctx = (struct nvme_tcp_q_ctx *)conversation_get_proto_data(*conversation, proto_nvme_tcp);
//	if(!q_ctx) {
//		/* Setup the conversation structure itself */
//		q_ctx = (struct nvme_tcp_q_ctx *)wmem_alloc0(wmem_file_scope(), sizeof(struct nvme_tcp_q_ctx));
//		q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
//		q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
//		q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
//		q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
//		q_ctx->n_q_ctx.qid = 0; // FIXME: how can i know queue id ???
//		conversation_add_proto_data(*conversation, proto_nvme_tcp, q_ctx);
//	}
//
//	return q_ctx;
//}



//
////static conversation_infiniband_data*
////find_ib_cm_conversation(packet_info *pinfo)
////{
////    conversation_t *conv;
////
////    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
////                             ENDPOINT_IBQP, pinfo->srcport, pinfo->destport, 0);
////    if (!conv)
////        return NULL;
////
////    return get_conversion_data(conv);
////}
//
////static void dissect_rdma_cm_req_packet(tvbuff_t *tvb, proto_tree *tree)
////{
////    proto_tree *cm_tree;
////    proto_item *ti, *qid_item;
////    /* private data is at offset of 36 bytes */
////    int offset = 36;
////    guint16 qid;
////
////    /* create display subtree for private data */
////    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, offset, 32, ENC_NA);
////    cm_tree = proto_item_add_subtree(ti, ett_cm);
////
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_recfmt, tvb,
////                        offset + 0, 2, ENC_LITTLE_ENDIAN);
////
////    qid_item = proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_qid, tvb,
////                                   offset + 2, 2, ENC_LITTLE_ENDIAN);
////    qid = tvb_get_guint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
////    proto_item_append_text(qid_item, " %s", qid ? "IOQ" : "AQ");
////
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_hrqsize, tvb,
////                        offset + 4, 2, ENC_LITTLE_ENDIAN);
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_hsqsize, tvb,
////                        offset + 6, 2, ENC_LITTLE_ENDIAN);
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_reserved, tvb,
////                        offset + 8, 24, ENC_NA);
////}
//
////static void dissect_rdma_cm_rsp_packet(tvbuff_t *tvb, proto_tree *tree)
////{
////    proto_tree *cm_tree;
////    proto_item *ti;
////
////    /* create display subtree for the private datat that start at offset 0 */
////    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 32, ENC_NA);
////    cm_tree = proto_item_add_subtree(ti, ett_cm);
////
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rsp_recfmt, tvb,
////            0, 2, ENC_LITTLE_ENDIAN);
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rsp_crqsize, tvb,
////            2, 2, ENC_LITTLE_ENDIAN);
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rsp_reserved, tvb,
////            4, 28, ENC_NA);
////}
//
////static void dissect_rdma_cm_rej_packet(tvbuff_t *tvb, proto_tree *tree)
////{
////    proto_tree *cm_tree;
////    proto_item *ti;
////
////    /* create display subtree for the private datat that start at offset 0 */
////    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 32, ENC_NA);
////    cm_tree = proto_item_add_subtree(ti, ett_cm);
////
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rej_recfmt, tvb,
////            0, 2, ENC_LITTLE_ENDIAN);
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rej_status, tvb,
////            2, 2, ENC_LITTLE_ENDIAN);
////    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rej_reserved, tvb,
////            4, 28, ENC_NA);
////}
//
////static int dissect_rdma_cm_packet(tvbuff_t *tvb, proto_tree *tree,
////                                  guint16 cm_attribute_id)
////{
////    switch (cm_attribute_id) {
////    case ATTR_CM_REQ:
////        dissect_rdma_cm_req_packet(tvb, tree);
////        break;
////    case ATTR_CM_REP:
////        dissect_rdma_cm_rsp_packet(tvb, tree);
////        break;
////    case ATTR_CM_REJ:
////        dissect_rdma_cm_rej_packet(tvb, tree);
////        break;
////    default:
////        break;
////    }
////    return TRUE;
////}
//
////static int
////dissect_nvme_ib_cm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
////        void *data)
////{
////    conversation_infiniband_data *conv_data = NULL;
////    struct infinibandinfo *info = (struct infinibandinfo *)data;
////
////    conv_data = find_ib_cm_conversation(pinfo);
////    if (!conv_data)
////        return FALSE;
////
////    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_RDMA);
////    return dissect_rdma_cm_packet(tvb, tree, info->cm_attribute_id);
////}
//
//static void dissect_nvme_fabric_connect_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
//{
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd1, cmd_tvb,
//                        5, 19, ENC_NA);
//    dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvme_rdma_cmd_connect_sgl1, NULL);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_recfmt, cmd_tvb,
//                        40, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_qid, cmd_tvb,
//                        42, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_sqsize, cmd_tvb,
//                        44, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_cattr, cmd_tvb,
//                        46, 1, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd2, cmd_tvb,
//                        47, 1, ENC_NA);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_kato, cmd_tvb,
//                        48, 4, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd3, cmd_tvb,
//                        52, 12, ENC_NA);
//}
//
//static guint8 dissect_nvme_fabric_prop_cmd_common(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
//{
//    proto_item *attr_item, *offset_item;
//    guint32 offset;
//    guint8 attr;
//
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_rsvd, cmd_tvb,
//                        5, 35, ENC_NA);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_rsvd1, cmd_tvb,
//                        40, 1, ENC_LITTLE_ENDIAN);
//    attr_item = proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_size, cmd_tvb,
//                                    40, 1, ENC_LITTLE_ENDIAN);
//    attr = tvb_get_guint8(cmd_tvb, 40) & 0x7;
//    proto_item_append_text(attr_item, " %s",
//                           val_to_str(attr, attr_size_tbl, "Reserved"));
//
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_rsvd2, cmd_tvb,
//                        41, 3, ENC_NA);
//
//    offset_item = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_rdma_cmd_prop_attr_offset,
//                                      cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN, &offset);
//    proto_item_append_text(offset_item, " %s",
//                           val_to_str(offset, prop_offset_tbl, "Unknown Property"));
//    return attr;
//}
//
//static void dissect_nvme_fabric_prop_get_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
//{
//    dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_get_rsvd3, cmd_tvb,
//                        48, 16, ENC_NA);
//}
//
//static void dissect_nvme_fabric_prop_set_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
//{
//    guint8 attr;
//
//    attr = dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb);
//    if (attr == 0) {
//        proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_4B_value, cmd_tvb,
//                            48, 4, ENC_LITTLE_ENDIAN);
//        proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_4B_value_rsvd, cmd_tvb,
//                            52, 4, ENC_LITTLE_ENDIAN);
//    } else {
//        proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_8B_value, cmd_tvb,
//                            48, 8, ENC_LITTLE_ENDIAN);
//    }
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_rsvd3, cmd_tvb,
//                        56, 8, ENC_NA);
//}
//
//static void dissect_nvme_fabric_generic_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
//{
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_generic_rsvd1, cmd_tvb,
//                        5, 35, ENC_NA);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_generic_field, cmd_tvb,
//                        40, 24, ENC_NA);
//}
//
//static struct nvme_rdma_cmd_ctx*
//bind_cmd_to_qctx(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
//                 guint16 cmd_id)
//{
//   struct nvme_rdma_cmd_ctx *ctx;
//
//   if (!PINFO_FD_VISITED(pinfo)) {
//       ctx = wmem_new0(wmem_file_scope(), struct nvme_rdma_cmd_ctx);
//
//       nvme_add_cmd_to_pending_list(pinfo, q_ctx,
//                                    &ctx->n_cmd_ctx, (void*)ctx, cmd_id);
//    } else {
//        /* Already visited this frame */
//        ctx = (struct nvme_rdma_cmd_ctx*)
//                  nvme_lookup_cmd_in_done_list(pinfo, q_ctx, cmd_id);
//        /* if we have already visited frame but haven't found completion yet,
//         * we won't find cmd in done q, so allocate a dummy ctx for doing
//         * rest of the processing.
//         */
//        if (!ctx)
//            ctx = wmem_new0(wmem_file_scope(), struct nvme_rdma_cmd_ctx);
//    }
//    return ctx;
//}
//
//static void
//dissect_nvme_fabric_cmd(tvbuff_t *nvme_tvb, proto_tree *nvme_tree,
//                        struct nvme_rdma_cmd_ctx *cmd_ctx)
//{
//    proto_tree *cmd_tree;
//    proto_item *ti, *opc_item, *fctype_item;
//    guint8 fctype;
//
//    fctype = tvb_get_guint8(nvme_tvb, 4);
//    cmd_ctx->fctype = fctype;
//
//    ti = proto_tree_add_item(nvme_tree, hf_nvme_rdma_cmd, nvme_tvb, 0,
//                             NVME_FABRIC_CMD_SIZE, ENC_NA);
//    cmd_tree = proto_item_add_subtree(ti, ett_data);
//
//    opc_item = proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_opc, nvme_tvb,
//                                   0, 1, ENC_LITTLE_ENDIAN);
//    proto_item_append_text(opc_item, "%s", " Fabric Cmd");
//
//    nvme_publish_cmd_to_cqe_link(cmd_tree, nvme_tvb, hf_nvme_rdma_cqe_pkt,
//                                 &cmd_ctx->n_cmd_ctx);
//
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_rsvd, nvme_tvb,
//                        1, 1, ENC_NA);
//    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_cid, nvme_tvb,
//                        2, 2, ENC_LITTLE_ENDIAN);
//
//    fctype_item = proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_fctype,
//                                      nvme_tvb,
//                                      4, 1, ENC_LITTLE_ENDIAN);
//    proto_item_append_text(fctype_item, " %s",
//                           val_to_str(fctype, fctype_tbl, "Unknown FcType"));
//
//    switch(fctype) {
//    case NVME_FCTYPE_CONNECT:
//        dissect_nvme_fabric_connect_cmd(cmd_tree, nvme_tvb);
//        break;
//    case NVME_FCTYPE_PROP_GET:
//        dissect_nvme_fabric_prop_get_cmd(cmd_tree, nvme_tvb);
//        break;
//    case NVME_FCTYPE_PROP_SET:
//        dissect_nvme_fabric_prop_set_cmd(cmd_tree, nvme_tvb);
//        break;
//    case NVME_FCTYPE_AUTH_RECV:
//    default:
//        dissect_nvme_fabric_generic_cmd(cmd_tree, nvme_tvb);
//        break;
//    }
//}
//
//static void
//dissect_nvme_fabric_connect_cmd_data(tvbuff_t *data_tvb, proto_tree *data_tree,
//                                     guint offset)
//{
//    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_hostid, data_tvb,
//                        offset, 16, ENC_NA);
//    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_cntlid, data_tvb,
//                        offset + 16, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_rsvd, data_tvb,
//                        offset + 18, 238, ENC_NA);
//    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_subnqn, data_tvb,
//                        offset + 256, 256, ENC_ASCII | ENC_NA);
//    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_hostnqn, data_tvb,
//                        offset + 512, 256, ENC_ASCII | ENC_NA);
//    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_rsvd1, data_tvb,
//                        offset + 768, 256, ENC_NA);
//}
//
//static void
//dissect_nvme_fabric_data(tvbuff_t *nvme_tvb, proto_tree *nvme_tree,
//                         guint len, guint8 fctype)
//{
//    proto_tree *data_tree;
//    proto_item *ti;
//
//    ti = proto_tree_add_item(nvme_tree, hf_nvme_rdma_cmd_data, nvme_tvb, 0,
//                             len, ENC_NA);
//    data_tree = proto_item_add_subtree(ti, ett_data);
//
//    switch (fctype) {
//    case NVME_FCTYPE_CONNECT:
//        dissect_nvme_fabric_connect_cmd_data(nvme_tvb, data_tree,
//                                             NVME_FABRIC_CMD_SIZE);
//        break;
//    default:
//        proto_tree_add_item(data_tree, hf_nvme_rdma_from_host_unknown_data,
//                            nvme_tvb, 0, len, ENC_NA);
//        break;
//    }
//}
//
//static void
//dissect_nvme_rdma_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
//                      proto_tree *nvme_tree, struct nvme_rdma_q_ctx *q_ctx,
//                      guint len)
//{
//    struct nvme_rdma_cmd_ctx *cmd_ctx;
//    guint16 cmd_id;
//    guint8 opcode;
//
//    opcode = tvb_get_guint8(nvme_tvb, 0);
//    cmd_id = tvb_get_guint16(nvme_tvb, 2, ENC_LITTLE_ENDIAN);
//    cmd_ctx = bind_cmd_to_qctx(pinfo, &q_ctx->n_q_ctx, cmd_id);
//    if (opcode == NVME_FABRIC_OPC) {
//        cmd_ctx->n_cmd_ctx.fabric = TRUE;
//        dissect_nvme_fabric_cmd(nvme_tvb, nvme_tree, cmd_ctx);
//        len -= NVME_FABRIC_CMD_SIZE;
//        if (len)
//            dissect_nvme_fabric_data(nvme_tvb, nvme_tree, len, cmd_ctx->fctype);
//    } else {
//        cmd_ctx->n_cmd_ctx.fabric = FALSE;
//        dissect_nvme_cmd(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx,
//                         &cmd_ctx->n_cmd_ctx);
//        if (cmd_ctx->n_cmd_ctx.remote_key) {
//            nvme_add_data_request(pinfo, &q_ctx->n_q_ctx,
//                                  &cmd_ctx->n_cmd_ctx, (void*)cmd_ctx);
//        }
//    }
//}
//
//static void
//dissect_nvme_from_host(tvbuff_t *nvme_tvb, packet_info *pinfo,
//                       proto_tree *root_tree, proto_tree *nvme_tree,
//                       struct infinibandinfo *info,
//                       struct nvme_rdma_q_ctx *q_ctx,
//                       guint len)
//
//{
//    switch (info->opCode) {
//    case RC_SEND_ONLY:
//        if (len >= NVME_FABRIC_CMD_SIZE)
//            dissect_nvme_rdma_cmd(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx, len);
//        else
//            proto_tree_add_item(nvme_tree, hf_nvme_rdma_from_host_unknown_data, nvme_tvb,
//                    0, len, ENC_NA);
//        break;
//    default:
//        proto_tree_add_item(nvme_tree, hf_nvme_rdma_from_host_unknown_data, nvme_tvb,
//                0, len, ENC_NA);
//        break;
//    }
//}
//
//static void
//dissect_nvme_rdma_cqe_status_8B(proto_tree *cqe_tree, tvbuff_t *cqe_tvb,
//                                  struct nvme_rdma_cmd_ctx *cmd_ctx)
//{
//    switch (cmd_ctx->fctype) {
//    case NVME_FCTYPE_CONNECT:
//        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_connect_cntlid, cqe_tvb,
//                            0, 2, ENC_LITTLE_ENDIAN);
//        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_connect_authreq, cqe_tvb,
//                            2, 2, ENC_LITTLE_ENDIAN);
//        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_connect_rsvd, cqe_tvb,
//                            4, 4, ENC_NA);
//        break;
//    case NVME_FCTYPE_PROP_GET:
//        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_sts, cqe_tvb,
//                            0, 8, ENC_LITTLE_ENDIAN);
//        break;
//    case NVME_FCTYPE_PROP_SET:
//        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_prop_set_rsvd, cqe_tvb,
//                            0, 8, ENC_NA);
//        break;
//    case NVME_FCTYPE_AUTH_RECV:
//    default:
//        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_sts, cqe_tvb,
//                            0, 8, ENC_LITTLE_ENDIAN);
//        break;
//    };
//}
//
//static void
//dissect_nvme_fabric_cqe(tvbuff_t *nvme_tvb,
//                        proto_tree *nvme_tree,
//                        struct nvme_rdma_cmd_ctx *cmd_ctx)
//{
//    proto_tree *cqe_tree;
//    proto_item *ti;
//
//    ti = proto_tree_add_item(nvme_tree, hf_nvme_rdma_cqe, nvme_tvb,
//                             0, NVME_FABRIC_CQE_SIZE, ENC_NA);
//    proto_item_append_text(ti, " (For Cmd: %s)", val_to_str(cmd_ctx->fctype,
//                                                fctype_tbl, "Unknown Cmd"));
//
//    cqe_tree = proto_item_add_subtree(ti, ett_data);
//
//    nvme_publish_cqe_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_rdma_cmd_pkt,
//                                 &cmd_ctx->n_cmd_ctx);
//    nvme_publish_cmd_latency(cqe_tree, &cmd_ctx->n_cmd_ctx, hf_nvme_rdma_cmd_latency);
//
//    dissect_nvme_rdma_cqe_status_8B(cqe_tree, nvme_tvb, cmd_ctx);
//
//    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_sqhd, nvme_tvb,
//                        8, 2, ENC_NA);
//    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_rsvd, nvme_tvb,
//                        10, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_cid, nvme_tvb,
//                        12, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_status, nvme_tvb,
//                        14, 2, ENC_LITTLE_ENDIAN);
//    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_status_rsvd, nvme_tvb,
//                        14, 2, ENC_LITTLE_ENDIAN);
//}
//
//static void
//dissect_nvme_rdma_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo,
//                      proto_tree *root_tree, proto_tree *nvme_tree,
//                      struct nvme_rdma_q_ctx *q_ctx)
//{
//    struct nvme_rdma_cmd_ctx *cmd_ctx;
//    guint16 cmd_id;
//
//    cmd_id = tvb_get_guint16(nvme_tvb, 12, ENC_LITTLE_ENDIAN);
//
//    if (!PINFO_FD_VISITED(pinfo)) {
//
//        cmd_ctx = (struct nvme_rdma_cmd_ctx*)
//                      nvme_lookup_cmd_in_pending_list(&q_ctx->n_q_ctx, cmd_id);
//        if (!cmd_ctx)
//            goto not_found;
//
//        /* we have already seen this cqe, or an identical one */
//        if (cmd_ctx->n_cmd_ctx.cqe_pkt_num)
//            goto not_found;
//
//        cmd_ctx->n_cmd_ctx.cqe_pkt_num = pinfo->num;
//        nvme_add_cmd_cqe_to_done_list(&q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id);
//    } else {
//        /* Already visited this frame */
//        cmd_ctx = (struct nvme_rdma_cmd_ctx*)
//                        nvme_lookup_cmd_in_done_list(pinfo, &q_ctx->n_q_ctx, cmd_id);
//        if (!cmd_ctx)
//            goto not_found;
//    }
//
//    nvme_update_cmd_end_info(pinfo, &cmd_ctx->n_cmd_ctx);
//
//    if (cmd_ctx->n_cmd_ctx.fabric)
//        dissect_nvme_fabric_cqe(nvme_tvb, nvme_tree, cmd_ctx);
//    else
//        dissect_nvme_cqe(nvme_tvb, pinfo, root_tree, &cmd_ctx->n_cmd_ctx);
//    return;
//
//not_found:
//    proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
//                        0, NVME_FABRIC_CQE_SIZE, ENC_NA);
//}
//
//static void
//dissect_nvme_to_host(tvbuff_t *nvme_tvb, packet_info *pinfo,
//                     proto_tree *root_tree, proto_tree *nvme_tree,
//                     struct infinibandinfo *info,
//                     struct nvme_rdma_q_ctx *q_ctx, guint len)
//{
//    struct nvme_rdma_cmd_ctx *cmd_ctx;
//
//    switch (info->opCode) {
//    case RC_SEND_ONLY:
//    case RC_SEND_ONLY_INVAL:
//        if (len == NVME_FABRIC_CQE_SIZE)
//            dissect_nvme_rdma_cqe(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx);
//        else
//            proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
//                    0, len, ENC_NA);
//        break;
//    case RC_RDMA_WRITE_ONLY:
//    case RC_RDMA_WRITE_FIRST:
//        if (!PINFO_FD_VISITED(pinfo)) {
//            cmd_ctx = (struct nvme_rdma_cmd_ctx*)
//                       nvme_lookup_data_request(&q_ctx->n_q_ctx,
//                                                info->reth_remote_key);
//            if (cmd_ctx) {
//                cmd_ctx->n_cmd_ctx.data_resp_pkt_num = pinfo->num;
//                nvme_add_data_response(&q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx,
//                                       info->reth_remote_key);
//            }
//        } else {
//            cmd_ctx = (struct nvme_rdma_cmd_ctx*)
//                       nvme_lookup_data_response(pinfo, &q_ctx->n_q_ctx,
//                                                 info->reth_remote_key);
//        }
//        if (cmd_ctx)
//            dissect_nvme_data_response(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx,
//                                       &cmd_ctx->n_cmd_ctx, len);
//        break;
//    default:
//        proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
//                0, len, ENC_NA);
//        break;
//    }
//}

//static void
//disect_nvme_tcp_on_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
//		struct nvme_tcp_q_ctx *conv_data/*, gboolean end_of_stream*/)
//{
//	int		offset = 0;
//	int		len;
//
//	while (tvb_reported_length_remaining(tvb, offset) > 0) {
////		len = dissect_http_message(tvb, offset, pinfo, tree, conv_data, "HTTP", proto_http, end_of_stream);
////				if (len == -1)
////					break;
////				offset += len;
//	}
////    struct nvme_rdma_cmd_ctx *cmd_ctx;
////
////    switch (info->opCode) {
////    case RC_SEND_ONLY:
////    case RC_SEND_ONLY_INVAL:
////        if (len == NVME_FABRIC_CQE_SIZE)
////            dissect_nvme_rdma_cqe(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx);
////        else
////            proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
////                    0, len, ENC_NA);
////        break;
////    case RC_RDMA_WRITE_ONLY:
////    case RC_RDMA_WRITE_FIRST:
////        if (!PINFO_FD_VISITED(pinfo)) {
////            cmd_ctx = (struct nvme_rdma_cmd_ctx*)
////                       nvme_lookup_data_request(&q_ctx->n_q_ctx,
////                                                info->reth_remote_key);
////            if (cmd_ctx) {
////                cmd_ctx->n_cmd_ctx.data_resp_pkt_num = pinfo->num;
////                nvme_add_data_response(&q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx,
////                                       info->reth_remote_key);
////            }
////        } else {
////            cmd_ctx = (struct nvme_rdma_cmd_ctx*)
////                       nvme_lookup_data_response(pinfo, &q_ctx->n_q_ctx,
////                                                 info->reth_remote_key);
////        }
////        if (cmd_ctx)
////            dissect_nvme_data_response(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx,
////                                       &cmd_ctx->n_cmd_ctx, len);
////        break;
////    default:
////        proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
////                0, len, ENC_NA);
////        break;
////    }
//}

/* dissector helper: length of PDU */
#include <stdio.h>
#define PDU_LEN_OFFSET_FROM_HEADER 4
static guint
get_nvme_tcp_pdu_len(packet_info *pinfo __attribute__((unused)), tvbuff_t *tvb __attribute__((unused)), int offset __attribute__((unused)), void *data _U_ __attribute__((unused)))
{

	guint pdu_len = tvb_get_letohl(tvb, offset + PDU_LEN_OFFSET_FROM_HEADER);
	printf("pdu len %d\n", pdu_len);
	return pdu_len;
//	/* Regular packet header: length (3) + sequence number (1) */
//	conversation_t	   *conversation;
//	mysql_conn_data_t  *conn_data;
//	guint		    len = 4 + tvb_get_letoh24(tvb, offset);
//
//	conversation = find_conversation_pinfo(pinfo, 0);
//	if (conversation) {
//		conn_data = (mysql_conn_data_t *)conversation_get_proto_data(conversation, proto_mysql);
//		if (conn_data && conn_data->compressed_state == MYSQL_COMPRESS_ACTIVE &&
//			pinfo->num > conn_data->frame_start_compressed) {
//			/* Compressed packet header includes uncompressed packet length (3) */
//			len += 3;
//		}
//	}
//
//	return len;

//	return 8;
}

static void
nvme_tcp_dissect_icreq(tvbuff_t *tvb, packet_info *pinfo __attribute__((unused)), int offset,
		       proto_tree *tree, struct nvme_tcp_q_ctx *queue) {

	proto_item *tf;
	proto_item *icreq_tree;
	guint       digest;
	// FIXME: should we set queue state here ?? Set connection state ????


	tf = proto_tree_add_item(tree, hf_nvme_tcp_icreq, tvb, offset, -1, ENC_NA);
	icreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp_icqreq);

	//col_append_fstr(pinfo->cinfo, COL_INFO, " proto=%d", protocol) ;


	proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_pfv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_maxr2t, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_hpda, tvb, offset, 1, ENC_NA);
	offset += 1;
	digest = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_digest, tvb, offset, 1, ENC_NA);
	offset += 1;

	queue->hdr_digest = !!(digest & NVME_TCP_HDR_DIGEST_ENABLE);
	queue->data_digest = !!(digest & NVME_TCP_DATA_DIGEST_ENABLE);

	// FIXME: should i register queue here???

	/* This is a "spare" field */
//	offset += 112;
//	return offset;
}


static void
nvme_tcp_dissect_icresp(tvbuff_t *tvb, packet_info *pinfo __attribute__((unused)), int offset,
		        proto_tree *tree, struct nvme_tcp_q_ctx *queue __attribute__((unused))) {

	proto_item *tf;
	proto_item *icresp_tree;

	// FIXME: should we set queue state here ?? Set connection state ????


	tf = proto_tree_add_item(tree, hf_nvme_tcp_icresp, tvb, offset, -1, ENC_NA);
	icresp_tree = proto_item_add_subtree(tf, ett_nvme_tcp_icqresp);

	//col_append_fstr(pinfo->cinfo, COL_INFO, " proto=%d", protocol) ;


	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_pfv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_cpda, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_digest, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_maxdata, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	// FIXME: now adjust data and header digest according to response

	/* This is a "spare" field */
//	offset += 112;
//	return offset;
}


static void
dissect_nvme_fabric_connect_cmd_data(tvbuff_t *data_tvb, proto_tree *data_tree,
                                     guint offset)
{
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_hostid, data_tvb,
                        offset, 16, ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_cntlid, data_tvb,
                        offset + 16, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_rsvd4, data_tvb,
                        offset + 18, 238, ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_subnqn, data_tvb,
                        offset + 256, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_hostnqn, data_tvb,
                        offset + 512, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_rsvd5, data_tvb,
                        offset + 768, 256, ENC_NA);
}


static void
dissect_nvme_fabric_data(tvbuff_t *nvme_tvb, proto_tree *nvme_tree,
			 guint32 len, guint8 fctype, int offset)
{
    proto_tree *data_tree;
    proto_item *ti;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_fabrics_cmd_data, nvme_tvb, 0,
                             len, ENC_NA);
    data_tree = proto_item_add_subtree(ti, ett_nvme_fabrics_data);

    switch (fctype) {
    case nvme_fabrics_type_connect:
        dissect_nvme_fabric_connect_cmd_data(nvme_tvb, data_tree, offset);
        break;
    default:
        proto_tree_add_item(data_tree, hf_nvme_fabrics_from_host_unknown_data,
                            nvme_tvb, 0, len, ENC_NA);
        break;
    }

//	static int hf_nvme_fabrics_cmd_data = -1;
//	static int hf_nvme_fabrics_cmd_connect_data_hostid = -1;
//	static int hf_nvme_fabrics_cmd_connect_data_cntlid = -1;
//	static int hf_nvme_fabrics_cmd_connect_data_rsvd4 = -1;
//	static int hf_nvme_fabrics_cmd_connect_data_subnqn = -1;
//	static int hf_nvme_fabrics_cmd_connect_data_hostnqn = -1;
//	static int hf_nvme_fabrics_cmd_connect_data_rsvd5 = -1;
}


static void dissect_nvme_fabric_generic_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, int offset)
{
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_generic_rsvd1, cmd_tvb,
                        offset + 5, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_generic_field, cmd_tvb,
                        offset + 40, 24, ENC_NA);
}

static void dissect_nvme_fabric_connect_cmd(struct nvme_tcp_q_ctx *queue, proto_tree *cmd_tree, tvbuff_t *cmd_tvb, int offset)
{
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_rsvd2, cmd_tvb,
	    	        offset + 5, 19, ENC_NA);
    dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvme_fabrics_cmd_connect_sgl1, NULL);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_recfmt, cmd_tvb,
		    	offset + 40, 2, ENC_LITTLE_ENDIAN);

    queue->n_q_ctx.qid = tvb_get_guint16(cmd_tvb, offset + 42, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_qid, cmd_tvb,
		    	offset + 42, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_sqsize, cmd_tvb,
		    	offset + 44, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_cattr, cmd_tvb,
		    	offset + 46, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_rsvd3, cmd_tvb,
		    	offset + 47, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_kato, cmd_tvb,
		    	offset + 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_rsvd4, cmd_tvb,
		    	offset + 52, 12, ENC_NA);
}


static guint8 dissect_nvme_fabric_prop_cmd_common(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, int offset)
{
    proto_item *attr_item, *offset_item;
    guint32 offset_in_string;
    guint8 attr;

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_rsvd1, cmd_tvb,
                        offset + 5, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_rsvd2, cmd_tvb,
		    	offset + 40, 1, ENC_LITTLE_ENDIAN);
    attr_item = proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_size, cmd_tvb,
                                    offset + 40, 1, ENC_LITTLE_ENDIAN);
    attr = tvb_get_guint8(cmd_tvb, offset + 40) & 0x7;
    proto_item_append_text(attr_item, " %s",
                           val_to_str(attr, attr_size_tbl, "Reserved"));

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_rsvd3, cmd_tvb,
                        offset + 41, 3, ENC_NA);

    offset_item = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_offset,
                                      cmd_tvb, offset + 44, 4, ENC_LITTLE_ENDIAN, &offset_in_string);
    proto_item_append_text(offset_item, " %s",
                           val_to_str(offset_in_string, prop_offset_tbl, "Unknown Property"));
    return attr;
}

static void dissect_nvme_fabric_prop_get_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, int offset)
{
    dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, offset);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_get_rsvd4, cmd_tvb,
                        offset + 48, 16, ENC_NA);
}


static void dissect_nvme_fabric_prop_set_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, int offset)
{
    guint8 attr;


    attr = dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, offset);
    if (attr == 0) {
        proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_set_4B_value, cmd_tvb,
                            offset + 48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_set_4B_value_rsvd, cmd_tvb,
                            offset + 52, 4, ENC_LITTLE_ENDIAN);
    } else {
	// FIXME: currently we dont have controller configuration settings
	// as human readable strings .. need to work on it
        proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_set_8B_value, cmd_tvb,
                            offset + 48, 8, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_set_rsvd3, cmd_tvb,
                        offset + 56, 8, ENC_NA);
}

static void
dissect_nvme_fabric_cmd(tvbuff_t *nvme_tvb, proto_tree *nvme_tree,
			struct nvme_tcp_q_ctx *queue,
                        struct nvme_tcp_cmd_ctx *cmd_ctx, int offset)
{
    proto_tree *cmd_tree;
    proto_item *ti, *opc_item;/*, *fctype_item;*/
    //*opc_item,;
    guint8 fctype;
//
    fctype = tvb_get_guint8(nvme_tvb, offset + 4);
    cmd_ctx->fctype = fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_fabrics_cmd, nvme_tvb, 0,
                             NVME_FABRIC_CMD_SIZE, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_nvme_fabrics);

    opc_item = proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_opc, nvme_tvb,
                                   offset, 1, ENC_NA);
    proto_item_append_text(opc_item, "%s", " Fabric Cmd");

    nvme_publish_cmd_to_cqe_link(cmd_tree, nvme_tvb, hf_nvme_fabrics_cqe_pkt,
                                 &cmd_ctx->n_cmd_ctx);

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_rsvd1, nvme_tvb,
                        offset + 1, 1, ENC_NA);

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_cid, nvme_tvb,
		    	offset + 2, 2, ENC_LITTLE_ENDIAN);

    // FIXME what about unknown type??
    /*fctype_item = */proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_fctype,
                                      nvme_tvb,
                                      offset + 4, 1, ENC_LITTLE_ENDIAN);

//    proto_item_append_text(fctype_item, " %s",
//                           val_to_str(fctype, fctype_tbl, "Unknown FcType"));
//
    switch(fctype) {
    case nvme_fabrics_type_connect:
        dissect_nvme_fabric_connect_cmd(queue, cmd_tree, nvme_tvb, offset);
        break;
    case nvme_fabrics_type_property_get:
        dissect_nvme_fabric_prop_get_cmd(cmd_tree, nvme_tvb, offset);
        break;
    case nvme_fabrics_type_property_set:
        dissect_nvme_fabric_prop_set_cmd(cmd_tree, nvme_tvb, offset);
        break;
    default:
        dissect_nvme_fabric_generic_cmd(cmd_tree, nvme_tvb, offset);
        break;
    }

}


static struct nvme_tcp_cmd_ctx*
bind_cmd_to_qctx(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                 guint16 cmd_id)
{
   struct nvme_tcp_cmd_ctx *ctx;


   // FIXME: why in rdma they are asking if they visited the frame ??
   ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
   nvme_add_cmd_to_pending_list(pinfo, q_ctx,
                                &ctx->n_cmd_ctx, (void*)ctx, cmd_id);
   return ctx;

   //ctx = (struct nvme_rdma_cmd_ctx*)
   //                 nvme_lookup_cmd_in_done_list(pinfo, q_ctx, cmd_id);

//   if (!PINFO_FD_VISITED(pinfo)) {
//       ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
//
//       nvme_add_cmd_to_pending_list(pinfo, q_ctx,
//                                    &ctx->n_cmd_ctx, (void*)ctx, cmd_id);
//    } else {
//        /* Already visited this frame */
//        ctx = (struct nvme_rdma_cmd_ctx*)
//                  nvme_lookup_cmd_in_done_list(pinfo, q_ctx, cmd_id);
//        /* if we have already visited frame but haven't found completion yet,
//         * we won't find cmd in done q, so allocate a dummy ctx for doing
//         * rest of the processing.
//         */
//        if (!ctx)
//            ctx = wmem_new0(wmem_file_scope(), struct nvme_rdma_cmd_ctx);
//    }
//    return ctx;
}


static void
dissect_nvme_tcp_command(tvbuff_t *tvb, packet_info *pinfo, int offset,
		        proto_tree *tree, struct nvme_tcp_q_ctx *queue,
			guint32         incapsuled_data_size) {

	struct nvme_tcp_cmd_ctx *cmd_ctx;
	guint16 cmd_id;
	guint8 opcode;

	opcode = tvb_get_guint8(tvb, offset);
	cmd_id = tvb_get_guint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
	cmd_ctx = bind_cmd_to_qctx(pinfo, &queue->n_q_ctx, cmd_id);

	if (opcode == nvme_fabrics_command) {
		cmd_ctx->n_cmd_ctx.fabric = TRUE;
		dissect_nvme_fabric_cmd(tvb, tree, queue, cmd_ctx, offset);
		if (incapsuled_data_size > 0) {
			dissect_nvme_fabric_data(tvb, tree, incapsuled_data_size, cmd_ctx->fctype, offset + NVME_FABRIC_CMD_SIZE);
		}
	} else {
		tvbuff_t *nvme_tvbuff;
		cmd_ctx->n_cmd_ctx.fabric = FALSE;
		/* get incapsuled nvme command */
		nvme_tvbuff = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
		dissect_nvme_cmd(nvme_tvbuff, pinfo, tree, &queue->n_q_ctx,
		                   &cmd_ctx->n_cmd_ctx);
		// FIXME: Interesting what to do here ??? should i parse data or somethinh ??
	}
}


static void
dissect_nvme_fabrics_cqe_status_8B(proto_tree *cqe_tree __attribute__((unused)), tvbuff_t *cqe_tvb __attribute__((unused)),
                                  struct nvme_tcp_cmd_ctx *cmd_ctx __attribute__((unused)), int offset __attribute__((unused)))
{
    switch (cmd_ctx->fctype) {
    case nvme_fabrics_type_connect:
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_connect_cntlid, cqe_tvb,
                            offset + 0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_connect_authreq, cqe_tvb,
                            offset + 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_connect_rsvd, cqe_tvb,
                            offset + 4, 4, ENC_NA);
        break;
    case nvme_fabrics_type_property_get:
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_sts, cqe_tvb,
                            offset + 0, 8, ENC_LITTLE_ENDIAN);
        break;
    case nvme_fabrics_type_property_set:
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_prop_set_rsvd, cqe_tvb,
                            offset + 0, 8, ENC_NA);
        break;
    };
}

static void
dissect_nvme_fabric_cqe(tvbuff_t *nvme_tvb,
                        proto_tree *nvme_tree,
                        struct nvme_tcp_cmd_ctx *cmd_ctx,
			int offset)
{
	proto_tree *cqe_tree;
	proto_item *ti;

	ti = proto_tree_add_item(nvme_tree, hf_nvme_fabrics_cqe, nvme_tvb,
				 0, NVME_FABRIC_CQE_SIZE, ENC_NA);

	proto_item_append_text(ti, " (For Cmd: %s)", val_to_str(cmd_ctx->fctype,
			       nvme_fabrics_cmd_type_vals, "Unknown Cmd"));

	cqe_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

	nvme_publish_cqe_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_fabrics_cmd_pkt,
				 &cmd_ctx->n_cmd_ctx);
	nvme_publish_cmd_latency(cqe_tree, &cmd_ctx->n_cmd_ctx, hf_nvme_fabrics_cmd_latency);

	dissect_nvme_fabrics_cqe_status_8B(cqe_tree, nvme_tvb, cmd_ctx, offset);

	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_sqhd, nvme_tvb,
			offset + 8, 2, ENC_NA);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_rsvd, nvme_tvb,
			offset + 10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_cid, nvme_tvb,
			offset + 12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_status, nvme_tvb,
			offset + 14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_status_rsvd, nvme_tvb,
			offset + 14, 2, ENC_LITTLE_ENDIAN);
}


static void
dissect_nvme_tcp_cqe(tvbuff_t *tvb, packet_info *pinfo, int offset,
		          proto_tree *tree, struct nvme_tcp_q_ctx *queue)
{
	struct nvme_tcp_cmd_ctx *cmd_ctx;
	guint16 cmd_id;

	cmd_id = tvb_get_guint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);
	cmd_ctx = (struct nvme_tcp_cmd_ctx*)
	             nvme_lookup_cmd_in_pending_list(&queue->n_q_ctx, cmd_id);

	// FIXME: we can dissect fields even if we did not find relecant command
	// consuder doing it
	if (!cmd_ctx)
		goto not_found;

	/* we have already seen this cqe, or an identical one */
	if (cmd_ctx->n_cmd_ctx.cqe_pkt_num)
	    goto not_found;

	cmd_ctx->n_cmd_ctx.cqe_pkt_num = pinfo->num;
	nvme_add_cmd_cqe_to_done_list(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id);

	nvme_update_cmd_end_info(pinfo, &cmd_ctx->n_cmd_ctx);

	if (cmd_ctx->n_cmd_ctx.fabric) {
		dissect_nvme_fabric_cqe(tvb, tree, cmd_ctx, offset);
	} else {
		// FIXME: dissect nvme cqe
		//dissect_nvme_cqe(tvb, pinfo, root_tree, &cmd_ctx->n_cmd_ctx);
	}
	return;
not_found:
	proto_tree_add_item(tree, hf_nvme_tcp_to_host_unknown_data, tvb,
			    offset, NVME_FABRIC_CQE_SIZE, ENC_NA);
}



static int
dissect_nvme_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo __attribute__((unused)), proto_tree *tree __attribute__((unused)), void* data _U_ __attribute__((unused))) {
	conversation_t  *conversation;
	struct nvme_tcp_q_ctx *q_ctx;
	proto_item      *ti;
	int             offset = 0;
	int 		nvme_tcp_pdu_offset;
	proto_tree      *nvme_tcp_tree;
	guint           packet_type;
	//guint           pdo;
	guint32         hlen;
	guint32         plen;
	guint32         incapsuled_data_size;


	conversation = find_or_create_conversation(pinfo);
	q_ctx = (struct nvme_tcp_q_ctx *)conversation_get_proto_data(conversation, proto_nvme_tcp);

	if (!q_ctx) {
		q_ctx = (struct nvme_tcp_q_ctx *)wmem_alloc0(wmem_file_scope(), sizeof(struct nvme_tcp_q_ctx));
		q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
		q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
		q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
		q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
		/* Initially set to non-0 so that by default queues are io queues
		 * this is required to be able to dissect correctly even if we mistt connect
		 * command*/
		q_ctx->n_q_ctx.qid = G_MAXUINT16;
		conversation_add_proto_data(conversation, proto_nvme_tcp, q_ctx);
	}


	col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);
	// FIXME: it is possible to have multiple nvme pdus in single frame ..
	// so we need to figure this out as well

	ti = proto_tree_add_item(tree, proto_nvme_tcp, tvb, 0, -1, ENC_NA);
	nvme_tcp_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

	if (q_ctx->n_q_ctx.qid != G_MAXUINT16)
		nvme_publish_qid(nvme_tcp_tree, hf_nvme_fabrics_cmd_qid, q_ctx->n_q_ctx.qid);


	packet_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_flags, tvb, offset + 1, 1, ENC_NA);
	hlen = tvb_get_letohs(tvb, offset + 2);
	proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_hlen, tvb, offset + 2, 1, ENC_NA);
	proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_pdo, tvb, offset + 3, 1, ENC_NA);
	plen = tvb_get_letohl(tvb, offset + 4);
	proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_plen, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);

	//
	//offset += (pdo - 8);

	//nvme_publish_qid(nvme_tree, hf_nvme_rdma_cmd_qid, q_ctx->n_q_ctx.qid);
	/* When we get here offset points directly after tcp header */
	nvme_tcp_pdu_offset = offset + NVME_TCP_HEADER_SIZE;

	/* This is the total length of the payload minus nvme header size
	 * Needed to */
	incapsuled_data_size = plen - hlen;
	printf("Plen %u hlen %u capsule len %u \n", plen, hlen, incapsuled_data_size);

	switch (packet_type) {
	case nvme_tcp_icreq:
		col_set_str(pinfo->cinfo, COL_INFO, "Connect Request");
		nvme_tcp_dissect_icreq(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx);
		break;
	case nvme_tcp_icresp:
		col_set_str(pinfo->cinfo, COL_INFO, "Connect Response");
		nvme_tcp_dissect_icresp(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx);
		break;
	case nvme_tcp_cmd:
		//col_set_str(pinfo->cinfo, COL_INFO, "");
		dissect_nvme_tcp_command(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx, incapsuled_data_size);
		break;
	case nvme_tcp_rsp:
		dissect_nvme_tcp_cqe(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx);
		break;
	default:
		printf("Error in parsing...\n");
		// FIXME: add here error info

	}

	offset += plen;

	//osset +=

	/* remaining payload indicates an error */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		/*ti = proto_tree_add_item(mysql_tree, hf_mysql_payload, tvb, offset, -1, ENC_NA);
		expert_add_info(pinfo, ti, &ei_mysql_dissector_incomplete);*/
		printf("%s:%d ERROR!!! remaining in parsing %d\n", __FILE__, __LINE__, tvb_reported_length_remaining(tvb, offset));
	}

	return tvb_reported_length(tvb);
}



static int
dissect_nvme_tcp(tvbuff_t *tvb __attribute__((unused)), packet_info *pinfo __attribute__((unused)), proto_tree *tree __attribute__((unused)), void *data __attribute__((unused)))
{
//      struct tcpinfo *tcpinfo = (struct tcpinfo *)data;
////    struct infinibandinfo *info = (struct infinibandinfo *)data;
////    conversation_infiniband_data *conv_data = NULL;
//      conversation_t *conv;
//      proto_tree *nvme_tree;
//      proto_item *ti;
//      struct nvme_tcp_q_ctx *q_ctx;
//      guint len = tvb_reported_length(tvb);
////
////    conv = find_ib_conversation(pinfo, &conv_data);
////    if (!conv)
////        return FALSE;
////
//      q_ctx = get_nvme_tcp_conversation_data(pinfo, &conv);
//      col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);
////
//      ti = proto_tree_add_item(tree, proto_nvme_tcp, tvb, 0, len, ENC_NA);
//      nvme_tree = proto_item_add_subtree(ti, ett_nvme_tcp);
//
//      // FIXME: when can we add this ??? only after we establish queue id .. .
//      //nvme_publish_qid(nvme_tree, hf_nvme_rdma_cmd_qid, q_ctx->n_q_ctx.qid);
////
////    if (conv_data->client_to_server)
////        dissect_nvme_from_host(tvb, pinfo, tree, nvme_tree, info, q_ctx, len);
////    else
////        dissect_nvme_to_host(tvb, pinfo, tree, nvme_tree, info, q_ctx, len);
////
//     disect_nvme_tcp_on_stream(tvb, pinfo, tree, nvme_tree, q_ctx);
//     return TRUE;

	printf("we are here %s:%d\n", __FILE__,__LINE__);
	tcp_dissect_pdus(tvb, pinfo, tree, /*mysql_desegment*/ TRUE, NVME_TCP_HEADER_SIZE,
			 get_nvme_tcp_pdu_len, dissect_nvme_tcp_pdu, data);

	return tvb_reported_length(tvb);
}

#include <epan/expert.h>
void
proto_register_nvme_tcp(void)
{

     module_t *nvme_tcp_module;
     //expert_module_t* expert_nvme_tcp;
     static hf_register_info hf[] = {
	     { &hf_nvme_tcp_type,
	         { "Pdu Type", "nvme-tcp.type",
	               FT_UINT8, BASE_DEC, VALS (nvme_tcp_pdu_type_vals),  0x0,
				NULL, HFILL }},
	     { &hf_nvme_tcp_flags,
			 { "Pdu Specific Flags", "nvme-tcp.flags",
			       FT_UINT8, BASE_DEC, NULL,  0x0,
					NULL, HFILL }},
    	     { &hf_nvme_tcp_hlen,
		 { "Pdu Header Length", "nvme-tcp.hlen",
		       FT_UINT8, BASE_DEC, NULL,  0x0,
				NULL, HFILL }},
	     { &hf_nvme_tcp_pdo,
			 { "Pdu Data Offset", "nvme-tcp.pdo",
			       FT_UINT8, BASE_DEC, NULL,  0x0,
					NULL, HFILL }},
	     { &hf_nvme_tcp_plen,
	         { "Packet Length", "nvme-tcp.plen",
	                FT_UINT32, BASE_DEC, NULL,  0x0,
			NULL, HFILL }},

	     { &hf_nvme_tcp_icreq,
			{ "Initial Connect Request", "nvme-tcp.icreq",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	     { &hf_nvme_tcp_icreq_pfv,
			 { "Pdu Version Format", "nvme-tcp.icreq.pfv",
				FT_UINT16, BASE_DEC, NULL,  0x0,
				NULL, HFILL }},

	    { &hf_nvme_tcp_icreq_maxr2t,
				 { "Maximum r2ts per request", "nvme-tcp.icreq.maxr2t",
					FT_UINT32, BASE_DEC, NULL,  0x0,
					NULL, HFILL }},

  	    { &hf_nvme_tcp_icreq_hpda,
			{ "Host Pdu data alignment", "nvme-tcp.icreq.hpda",
			FT_UINT8, BASE_DEC, NULL,  0x0,
				NULL, HFILL }},

            { &hf_nvme_tcp_icreq_digest,
			{ "Digest Types Enabled", "nvme-tcp.icreq.digest",
			FT_UINT8, BASE_DEC, NULL,  0x0,
				NULL, HFILL }},

	    { &hf_nvme_tcp_icresp,
				{ "Initial Connect Response", "nvme-tcp.icresp",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

	    { &hf_nvme_tcp_icresp_pfv,
				 { "Pdu Version Format", "nvme-tcp.icresp.pfv",
					FT_UINT16, BASE_DEC, NULL,  0x0,
					NULL, HFILL }},

	    { &hf_nvme_tcp_icresp_cpda,
				 { "Controller Pdu data alignment", "nvme-tcp.icresp.cpda",
					FT_UINT32, BASE_DEC, NULL,  0x0,
					NULL, HFILL }},

	    { &hf_nvme_tcp_icresp_digest,
			{ "Digest types enabled", "nvme-tcp.icresp.digest",
			FT_UINT8, BASE_DEC, NULL,  0x0,
				NULL, HFILL }},

	    { &hf_nvme_tcp_icresp_maxdata,
			{ "Maximum data capsules per r2t supported", "nvme-tcp.icresp.maxdata",
			FT_UINT8, BASE_DEC, NULL,  0x0,
				NULL, HFILL }},

	    /* NVMe fabrics command */
	   { &hf_nvme_fabrics_cmd,
	    { "Cmd", "nvme-tcp.cmd",
	       FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	   },

	   { &hf_nvme_fabrics_cmd_opc,
	       { "Opcode", "nvme-tcp.cmd.opc",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
	   },
	   { &hf_nvme_fabrics_cmd_rsvd1,
	       { "Reserved", "nvme-tcp.cmd.rsvd",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
	   },

	   { &hf_nvme_fabrics_cmd_cid,
	               { "Command ID", "nvme-tcp.cmd.cid",
	                  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
	   },

	   { &hf_nvme_fabrics_cmd_fctype,
	      { "Fabric Cmd Type", "nvme-tcp.cmd.fctype",
		 FT_UINT8, BASE_HEX, VALS (nvme_fabrics_cmd_type_vals) , 0x0, NULL, HFILL}
	  },

	  { &hf_nvme_fabrics_cmd_generic_rsvd1,
	              { "Reserved", "nvme-rdma.cmd.generic.rsvd1",
	                 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_generic_field,
	      { "Fabric Cmd specific field", "nvme-rdma.cmd.generic.field",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },

	  /* NVMe connect command fields */
	  { &hf_nvme_fabrics_cmd_connect_rsvd2,
	      { "Reserved", "nvme-tcp.cmd.connect.rsvd1",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_sgl1,
	      { "SGL1", "nvme-tcp.cmd.connect.sgl1",
		 FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_recfmt,
	      { "Record Format", "nvme-tcp.cmd.connect.recfmt",
		 FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_qid,
	      { "Queue ID", "nvme-tcp.cmd.connect.qid",
		 FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_sqsize,
	      { "SQ Size", "nvme-tcp.cmd.connect.sqsize",
		 FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_cattr,
	      { "Connect Attributes", "nvme-tcp.cmd.connect.cattr",
		 FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_rsvd3,
	      { "Reserved", "nvme-tcp.cmd.connect.rsvd2",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_kato,
	      { "Keep Alive Timeout", "nvme-tcp.cmd.connect.kato",
		 FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_rsvd4,
	      { "Reserved", "nvme-tcp.cmd.connect.rsvd4",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },

	  /* NVMe connect command data */
	  { &hf_nvme_fabrics_cmd_data,
	      { "Data", "nvme-tcp.cmd.data",
		 FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_hostid,
	      { "Host Identifier", "nvme-tcp.cmd.connect.data.hostid",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_cntlid,
	      { "Controller ID", "nvme-tcp.cmd.connect.data.cntrlid",
		 FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_rsvd4,
	      { "Reserved", "nvme-tcpcmd.connect.data.rsvd4",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_subnqn,
	      { "Subsystem NQN", "nvme-tcp.cmd.connect.data.subnqn",
		 FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_hostnqn,
	      { "Host NQN", "nvme-tcp.cmd.connect.data.hostnqn",
		 FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_rsvd5,
	      { "Reserved", "nvme-tcp.cmd.connect.data.rsvd5",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_from_host_unknown_data,
	      { "Dissection unsupported", "nvme-rdma.unknown_data",
		 FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },




//	  static int hf_nvme_fabrics_cmd_data = -1;
//	  static int hf_nvme_fabrics_cmd_connect_data_hostid = -1;
//	  static int hf_nvme_fabrics_cmd_connect_data_cntlid = -1;
//	  static int hf_nvme_fabrics_cmd_connect_data_rsvd = -1;
//	  static int hf_nvme_fabrics_cmd_connect_data_subnqn = -1;
//	  static int hf_nvme_fabrics_cmd_connect_data_hostnqn = -1;
//	  static int hf_nvme_fabrics_cmd_connect_data_rsvd1 = -1;



/*


	  static int hf_nvme_fabrics_cmd_connect_rsvd1 = -1;
	  static int hf_nvme_fabrics_cmd_connect_sgl1 = -1;
	  static int hf_nvme_fabrics_cmd_connect_recfmt = -1;
	  static int hf_nvme_fabrics_cmd_connect_qid = -1;
	  static int hf_nvme_fabrics_cmd_connect_sqsize = -1;
	  static int hf_nvme_fabrics_cmd_connect_cattr = -1;
	  static int hf_nvme_fabrics_cmd_connect_rsvd2 = -1;
	  static int hf_nvme_fabrics_cmd_connect_kato = -1;
	  static int hf_nvme_fabrics_cmd_connect_rsvd3 = -1;
	  static int hf_nvme_fabrics_cmd_connect_rsvd4 = -1;
	  */








//    static hf_register_info hf[] = {
//        /* IB RDMA CM fields */
//        { &hf_nvme_rdma_cm_req_recfmt,
//            { "Recfmt", "nvme-rdma.cm.req.recfmt",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_req_qid,
//            { "Qid", "nvme-rdma.cm.req.qid",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_req_hrqsize,
//            { "HrqSize", "nvme-rdma.cm.req.hrqsize",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_req_hsqsize,
//            { "HsqSize", "nvme-rdma.cm.req.hsqsize",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_req_reserved,
//            { "Reserved", "nvme-rdma.cm.req.reserved",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_rsp_recfmt,
//            { "Recfmt", "nvme-rdma.cm.rsp.recfmt",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_rsp_crqsize,
//            { "CrqSize", "nvme-rdma.cm.rsp.crqsize",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_rsp_reserved,
//            { "Reserved", "nvme-rdma.cm.rsp.reserved",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_rej_recfmt,
//            { "Recfmt", "nvme-rdma.cm.rej.recfmt",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_rej_status,
//            { "Status", "nvme-rdma.cm.rej.status",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cm_rej_reserved,
//            { "Reserved", "nvme-rdma.cm.rej.reserved",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        /* IB RDMA NVMe Command fields */
//        { &hf_nvme_rdma_cmd,
//            { "Cmd", "nvme-rdma.cmd",
//               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_from_host_unknown_data,
//            { "Dissection unsupported", "nvme-rdma.unknown_data",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_opc,
//            { "Opcode", "nvme-rdma.cmd.opc",
//               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_rsvd,
//            { "Reserved", "nvme-rdma.cmd.rsvd",
//               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_cid,
//            { "Command ID", "nvme-rdma.cmd.cid",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_fctype,
//            { "Fabric Cmd Type", "nvme-rdma.cmd.fctype",
//               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_rsvd1,
//            { "Reserved", "nvme-rdma.cmd.connect.rsvd1",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_sgl1,
//            { "SGL1", "nvme-rdma.cmd.connect.sgl1",
//               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_recfmt,
//            { "Record Format", "nvme-rdma.cmd.connect.recfmt",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_qid,
//            { "Queue ID", "nvme-rdma.cmd.connect.qid",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_sqsize,
//            { "SQ Size", "nvme-rdma.cmd.connect.sqsize",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_cattr,
//            { "Connect Attributes", "nvme-rdma.cmd.connect.cattr",
//               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_rsvd2,
//            { "Reserved", "nvme-rdma.cmd.connect.rsvd2",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_kato,
//            { "Keep Alive Timeout", "nvme-rdma.cmd.connect.kato",
//               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_rsvd3,
//            { "Reserved", "nvme-rdma.cmd.connect.rsvd3",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_data,
//            { "Data", "nvme-rdma.cmd.data",
//               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_data_hostid,
//            { "Host Identifier", "nvme-rdma.cmd.connect.data.hostid",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_data_cntlid,
//            { "Controller ID", "nvme-rdma.cmd.connect.data.cntrlid",
//               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_data_rsvd,
//            { "Reserved", "nvme-rdma.cmd.connect.data.rsvd",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_data_subnqn,
//            { "Subsystem NQN", "nvme-rdma.cmd.connect.data.subnqn",
//               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_data_hostnqn,
//            { "Host NQN", "nvme-rdma.cmd.connect.data.hostnqn",
//               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_connect_data_rsvd1,
//            { "Reserved", "nvme-rdma.cmd.connect.data.rsvd1",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
        { &hf_nvme_fabrics_cmd_prop_attr_rsvd1,
            { "Reserved", "nvme-rdma.cmd.prop_attr.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_rsvd2,
            { "Reserved", "nvme-rdma.cmd.prop_attr.rsvd2",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_size,
            { "Property Size", "nvme-rdma.cmd.prop_attr.size",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_rsvd3,
            { "Reserved", "nvme-rdma.cmd.prop_attr.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_offset,
            { "Offset", "nvme-rdma.cmd.prop_attr.offset",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_get_rsvd4,
            { "Reserved", "nvme-tcp.cmd.prop_attr.get.rsvd4",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_set_4B_value,
            { "Value", "nvme-tcp.cmd.prop_attr.set.value.4B",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_set_4B_value_rsvd,
            { "Reserved", "nvme-tcp.cmd.prop_attr.set.value.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_set_8B_value,
            { "Value", "nvme-tcp.cmd.prop_attr.set.value.8B",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cmd_prop_attr_set_rsvd3,
            { "Reserved", "nvme-tcp.cmd.prop_attr.set.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
//        { &hf_nvme_rdma_cmd_generic_rsvd1,
//            { "Reserved", "nvme-rdma.cmd.generic.rsvd1",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        { &hf_nvme_rdma_cmd_generic_field,
//            { "Fabric Cmd specific field", "nvme-rdma.cmd.generic.field",
//               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
//        },
//        /* IB RDMA NVMe Response fields */
        { &hf_nvme_fabrics_cqe,
            { "Cqe", "nvme-tcp.cqe",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_sts,
            { "Cmd specific Status", "nvme-tcp.cqe.sts",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_sqhd,
            { "SQ Head Pointer", "nvme-tcp.cqe.sqhd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_rsvd,
            { "Reserved", "nvme-tcp.cqe.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_cid,
            { "Command ID", "nvme-tcp.cqe.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_status,
            { "Status", "nvme-tcp.cqe.status",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_status_rsvd,
            { "Reserved", "nvme-tcp.cqe.status.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_connect_cntlid,
            { "Controller ID", "nvme-tcp.cqe.connect.cntrlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_connect_authreq,
            { "Authentication Required", "nvme-tcp.cqe.connect.authreq",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_connect_rsvd,
            { "Reserved", "nvme-tcp.cqe.connect.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fabrics_cqe_prop_set_rsvd,
            { "Reserved", "nvme-tcp.cqe.prop_set.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
	{ &hf_nvme_tcp_to_host_unknown_data,
	    { "Dissection unsupported", "nvme-tcp.unknown_data",
	       FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	},
        { &hf_nvme_fabrics_cmd_pkt,
            { "Fabric Cmd in", "nvme-tcp.cmd_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cmd for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_fabrics_cqe_pkt,
            { "Fabric Cqe in", "nvme-tcp.cqe_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cqe for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_fabrics_cmd_latency,
            { "Cmd Latency", "nvme-tcp.cmd_latency",
              FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "The time between the command and completion, in usec", HFILL }
        },
        { &hf_nvme_fabrics_cmd_qid,
            { "Cmd Qid", "nvme-tcp.cmd.qid",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "Qid on which command is issued", HFILL }
        },
    };
    static gint *ett[] = {
        &ett_nvme_tcp,
	&ett_nvme_tcp_icqreq,
	&ett_nvme_tcp_icqresp,
	&ett_nvme_fabrics,
	&ett_nvme_fabrics_data
    };
//
     proto_nvme_tcp = proto_register_protocol("NVM Express Fabrics TCP",
                                              NVME_FABRICS_TCP, "nvme-tcp");

     proto_register_field_array (proto_nvme_tcp, hf, array_length (hf));
     proto_register_subtree_array (ett, array_length (ett));

//     tf = proto_tree_add_item(tree, hf_mysql_server_greeting, tvb, offset, -1, ENC_NA);
//     greeting_tree = proto_item_add_subtree(tf, ett_server_greeting);


//
//    proto_register_field_array(proto_nvme_rdma, hf, array_length(hf));
//    proto_register_subtree_array(ett, array_length(ett));
//
//    /* Register preferences */
//    //nvme_rdma_module = prefs_register_protocol(proto_nvme_rdma, proto_reg_handoff_nvme_rdma);
     nvme_tcp_module = prefs_register_protocol(proto_nvme_tcp, NULL);
//
     range_convert_str(wmem_epan_scope(), &gPORT_RANGE, NVME_TCP_PORT_RANGE, MAX_TCP_PORT);
     prefs_register_range_preference(nvme_tcp_module,
                                    "subsystem_ports",
                                    "Subsystem Ports Range",
                                    "Range of NVMe Subsystem ports"
                                    "(default " NVME_TCP_PORT_RANGE ")",
                                    &gPORT_RANGE, MAX_TCP_PORT);
     //expert_nvme_tcp = expert_register_protocol(proto_nvme_tcp);
     nvmet_tcp_handle = register_dissector("nvme-tcp", dissect_nvme_tcp, proto_nvme_tcp);
     printf("we are here %s:%d\n", __FILE__,__LINE__);
}

void
proto_reg_handoff_nvme_tcp(void)
{
//    heur_dissector_add("tcp", dissect_nvme_tcp,
//                       "NVMe Fabrics TCP packets",
//                       "nvme_tcp", proto_nvme_tcp, HEURISTIC_ENABLE);
      printf("we are here %s:%d\n", __FILE__,__LINE__);
      //tcp_handler = find_dissector_add_dependency("tcp", proto_nvme_tcp);
      //proto_tcp = dissector_handle_get_protocol_index(tcp_handler);
      dissector_add_uint_with_preference("tcp.port", 4420, nvmet_tcp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
