/* packet-nvme-tcp.c
 * Routines for NVM Express over Fabrics(TCP) dissection
 * Code by Alexander Solganik
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
for TCP. This adds very basic support for dissecting commands
completions.

Current dissection supports dissection of
(a) NVMe cmd and cqe
(b) NVMe Fabric command and cqe
As part of it, it also calculates cmd completion latencies.

This protocol is similar to iSCSI and SCSI dissection where iSCSI is
transport protocol for carying SCSI commands and responses. Similarly
NVMe Fabrics - TCP transport protocol carries NVMe commands.

     +----------+
     |   NVMe   |
     +------+---+
            |
+-----------+------------------+
|         NVMe Fabrics 	       |
+----+-----------+-------------+
     |           |	     |
+----+---+   +---+----+  +---+---+
|  RDMA  |   |   FC   |  |  TCP  |
+--------+   +--------+  +--------+

References:
NVMe Express fabrics specification is located at
http://www.nvmexpress.org/wp-content/uploads/NVMe_over_Fabrics_1_0_Gold_20160605.pdf

NVMe Express specification is located at
http://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_2a.pdf

NVM Express TCP TCP port assigned by IANA that maps to RDMA IP service
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
static dissector_handle_t nvmet_tcp_handle;
#define NVME_TCP_PORT_RANGE    "4420" /* IANA registered */

#define NVME_FABRICS_TCP "NVMe/TCP"
#define NVME_TCP_HEADER_SIZE 8
#define NVME_TCP_DATA_PDU_SIZE 24

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


static int hf_nvme_tcp_r2t_pdu = -1;
static int hf_nvme_tcp_r2t_offset = -1;
static int hf_nvme_tcp_r2t_length = -1;
static int hf_nvme_tcp_r2t_resvd = -1;


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

/* tracking Cmd and its respective CQE */
static int hf_nvme_fabrics_cmd_pkt = -1;
static int hf_nvme_fabrics_cqe_pkt = -1;
static int hf_nvme_fabrics_cmd_latency = -1;
static int hf_nvme_fabrics_cmd_qid = -1;


/* NVMe Fabric CQE */
static int hf_nvme_fabrics_cqe = -1;
static int hf_nvme_fabrics_cqe_sts = -1;
static int hf_nvme_fabrics_cqe_sqhd = -1;
static int hf_nvme_fabrics_cqe_rsvd = -1;
//static int hf_nvme_fabrics_cqe_cid = -1;
static int hf_nvme_fabrics_cqe_status = -1;
static int hf_nvme_fabrics_cqe_status_rsvd = -1;

static int hf_nvme_fabrics_cqe_connect_cntlid = -1;
static int hf_nvme_fabrics_cqe_connect_authreq = -1;
static int hf_nvme_fabrics_cqe_connect_rsvd = -1;
static int hf_nvme_fabrics_cqe_prop_set_rsvd = -1;
static int hf_nvme_tcp_to_host_unknown_data = -1;

/* Data response fields */
static int hf_nvme_tcp_data_pdu = -1;
static int hf_nvme_tcp_pdu_ttag = -1;
static int hf_nvme_tcp_data_pdu_data_offset = -1;
static int hf_nvme_tcp_data_pdu_data_length = -1;
static int hf_nvme_tcp_data_pdu_data_resvd = -1;
static int hf_nvme_gen_data = -1;

static gint ett_nvme_tcp = -1;
static gint ett_nvme_tcp_icqreq = -1;
static gint ett_nvme_tcp_icqresp = -1;
static gint ett_nvme_fabrics = -1;
static gint ett_nvme_fabrics_data = -1;
static gint ett_nvme_data = -1;
static range_t *gPORT_RANGE;


/* dissector helper: length of PDU */
#include <stdio.h>
#define PDU_LEN_OFFSET_FROM_HEADER 4
static guint
get_nvme_tcp_pdu_len(packet_info *pinfo __attribute__((unused)), tvbuff_t *tvb, int offset, void* data __attribute__((unused)))
{
	return tvb_get_letohl(tvb, offset + PDU_LEN_OFFSET_FROM_HEADER);
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
}


static void
nvme_tcp_dissect_icresp(tvbuff_t *tvb, packet_info *pinfo __attribute__((unused)), int offset,
		        proto_tree *tree, struct nvme_tcp_q_ctx *queue __attribute__((unused))) {

	proto_item *tf;
	proto_item *icresp_tree;

	tf = proto_tree_add_item(tree, hf_nvme_tcp_icresp, tvb, offset, -1, ENC_NA);
	icresp_tree = proto_item_add_subtree(tf, ett_nvme_tcp_icqresp);

	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_pfv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_cpda, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_digest, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_maxdata, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
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
    proto_item *ti, *opc_item;
    guint8 fctype;

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

   /* wireshark will dissect same packet multiple times
    * when display is refreshed*/
   if (!PINFO_FD_VISITED(pinfo)) {
	   ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
	   nvme_add_cmd_to_pending_list(pinfo, q_ctx,
	                                   &ctx->n_cmd_ctx, (void*)ctx, cmd_id);
   } else {
	   /* Already visited this frame */
	   ctx = (struct nvme_tcp_cmd_ctx*)
		     nvme_lookup_cmd_in_done_list(pinfo, q_ctx, cmd_id);
	   /* if we have already visited frame but haven't found completion yet,
	    * we won't find cmd in done q, so allocate a dummy ctx for doing
	    * rest of the processing.
	    */
	   if (!ctx)
	       ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
   }

   return ctx;
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
		guint8 fctype;

		cmd_ctx->n_cmd_ctx.fabric = TRUE;
		fctype = tvb_get_guint8(tvb, offset + 4);
		dissect_nvme_fabric_cmd(tvb, tree, queue, cmd_ctx, offset);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Fabrics %s Request",
				val_to_str(fctype, nvme_fabrics_cmd_type_vals, "Unknown FcType"));
		if (incapsuled_data_size > 0) {
			dissect_nvme_fabric_data(tvb, tree, incapsuled_data_size, cmd_ctx->fctype, offset + NVME_FABRIC_CMD_SIZE);
		}
	} else {
		tvbuff_t *nvme_tvbuff;
		cmd_ctx->n_cmd_ctx.fabric = FALSE;
		/* get incapsuled nvme command */
		nvme_tvbuff = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
		col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe %s", nvme_get_opcode_string(opcode, queue->n_q_ctx.qid));
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
			packet_info *pinfo,
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

	col_add_fstr(pinfo->cinfo, COL_INFO, "Fabrics %s Response",
			val_to_str(cmd_ctx->fctype, nvme_fabrics_cmd_type_vals, "Unknown FcType"));

	cqe_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

	nvme_publish_cqe_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_fabrics_cmd_pkt,
				 &cmd_ctx->n_cmd_ctx);
	nvme_publish_cmd_latency(cqe_tree, &cmd_ctx->n_cmd_ctx, hf_nvme_fabrics_cmd_latency);

	dissect_nvme_fabrics_cqe_status_8B(cqe_tree, nvme_tvb, cmd_ctx, offset);

	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_sqhd, nvme_tvb,
			offset + 8, 2, ENC_NA);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_rsvd, nvme_tvb,
			offset + 10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cmd_cid, nvme_tvb,
			offset + 12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_status, nvme_tvb,
			offset + 14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_status_rsvd, nvme_tvb,
			offset + 14, 2, ENC_LITTLE_ENDIAN);
}

static guint32
dissect_nvme_tcp_data_pdu(tvbuff_t *tvb, packet_info *pinfo, int offset,
		  	  proto_tree *tree)
{
	guint32 data_length;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
	proto_tree_add_item(tree, hf_nvme_fabrics_cmd_cid, tvb,
			    offset, 2, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree, hf_nvme_tcp_pdu_ttag, tvb,
			    offset + 2, 2, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree, hf_nvme_tcp_data_pdu_data_offset, tvb,
			    offset + 4, 4, ENC_LITTLE_ENDIAN);

	data_length = tvb_get_guint32(tvb, offset + 8, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_nvme_tcp_data_pdu_data_length, tvb,
			    offset + 8, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree, hf_nvme_tcp_data_pdu_data_resvd, tvb,
			    offset + 12, 4, ENC_NA);

	return data_length;
}

static void
dissect_nvme_tcp_c2h_data(tvbuff_t *tvb, packet_info *pinfo, int offset,
			  proto_tree *tree, struct nvme_tcp_q_ctx *queue,
			  struct tcpinfo *tcpinfo)
{
	struct nvme_tcp_cmd_ctx *cmd_ctx;
	guint32 cmd_id;
	guint32 data_length;
	tvbuff_t *nvme_data;
	guint32 data_key;
	//wmem_tree_key_t key[2];

	printf("%s:%d frame %u \n", __func__, __LINE__, pinfo->num);
	cmd_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	data_length = dissect_nvme_tcp_data_pdu(tvb, pinfo, offset, tree);

	/* This can identify our packet uniquely  */
	data_key = tcpinfo->seq + offset;
	if (!PINFO_FD_VISITED(pinfo)) {
		cmd_ctx = (struct nvme_tcp_cmd_ctx*)
			     nvme_lookup_cmd_in_pending_list(&queue->n_q_ctx, cmd_id);
		if (!cmd_ctx) {
			goto not_found;
		}

		/* In order to later lookup for command context lets add this command
		 * to data responses */
		cmd_ctx->n_cmd_ctx.data_resp_pkt_num = pinfo->num;
		nvme_add_data_response(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx,
					data_key);
	} else {
		cmd_ctx = (struct nvme_tcp_cmd_ctx*)
		            nvme_lookup_data_response(pinfo, &queue->n_q_ctx, data_key);
		if (!cmd_ctx) {
			printf("%s:%d frame %u not found visited %d cmd id %x \n", __func__, __LINE__, pinfo->num, PINFO_FD_VISITED(pinfo), cmd_id);
			goto not_found;
		}
	}



	//nvme_publish_cqe_to_cmd_link(tree, tvb, hf_nvme_fabrics_cmd_pkt,
	//				 &cmd_ctx->n_cmd_ctx);
	/* get incapsuled nvme data */
	nvme_data = tvb_new_subset_remaining(tvb, NVME_TCP_DATA_PDU_SIZE);

	printf("%s:%d frame %u cmd ctx %p opcode %d cmd id %x \n", __func__, __LINE__, pinfo->num, &cmd_ctx->n_cmd_ctx, cmd_ctx->n_cmd_ctx.opcode, cmd_id);
	dissect_nvme_data_response(nvme_data, pinfo, tree, &queue->n_q_ctx,
				   &cmd_ctx->n_cmd_ctx, data_length);

	// FIXME: we need to link this to request ????

	return;
not_found:
	// What is the size of data ???
	proto_tree_add_item(tree, hf_nvme_tcp_to_host_unknown_data, tvb,
			    offset + 16, data_length, ENC_NA);
}

static void
dissect_nvme_tcp_h2c_data(tvbuff_t *tvb, packet_info *pinfo, int offset,
			  proto_tree *tree, struct nvme_tcp_q_ctx *queue  __attribute__((unused)),
			  struct tcpinfo *tcpinfo)
{
	struct nvme_tcp_cmd_ctx *cmd_ctx;
	guint16 cmd_id;
	guint32 data_length;
	guint32 data_key;
	tvbuff_t *nvme_data;

	cmd_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	data_length = dissect_nvme_tcp_data_pdu(tvb, pinfo, offset, tree);

	/* This can identify our packet uniquely  */
	data_key = tcpinfo->seq + offset;
	if (!PINFO_FD_VISITED(pinfo)) {
		cmd_ctx = (struct nvme_tcp_cmd_ctx*)
			     nvme_lookup_cmd_in_pending_list(&queue->n_q_ctx, cmd_id);
		printf("%s:%d frame %u cmd id  %x cmd %p \n", __func__, __LINE__, pinfo->num, cmd_id, cmd_ctx);
		if (!cmd_ctx) {
			printf("%s:%d NOT FOUND !!!! frame %u cmd id  %x cmd %p \n", __func__, __LINE__, pinfo->num, cmd_id, cmd_ctx);
			goto not_found;
		}

		/* Fill this for "adding data request call, this will be the key to fetch data request later */
		cmd_ctx->n_cmd_ctx.remote_key = data_key;
		nvme_add_data_request(pinfo, &queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, (void*)cmd_ctx);
	} else {
		cmd_ctx = (struct nvme_tcp_cmd_ctx*)
				nvme_lookup_data_request(&queue->n_q_ctx, data_key);
		if (!cmd_ctx) {
			printf("%s:%d frame %u not found visited %d cmd id %x \n", __func__, __LINE__, pinfo->num, PINFO_FD_VISITED(pinfo), cmd_id);
			goto not_found;
		}
	}

	nvme_data = tvb_new_subset_remaining(tvb, NVME_TCP_DATA_PDU_SIZE);
	printf("%s:%d frame %u cmd ctx %p opcode %d cmd id %x \n", __func__, __LINE__, pinfo->num, &cmd_ctx->n_cmd_ctx, cmd_ctx->n_cmd_ctx.opcode, cmd_id);
	dissect_nvme_data_response(nvme_data, pinfo, tree, &queue->n_q_ctx,
					   &cmd_ctx->n_cmd_ctx, data_length);
	return;
not_found:
	proto_tree_add_item(tree, hf_nvme_tcp_to_host_unknown_data, tvb,
			    offset + 16, data_length, ENC_NA);

}

static void
dissect_nvme_tcp_cqe(tvbuff_t *tvb, packet_info *pinfo, int offset,
		          proto_tree *tree, struct nvme_tcp_q_ctx *queue)
{
	struct nvme_tcp_cmd_ctx *cmd_ctx;
	guint16 cmd_id;

	cmd_id = tvb_get_guint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);
	//printf("Frame %d: %s:%d cmd id %x\n", pinfo->num, __func__, __LINE__, cmd_id);

	/* wireshark will dissect packet several times when display is refreshed
	 * we need to track state changes only once */
	if (!PINFO_FD_VISITED(pinfo)) {
		cmd_ctx = (struct nvme_tcp_cmd_ctx*)
			             nvme_lookup_cmd_in_pending_list(&queue->n_q_ctx, cmd_id);
		if (!cmd_ctx) {
			printf("SASHA !!!!\n");
			goto not_found;
		}
		/* we have already seen this cqe, or an identical one */
		if (cmd_ctx->n_cmd_ctx.cqe_pkt_num) {
		    printf("ALREADY SEEN??? Frame %d: %s:%d cmd id %x\n", pinfo->num, __func__, __LINE__, cmd_id);
		    goto not_found;
		}
		cmd_ctx->n_cmd_ctx.cqe_pkt_num = pinfo->num;
		printf("%s:%d frame %u move cmd %p cmd_id %x to done list\n", __func__, __LINE__, pinfo->num, &cmd_ctx->n_cmd_ctx, cmd_id);
		nvme_add_cmd_cqe_to_done_list(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id);

	} else {
		cmd_ctx = (struct nvme_tcp_cmd_ctx*)
				nvme_lookup_cmd_in_done_list(pinfo, &queue->n_q_ctx, cmd_id);
		if (!cmd_ctx) {
			printf("!!!! ERROR NOT IN DONE LIST \n");
			goto not_found;
		}
	}

	nvme_update_cmd_end_info(pinfo, &cmd_ctx->n_cmd_ctx);

	//printf("%s:%d frame %d fabrics %d ?\n", __func__, __LINE__, pinfo->num, cmd_ctx->n_cmd_ctx.fabric);
	if (cmd_ctx->n_cmd_ctx.fabric) {
		dissect_nvme_fabric_cqe(tvb, pinfo, tree, cmd_ctx, offset);
	} else {
		tvbuff_t *nvme_tvb;
		/* get incapsuled nvme command */
		nvme_tvb = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "NVMe %s: Response",
				nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode, queue->n_q_ctx.qid));
		/* In order to search according to nvme-tcp.cmd.cid lets add command
		* id also in nvme-tcp tree*/
		proto_tree_add_item(tree, hf_nvme_fabrics_cmd_cid, nvme_tvb,
				    12, 2, ENC_LITTLE_ENDIAN);

		dissect_nvme_cqe(nvme_tvb, pinfo, tree, &cmd_ctx->n_cmd_ctx);
	}
	return;
not_found:
	printf("!!!! CQE NOT FOUND !!! for cmd %x\n", cmd_id);
	proto_tree_add_item(tree, hf_nvme_tcp_to_host_unknown_data, tvb,
			    offset, NVME_FABRIC_CQE_SIZE, ENC_NA);
}

static void
nvme_tcp_dissect_r2t(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree)
{
	proto_item *tf;
	proto_item *r2t_tree;

	tf = proto_tree_add_item(tree, hf_nvme_tcp_r2t_pdu, tvb, offset, -1, ENC_NA);
	r2t_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

	col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "Ready To Transfer");
	//proto_tree_add_item(r2t_tree, hf_nvme_tcp_icreq_pfv, tvb, offset, 2, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(r2t_tree, hf_nvme_fabrics_cmd_cid, tvb,
			    offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(r2t_tree, hf_nvme_tcp_pdu_ttag, tvb,
				offset + 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(r2t_tree, hf_nvme_tcp_r2t_offset, tvb,
				offset + 4, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(r2t_tree, hf_nvme_tcp_r2t_length, tvb,
				offset + 8, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(r2t_tree, hf_nvme_tcp_r2t_resvd, tvb,
				offset + 12, 4, ENC_NA);
}


static int
dissect_nvme_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo __attribute__((unused)), proto_tree *tree __attribute__((unused)), void* data _U_ __attribute__((unused))) {
	struct tcpinfo *tcpinfo = (struct tcpinfo *)data;
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
	printf("frame %u Plen %u hlen %u capsule len %u packet type %u\n", pinfo->num, plen, hlen, incapsuled_data_size, packet_type);

	switch (packet_type) {
	case nvme_tcp_icreq:
		col_set_str(pinfo->cinfo, COL_INFO,  "Initialize Connection Request");
		nvme_tcp_dissect_icreq(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx);
		break;
	case nvme_tcp_icresp:
		col_set_str(pinfo->cinfo, COL_INFO, "Initialize Connection Response");
		nvme_tcp_dissect_icresp(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx);
		break;
	case nvme_tcp_cmd:
		//col_set_str(pinfo->cinfo, COL_INFO, "");
		dissect_nvme_tcp_command(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx, incapsuled_data_size);
		break;
	case nvme_tcp_rsp:
		dissect_nvme_tcp_cqe(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx);
		break;
	case nvme_tcp_c2h_data:
		dissect_nvme_tcp_c2h_data(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx, tcpinfo);
		break;
	case nvme_tcp_h2c_data:
		dissect_nvme_tcp_h2c_data(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree, q_ctx, tcpinfo);
		break;
	case nvme_tcp_r2t:
		nvme_tcp_dissect_r2t(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree);
		break;
	case nvme_tcp_h2c_term:
	case nvme_tcp_c2h_term:
	default:
		printf("Error in parsing... unkown packet type %u\n", packet_type);
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
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, NVME_TCP_HEADER_SIZE,
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
			{ "ICReq", "nvme-tcp.icreq",
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
				{ "ICResp", "nvme-tcp.icresp",
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
	    { "NVMe Cmd", "nvme-tcp.cmd",
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
	               { "Command ID", "nvme.cmd.cid",
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

	  /* NVMe command data */
	  { &hf_nvme_fabrics_cmd_data,
	      { "Data", "nvme-tcp.cmd.data",
		 FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  { &hf_nvme_fabrics_cmd_connect_data_hostid,
	      { "Host Identifier", "nvme-tcp.cmd.connect.data.hostid",
		 FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL}
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

        /* NVMe Response fields */
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
	/* NVMe TCP data response */
	{ &hf_nvme_tcp_data_pdu,
	            { "Cqe", "nvme-tcp.data",
	               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	},
	{ &hf_nvme_tcp_pdu_ttag,
		    { "Transfer Tag", "nvme-tcp.ttag",
		FT_UINT16, BASE_HEX, NULL, 0x0, "Transfer tag (controller generated)", HFILL}
	},
	{ &hf_nvme_tcp_data_pdu_data_offset,
		{ "Data Offset", "nvme-tcp.data.offset",
		FT_UINT32, BASE_DEC, NULL, 0x0, "Offset from the start of the command data", HFILL}
	},
	{ &hf_nvme_tcp_data_pdu_data_length,
		{ "Data Length", "nvme-tcp.data.length",
		FT_UINT32, BASE_DEC, NULL, 0x0, "Length of the data stream", HFILL}
	},
	{ &hf_nvme_tcp_data_pdu_data_resvd,
		{ "Reserved", "nvme-tcp.data.rsvd",
		FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	},
	{ &hf_nvme_gen_data,
	            { "Nvme Data", "nvme.data",
	              FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	},
	/* NVMEe TCP R2T pdu */
	{ &hf_nvme_tcp_r2t_pdu,
		            { "R2T", "nvme-tcp.r2t",
		               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	},
	{ &hf_nvme_tcp_r2t_offset,
		{ "R2T Offset", "nvme-tcp.r2t.offset",
		FT_UINT32, BASE_DEC, NULL, 0x0, "offset from the start of the command data", HFILL}
	},
	{ &hf_nvme_tcp_r2t_length,
		{ "R2T Length", "nvme-tcp.r2t.length",
		FT_UINT32, BASE_DEC, NULL, 0x0, "Length of the data stream", HFILL}
	},
	{ &hf_nvme_tcp_r2t_resvd,
		{ "Reserved", "nvme-tcp.r2t.rsvd",
		FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
	},
    };
    static gint *ett[] = {
        &ett_nvme_tcp,
	&ett_nvme_tcp_icqreq,
	&ett_nvme_tcp_icqresp,
	&ett_nvme_fabrics,
	&ett_nvme_fabrics_data,
	&ett_nvme_data
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
     //printf("we are here %s:%d\n", __FILE__,__LINE__);
}

void
proto_reg_handoff_nvme_tcp(void)
{
//    heur_dissector_add("tcp", dissect_nvme_tcp,
//                       "NVMe Fabrics TCP packets",
//                       "nvme_tcp", proto_nvme_tcp, HEURISTIC_ENABLE);
      //printf("we are here %s:%d\n", __FILE__,__LINE__);
      //tcp_handler = find_dissector_add_dependency("tcp", proto_nvme_tcp);
      //proto_tcp = dissector_handle_get_protocol_index(tcp_handler);
      dissector_add_uint_with_preference("tcp.port", 4420, nvmet_tcp_handle);

}
