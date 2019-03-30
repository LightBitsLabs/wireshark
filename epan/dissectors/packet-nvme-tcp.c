/* packet-nvme-tcp.c
 * Routines for NVM Express over Fabrics(TCP) dissection
 * Code by Solganik Alexander <solganik@gmail.com>
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
#define PDU_LEN_OFFSET_FROM_HEADER 4
static range_t *gPORT_RANGE;

enum nvme_tcp_pdu_type {
    nvme_tcp_icreq = 0x0,
    nvme_tcp_icresp = 0x1,
    nvme_tcp_h2c_term = 0x2,
    nvme_tcp_c2h_term = 0x3,
    nvme_tcp_cmd = 0x4,
    nvme_tcp_rsp = 0x5,
    nvme_tcp_h2c_data = 0x6,
    nvme_tcp_c2h_data = 0x7,
    nvme_tcp_r2t = 0x9,
};

static const value_string nvme_tcp_pdu_type_vals[] = {
    { nvme_tcp_icreq, "ICREQ" },
    { nvme_tcp_icresp, "ICRESP" },
    { nvme_tcp_h2c_term, "H2CTerm " },
    { nvme_tcp_c2h_term, "C2HTerm" },
    { nvme_tcp_cmd, "Command" },
    { nvme_tcp_rsp, "Response" },
    { nvme_tcp_h2c_data, "H2CData" },
    { nvme_tcp_c2h_data, "C2HData" },
    { nvme_tcp_r2t,"Ready To Transmit" },
    { 0, NULL }
};

struct nvme_tcp_q_ctx {
    struct nvme_q_ctx n_q_ctx;
};

static int hf_nvme_tcp_type = -1;
static int hf_nvme_tcp_flags = -1;
static int hf_nvme_tcp_hlen = -1;
static int hf_nvme_tcp_pdo = -1;
static int hf_nvme_tcp_plen = -1;

/* NVMe tcp icreq/icresp fields */
static int hf_nvme_tcp_icreq = -1;
static int hf_nvme_tcp_icreq_pfv = -1;
static int hf_nvme_tcp_icreq_maxr2t = -1;
static int hf_nvme_tcp_icreq_hpda = -1;
static int hf_nvme_tcp_icreq_digest = -1;
static int hf_nvme_tcp_icresp = -1;
static int hf_nvme_tcp_icresp_pfv = -1;
static int hf_nvme_tcp_icresp_cpda = -1;
static int hf_nvme_tcp_icresp_digest = -1;
static int hf_nvme_tcp_icresp_maxdata = -1;

static int hf_nvme_tcp_unknown_data = -1;

static int hf_nvme_fabrics_cmd_qid = -1;

static gint ett_nvme_tcp = -1;

static guint
get_nvme_tcp_pdu_len(packet_info *pinfo _U_,
                     tvbuff_t *tvb,
                     int offset,
                     void* data _U_)
{
    return tvb_get_letohl(tvb, offset + PDU_LEN_OFFSET_FROM_HEADER);
}

static void
dissect_nvme_tcp_icreq(tvbuff_t *tvb,
                       packet_info *pinfo,
                       int offset,
                       proto_tree *tree)
{
    proto_item *tf;
    proto_item *icreq_tree;

    col_set_str(pinfo->cinfo, COL_INFO, "Initialize Connection Request");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_icreq, tvb, offset, 8, ENC_NA);
    icreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_pfv, tvb, offset, 2,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_maxr2t, tvb, offset + 2,
            4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_hpda, tvb, offset + 6, 1,
            ENC_NA);
    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_digest, tvb, offset + 7,
            1, ENC_NA);
}

static void
dissect_nvme_tcp_icresp(tvbuff_t *tvb,
                        packet_info *pinfo,
                        int offset,
                        proto_tree *tree)
{
    proto_item *tf;
    proto_item *icresp_tree;

    col_set_str(pinfo->cinfo, COL_INFO, "Initialize Connection Response");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_icresp, tvb, offset, 8, ENC_NA);
    icresp_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_pfv, tvb, offset, 2,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_cpda, tvb, offset + 2,
            1, ENC_NA);
    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_digest, tvb, offset + 3,
            1, ENC_NA);
    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_maxdata, tvb,
            offset + 4, 4, ENC_LITTLE_ENDIAN);
}

static int
dissect_nvme_tcp_pdu(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *tree,
                     void* data _U_)
{
    conversation_t *conversation;
    struct nvme_tcp_q_ctx *q_ctx;
    proto_item *ti;
    int offset = 0;
    int nvme_tcp_pdu_offset;
    proto_tree *nvme_tcp_tree;
    guint packet_type;
    guint8 hlen;
    guint32 plen;

    conversation = find_or_create_conversation(pinfo);
    q_ctx = (struct nvme_tcp_q_ctx *)
            conversation_get_proto_data(conversation, proto_nvme_tcp);

    if (!q_ctx) {
        q_ctx = (struct nvme_tcp_q_ctx *) wmem_alloc0(wmem_file_scope(),
                sizeof(struct nvme_tcp_q_ctx));
        q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
        /* Initially set to non-0 so that by default queues are io queues
         * this is required to be able to dissect correctly even
         * if we miss connect command*/
        q_ctx->n_q_ctx.qid = G_MAXUINT16;
        conversation_add_proto_data(conversation, proto_nvme_tcp, q_ctx);
    }

    ti = proto_tree_add_item(tree, proto_nvme_tcp, tvb, 0, -1, ENC_NA);
    nvme_tcp_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

    if (q_ctx->n_q_ctx.qid != G_MAXUINT16)
        nvme_publish_qid(nvme_tcp_tree, hf_nvme_fabrics_cmd_qid,
                q_ctx->n_q_ctx.qid);

    packet_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_type, tvb, offset, 1,
            ENC_NA);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_flags, tvb, offset + 1, 1,
            ENC_NA);
    hlen = tvb_get_gint8(tvb, offset + 2);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_hlen, tvb, offset + 2, 1,
            ENC_NA);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_pdo, tvb, offset + 3, 1,
            ENC_NA);
    plen = tvb_get_letohl(tvb, offset + 4);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_plen, tvb, offset + 4, 4,
            ENC_LITTLE_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);

    nvme_tcp_pdu_offset = offset + NVME_TCP_HEADER_SIZE;

    switch (packet_type) {
    case nvme_tcp_icreq:
        dissect_nvme_tcp_icreq(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree);
        proto_item_set_len(ti, hlen);
        break;
    case nvme_tcp_icresp:
        dissect_nvme_tcp_icresp(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree);
        proto_item_set_len(ti, hlen);
        break;
    case nvme_tcp_cmd:
    case nvme_tcp_rsp:
    case nvme_tcp_c2h_data:
    case nvme_tcp_h2c_data:
    case nvme_tcp_r2t:
    case nvme_tcp_h2c_term:
    case nvme_tcp_c2h_term:
    default:
        proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_unknown_data, tvb,
                offset, plen, ENC_NA);
        break;
    }

    offset += plen;
    return tvb_reported_length(tvb);
}

static int
dissect_nvme_tcp(tvbuff_t *tvb,
                 packet_info *pinfo,
                 proto_tree *tree,
                 void *data)
{
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, NVME_TCP_HEADER_SIZE,
            get_nvme_tcp_pdu_len, dissect_nvme_tcp_pdu, data);

    return tvb_reported_length(tvb);
}

void proto_register_nvme_tcp(void) {

    static hf_register_info hf[] = {
       { &hf_nvme_tcp_type,
           { "Pdu Type", "nvme-tcp.type",
             FT_UINT8, BASE_DEC, VALS(nvme_tcp_pdu_type_vals),
             0x0, NULL, HFILL } },
       { &hf_nvme_tcp_flags,
           { "Pdu Specific Flags", "nvme-tcp.flags",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_hlen,
           { "Pdu Header Length", "nvme-tcp.hlen",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_pdo,
           { "Pdu Data Offset", "nvme-tcp.pdo",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_plen,
           { "Packet Length", "nvme-tcp.plen",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq,
           { "ICReq", "nvme-tcp.icreq",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_pfv,
           { "Pdu Version Format", "nvme-tcp.icreq.pfv",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_maxr2t,
           { "Maximum r2ts per request", "nvme-tcp.icreq.maxr2t",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_hpda,
           { "Host Pdu data alignment", "nvme-tcp.icreq.hpda",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_digest,
           { "Digest Types Enabled", "nvme-tcp.icreq.digest",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp,
           { "ICResp", "nvme-tcp.icresp",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_pfv,
           { "Pdu Version Format", "nvme-tcp.icresp.pfv",
             FT_UINT16, BASE_DEC, NULL, 0x0,
             NULL, HFILL } },
       { &hf_nvme_tcp_icresp_cpda,
           { "Controller Pdu data alignment", "nvme-tcp.icresp.cpda",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_digest,
           { "Digest types enabled", "nvme-tcp.icresp.digest",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_maxdata,
           { "Maximum data capsules per r2t supported",
                   "nvme-tcp.icresp.maxdata",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_unknown_data,
           { "Unknown Data", "nvme-tcp.unknown_data",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_qid,
           { "Cmd Qid", "nvme-tcp.cmd.qid",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             "Qid on which command is issued", HFILL } },
    };

    static gint *ett[] = {
        &ett_nvme_tcp
    };

    proto_nvme_tcp = proto_register_protocol("NVM Express Fabrics TCP",
            NVME_FABRICS_TCP, "nvme-tcp");

    proto_register_field_array(proto_nvme_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nvmet_tcp_handle = register_dissector("nvme-tcp", dissect_nvme_tcp,
            proto_nvme_tcp);
}

void proto_reg_handoff_nvme_tcp(void) {
    module_t *nvme_tcp_module;
    nvme_tcp_module = prefs_register_protocol(proto_nvme_tcp, NULL);
    range_convert_str(wmem_epan_scope(), &gPORT_RANGE, NVME_TCP_PORT_RANGE,
            MAX_TCP_PORT);
    prefs_register_range_preference(nvme_tcp_module,
                                    "subsystem_ports",
                                    "Subsystem Ports Range",
                                    "Range of NVMe Subsystem ports"
                                    "(default " NVME_TCP_PORT_RANGE ")",
                                    &gPORT_RANGE,
                                    MAX_TCP_PORT);
    dissector_add_uint_range("tcp.port", gPORT_RANGE, nvmet_tcp_handle);
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
