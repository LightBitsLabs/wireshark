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
    proto_tree *nvme_tcp_tree;

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

    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_type, tvb, offset, 1,
            ENC_NA);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_flags, tvb, offset + 1, 1,
            ENC_NA);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_hlen, tvb, offset + 2, 1,
            ENC_NA);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_pdo, tvb, offset + 3, 1,
            ENC_NA);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_plen, tvb, offset + 4, 4,
            ENC_LITTLE_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);

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
