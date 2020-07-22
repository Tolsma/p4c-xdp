/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "backends/ebpf/ebpfType.h"
#include "backends/ebpf/ebpfControl.h"
#include "backends/ebpf/ebpfParser.h"
#include "backends/ebpf/ebpfTable.h"
#include "frontends/p4/coreLibrary.h"
#include "xdpProgram.h"
#include "xdpControl.h"

namespace XDP {

bool XDPProgram::build() {
    auto pack = toplevel->getMain();
    unsigned paramCount = pack->getConstructorParameters()->size();

    cstring parserParamName;
    if (paramCount == 2) {
        parserParamName = model.filter.parser.name;
    } else if (paramCount == 3) {
        parserParamName = xdp_model.xdp.parser.name;
    } else {
        ::error("%1%: Expected 2 or 3 package parameters", pack);
    }

    auto pb = pack->getParameterValue(parserParamName)
            ->to<IR::ParserBlock>();
    BUG_CHECK(pb != nullptr, "No parser block found");
    parser = new EBPF::EBPFParser(this, pb, typeMap);
    bool success = parser->build();
    if (!success)
        return success;

    if (paramCount == 2) {
        cstring controlParamName = model.filter.filter.name;
        auto cb = pack->getParameterValue(controlParamName)
                ->to<IR::ControlBlock>();
        BUG_CHECK(cb != nullptr, "No control block found");
        control = new EBPF::EBPFControl(this, cb, parser->headers);
        success = control->build();
        if (!success)
            return success;
    } else {
        cstring controlParamName = xdp_model.xdp.swtch.name;
        auto cb = pack->getParameterValue(controlParamName)
                ->to<IR::ControlBlock>();
        BUG_CHECK(cb != nullptr, "No control block found");
        control = new XDPSwitch(this, cb, parser->headers);
        success = control->build();
        if (!success)
            return success;
    }

    if (paramCount == 3) {
        auto db = pack->getParameterValue(xdp_model.xdp.deparser.name)
                ->to<IR::ControlBlock>();
        BUG_CHECK(db != nullptr, "No deparser block found");
        deparser = new XDPDeparser(this, db, parser->headers);
        success = deparser->build();
        if (!success)
            return success;
    }

    return true;
}

void XDPProgram::emitTypes(EBPF::CodeBuilder* builder) {
    for (auto d : program->objects) {
        if (!d->is<IR::Type>()) continue;

        if (d->is<IR::IContainer>() || d->is<IR::Type_Extern>() ||
            d->is<IR::Type_Parser>() || d->is<IR::Type_Control>() ||
            d->is<IR::Type_Typedef>() || d->is<IR::Type_Error>())
            continue;

        if (d->is<IR::Type_Enum>()) {
            if (d->to<IR::Type_Enum>()->name == XDPModel::instance.action_enum.name)
                continue;
        }

        auto type = EBPF::EBPFTypeFactory::instance->create(d->to<IR::Type>());
        if (type == nullptr)
            continue;
        type->emit(builder);
        builder->newline();
    }
}

void XDPProgram::emitC(EBPF::CodeBuilder* builder, cstring headerFile) {
    emitGeneratedComment(builder);

    if (!switchTarget()) {
        EBPF::EBPFProgram::emitC(builder, headerFile);
        return;
    }

    if (builder->target->name != "XDP") {
        ::error("This program must be compiled with --target xdp");
        return;
    }

    builder->appendFormat("#include \"%s\"", headerFile);
    builder->newline();
    builder->target->emitIncludes(builder);
    emitPreamble(builder);
    control->emitTableInstances(builder);

    builder->appendLine(
        "inline u16 ebpf_ipv4_checksum(u8 version, u8 ihl, u8 diffserv,\n"
        "                  u16 totalLen, u16 identification, u8 flags,\n"
        "                  u16 fragOffset, u8 ttl, u8 protocol,\n"
        "                  u32 srcAddr, u32 dstAddr) {\n"
        "    u32 checksum = __bpf_htons(((u16)version << 12) | ((u16)ihl << 8) | (u16)diffserv);\n"
        "    checksum += __bpf_htons(totalLen);\n"
        "    checksum += __bpf_htons(identification);\n"
        "    checksum += __bpf_htons(((u16)flags << 13) | fragOffset);\n"
        "    checksum += __bpf_htons(((u16)ttl << 8) | (u16)protocol);\n"
        "    srcAddr = __bpf_ntohl(srcAddr);\n"
        "    dstAddr = __bpf_ntohl(dstAddr);\n"
        "    checksum += (srcAddr >> 16) + (u16)srcAddr;\n"
        "    checksum += (dstAddr >> 16) + (u16)dstAddr;\n"
        "    // Fields in 'struct Headers' are host byte order.\n"
        "    // Deparser converts to network byte-order\n"
        "    return bpf_ntohs(~((checksum & 0xFFFF) + (checksum >> 16)));\n"
        "}");

    builder->appendLine(
                "inline u16 csum16_add(u16 csum, u16 addend) {\n"
                "    u16 res = csum;\n"
                "    res += addend;\n"
                "    return (res + (res < addend));\n"
                "}\n"
                "inline u16 csum16_sub(u16 csum, u16 addend) {\n"
                "    return csum16_add(csum, ~addend);\n"
                "}\n"
                "inline u16 csum_replace2(u16 csum, u16 old, u16 new) {\n"
                "    return (~csum16_add(csum16_sub(~csum, old), new));\n"
        "}\n");

    builder->appendLine(
        "inline u16 csum_fold(u32 csum) {\n"
        "    u32 r = csum << 16 | csum >> 16;\n"
        "    csum = ~csum;\n"
        "    csum -= r;\n"
        "    return (u16)(csum >> 16);\n"
        "}\n"
        "inline u32 csum_unfold(u16 csum) {\n"
        "    return (u32)csum;\n"
        "}\n"
                "inline u32 csum32_add(u32 csum, u32 addend) {\n"
                "    u32 res = csum;\n"
                "    res += addend;\n"
                "    return (res + (res < addend));\n"
                "}\n"
                "inline u32 csum32_sub(u32 csum, u32 addend) {\n"
                "    return csum32_add(csum, ~addend);\n"
                "}\n"
                "inline u16 csum_replace4(u16 csum, u32 from, u32 to) {\n"
        "    u32 tmp = csum32_sub(~csum_unfold(csum), from);\n"
                "    return csum_fold(csum32_add(tmp, to));\n"
        "}\n");

    builder->appendLine(
        "#define BPF_KTIME_GET_NS() ({\\\n"
        "   u32 ___ts = (u32)bpf_ktime_get_ns(); ___ts; })\\\n");

    builder->appendLine(
        "enum PortType {\n"
        "    PORT_DROP,\n"
        "    PORT_DEV,\n"
        "    PORT_XSK,\n"
        "    PORT_PASS,\n"
        "};\n"
        "\n"
        "struct dqIdx {\n"
        "    u32 ifindex;\n"
        "    u32 queue;\n"
        "};\n"
        "\n"
        "struct portmap {\n"
        "    u32 type;\n"
        "    u32 index;\n"
        "    u32 ifindex;\n"
        "};\n"
        "\n"
        "struct bpf_map_def SEC(\"maps\") dq_table = {\n"
        "    .type = BPF_MAP_TYPE_HASH,\n"
        "    .key_size = sizeof(struct dqIdx),\n"
        "    .value_size = sizeof(u32),\n"
        "    .max_entries = 256*8 /* At this moment maximum of 256 devs with 8 queues on p4vswitch*/\n"
        "};\n"
        "\n"
        "struct bpf_map_def SEC(\"maps\") port_table = {\n"
        "    .type = BPF_MAP_TYPE_ARRAY,\n"
        "    .key_size = sizeof(u32),\n"
        "    .value_size = sizeof(struct portmap),\n"
        "    .max_entries = 256 /* At this moment maximum of 256 ports on p4vswitch*/\n"
        "};\n"
        "\n"
        "struct bpf_map_def SEC(\"maps\") dev_table = {\n"
        "    .type = BPF_MAP_TYPE_DEVMAP,\n"
        "    .key_size = sizeof(int),\n"
        "    .value_size = sizeof(int),\n"
        "    .max_entries = 256 /* At this moment maximum of 256 ports on p4vswitch*/\n"
        "};\n"
        "\n"
        "struct bpf_map_def SEC(\"maps\") xsk_table = {\n"
        "    .type = BPF_MAP_TYPE_XSKMAP,\n"
        "    .key_size = sizeof(int),\n"
        "    .value_size = sizeof(int),\n"
        "    .max_entries = 256 /* At this moment maximum of 256 ports on p4vswitch*/\n"
        "};\n");

    builder->newline();
    builder->emitIndent();

// replace emitCodeSection with own line because p4c-ebpf doesnt use functionName but emits always "prog"
// and libbpf doesn't like this....
// see also: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/libbpf.c #6617
//
//    builder->target->emitCodeSection(builder, functionName);
    builder->appendFormat("SEC(\"%s\")\n", "xdp");

    builder->emitIndent();
    builder->target->emitMain(builder, "p4vswitch_prog", model.CPacketName.str());
    builder->blockStart();

    emitHeaderInstances(builder);
    builder->append(" = ");
    parser->headerType->emitInitializer(builder);
    builder->endOfStatement(true);

    emitLocalVariables(builder);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::start.c_str());
    builder->newline();

    parser->emit(builder);
    emitPipeline(builder);

    builder->emitIndent();
    builder->append(endLabel);
    builder->appendLine(":");

    builder->appendLine(
        "    {\n"
        "        /* Get output port information */\n"
        "        struct portmap *rec = bpf_map_lookup_elem(&port_table, &xout.output_port);\n"
        "        if (!rec) return XDP_ABORTED; /* Satisfy verifier: If not found return abort! */\n"
        "\n"
        "        /*  PORT_DEV and same out ifIndex as in ifIndex then XDP_TX: */\n"
        "        if (rec->type == PORT_DEV && rec->ifindex == xin.input_ifindex) return XDP_TX;\n"
        "\n"
        "        /*  PORT_DEV: */\n"
        "        if (rec->type == PORT_DEV) return bpf_redirect_map(&dev_table, rec->index, 0);\n"
        "\n"
        "        /*  PORT_XSK calculate index in xsk_map: */\n"
        "        if (rec->type == PORT_XSK) {\n"
        "            int tmp_index = (rec->index*8) + xin.input_queue;\n"
        "            return bpf_redirect_map(&xsk_table, tmp_index, 0);\n"
        "        }\n"
        "\n"
        "        /*  PORT_PASS the output to input netdev kernel networking interface: */\n"
        "        /*  (this is the XDP implemention and can't be changed) */\n"
        "        if (rec->type == PORT_PASS && rec->ifindex == xin.input_ifindex) return XDP_PASS;\n"
        "\n"
        "        /* Anything else including PORT_DROP */\n"
        "        return XDP_DROP;\n"
        "    }\n");
    builder->blockEnd(true);  // end of function

    builder->target->emitLicense(builder, license);
}

void XDPProgram::emitPipeline(EBPF::CodeBuilder* builder) {
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(":");
    builder->newline();

    builder->emitIndent();
    builder->blockStart();
    control->emit(builder);
    builder->blockEnd(true);

    if (switchTarget()) {
        builder->emitIndent();
        builder->append("/* deparser */");
        builder->newline();
        builder->emitIndent();
        builder->blockStart();
        deparser->emit(builder);
        builder->blockEnd(true);
    }
}

void XDPProgram::emitLocalVariables(EBPF::CodeBuilder* builder) {
    if (!switchTarget()) {
        EBPF::EBPFProgram::emitLocalVariables(builder);
        return;
    }

    builder->emitIndent();
    builder->appendFormat("unsigned %s = 0;", offsetVar);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("enum %s %s = %s;", errorEnum, errorVar,
                          P4::P4CoreLibrary::instance.noError.str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("void* %s = %s;",
                          packetStartVar, builder->target->dataOffset(model.CPacketName.str()));
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("void* %s = %s;",
                          packetEndVar, builder->target->dataEnd(model.CPacketName.str()));
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", zeroKey);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u8 %s = 0;", byteVar);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", outHeaderLengthVar);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("struct %s %s;", xdp_model.outputMetadataModel.name,
                          getSwitch()->outputMeta->name.name);
    builder->newline();

    builder->newline();
    builder->emitIndent();
    builder->appendFormat("/* Initialize input metadata */");
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("struct %s %s;", xdp_model.inputMetadataModel.name,
                          getSwitch()->inputMeta->name.name);
    builder->newline();

    builder->appendLine(
        "    xin.input_ifindex = skb->ingress_ifindex;\n"
        "    xin.input_queue = skb->rx_queue_index;\n"
        "    xin.input_port = 0;\n"
        "\n"
        "    /* Retrieve p4vswitch input port*/\n"
        "    struct dqIdx key = {};\n"
        "    key.ifindex = xin.input_ifindex;\n"
        "    key.queue = xin.input_queue;\n"
        "    u32 *p4port = bpf_map_lookup_elem(&dq_table, &key);\n"
        "    if (!p4port) return XDP_DROP; /* Satisfy verifier */\n"
        "    xin.input_port = *p4port;");
}

XDPSwitch* XDPProgram::getSwitch() const {
    return dynamic_cast<XDPSwitch*>(control);
}

}  // namespace XDP
