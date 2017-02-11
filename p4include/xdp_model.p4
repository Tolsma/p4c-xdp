/*
Copyright 2017 VMWare, Inc.

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

/*

This file describes a P4 architectural model called XDP.  This model
generates EBPF code that is run under the XDP (eXpress Data Path):
https://www.iovisor.org/technology/xdp.  We support two different architectures:

- a packet filter, which is identical to the ebpfFilter architecture
- a switch, which has a parser, control pipline and deparser

*/

#ifndef _XDP_MODEL_P4
#define _XDP_MODEL_P4

#include <core.p4>
#include <ebpf_model.p4>  // we continue to support the EBPF packet filter model

/* architectural model for a packet switch architecture */
struct xdp_input {
    bit<32> input_port;
}

struct xdp_output {
    bool    drop;  // if set packet is dropped
    bit<32> output_port;  // output port for packet
}

parser xdp_parse<H>(packet_in packet, out H headers);
control xdp_switch<H>(inout H headers, in xdp_input imd, out xdp_output omd);
control xdp_deparse<H>(in H headers, packet_out packet);

package xdp<H>(xdp_parse<H> p, xdp_switch<H> s, xdp_deparse<H> d);

#endif  /* _XDP_MODEL_P4 */