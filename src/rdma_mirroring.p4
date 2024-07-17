#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/headers.p4"
#include "includes/parser.p4"

const bit<10> MIRROR_SESSION_RDMA_ID_IG = 10w777;
const bit<10> MIRROR_SESSION_RDMA_ID_EG = 10w888;

control SwitchIngress(
    inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm){

	/**
	 * @brief L2 Forwarding
	 */
	action nop(){}
	action drop(){
		ig_intr_md_for_dprsr.drop_ctl = 0b001;
	}

	action miss(bit<3> drop_bits) {
		ig_intr_md_for_dprsr.drop_ctl = drop_bits;
	}

	action forward(PortId_t port){
		ig_intr_md_for_tm.ucast_egress_port = port;
	}


	action get_seqnum_to_metadata() {
        meta.ig_mirror1.rdma_seqnum = (bit<32>)hdr.bth.packet_seqnum;
    }

    /* Mirroring packets to Sniff Port */
    action mirror_to_collector(bit<10> ing_mir_ses){
        ig_intr_md_for_dprsr.mirror_type = IG_MIRROR_TYPE_1;
        meta.mirror_session = ing_mir_ses;
		meta.ig_mirror1.ingress_mac_timestamp = ig_intr_md.ingress_mac_tstamp;
		meta.ig_mirror1.opcode = hdr.bth.opcode;
		meta.ig_mirror1.mirrored = (bit<8>)IG_MIRROR_TYPE_1;
    }

	/* What we mainly use for switching/routing */
	table l2_forward {
		key = {
			meta.port_md.switch_id: exact;
			hdr.ethernet.dst_addr: exact;
		}

		actions = {
			forward;
			@defaultonly miss;
		}

		const default_action = miss(0x1);
	}


	apply {
        l2_forward.apply(); 

        if (hdr.bth.isValid()){ // if RDMA
            mirror_to_collector(MIRROR_SESSION_RDMA_ID_IG); // ig_mirror all RDMA packets
            get_seqnum_to_metadata();
        }
	}

}  // End of SwitchIngressControl


control SwitchEgress(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){
	action nop(){}


	apply{
		if (meta.ig_mirror1.mirrored == (bit<8>)IG_MIRROR_TYPE_1) {  // if is mirroring pkg , do this
			/* Timestamp -> MAC Src Address*/
			hdr.ethernet.src_addr = meta.ig_mirror1.ingress_mac_timestamp; // 48 bits
			/* Sequence Number -> MAC Dst Address */
			hdr.ethernet.dst_addr = (bit<48>)meta.ig_mirror1.rdma_seqnum;
		}
	} 

} // End of SwitchEgress


Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()
		 ) pipe;

Switch(pipe) main;