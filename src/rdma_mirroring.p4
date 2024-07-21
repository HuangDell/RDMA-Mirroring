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

	// store the timestamp of the previous pkg
	Register <timestamp_tail_t,_>(1,32w0) last_timestamp_tail_reg;  // default = 0
	Register <timestamp_head_t,_>(1,16w0) last_timestamp_head_reg;  // default = 0

	// Register <timestamp_t,_>(1,48w0) last_timestamp_reg;  // default = 0

	RegisterAction<timestamp_tail_t,_,timestamp_tail_t> (last_timestamp_tail_reg) 
	read_and_set_timestemp_tail={
		void apply(inout timestamp_tail_t data,out timestamp_tail_t last_timestamp_tail){
			last_timestamp_tail=data;
			data=ig_intr_md.ingress_mac_tstamp[31:0];
		}
	};

	RegisterAction<timestamp_head_t,_,timestamp_head_t> (last_timestamp_head_reg) 
	read_and_set_timestemp_head={
		void apply(inout timestamp_head_t data,out timestamp_head_t last_timestamp_head){
			last_timestamp_head=data;
			data=ig_intr_md.ingress_mac_tstamp[47:32];
		}
	};



	// flag for the first reg
	Register <flag_t,_>(1,8w1) first_pkg_flag_reg;  // default = 1

	RegisterAction<flag_t,_,flag_t>(first_pkg_flag_reg)
	read_and_set_flag={
		void apply(inout flag_t data,out flag_t flag){
			flag=data;
			data=8w0;
		}
	};

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



    // /* Mirroring packets to Sniff Port */
    // action mirror_to_collector(bit<10> ing_mir_ses){
    // }

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
			bit<1> index=0;  // flag reg and timestamp just have one item, so index is 0
			meta.ts.first_pkg_flag=read_and_set_flag.execute(index);

			timestamp_t last_timestamp;
			timestamp_head_t last_timestamp_head;
			timestamp_tail_t last_timestamp_tail;

			last_timestamp_head=read_and_set_timestemp_head.execute(index);
			last_timestamp_tail=read_and_set_timestemp_tail.execute(index);

			ig_intr_md_for_dprsr.mirror_type = IG_MIRROR_TYPE_1;
			meta.mirror_session = MIRROR_SESSION_RDMA_ID_IG;
			meta.ts.last_timestamp=last_timestamp_head++last_timestamp_tail;
			meta.ig_mirror1.ingress_mac_timestamp = ig_intr_md.ingress_mac_tstamp;
			meta.ig_mirror1.opcode = hdr.bth.opcode;
			meta.ig_mirror1.mirrored = (bit<8>)IG_MIRROR_TYPE_1;
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
		if (meta.ig_mirror1.mirrored == (bit<8>)IG_MIRROR_TYPE_1) {  // if is a mirroring pkg , do this

			// cal diff timestamp
			if(meta.ts.first_pkg_flag==8w0){
				// alg_t ingress_mac_tstamp_temp=(bit<64>)meta.ig_mirror1.ingress_mac_timestamp;
				// ingress_mac_tstamp_temp=(bit<64>)meta.ig_mirror1.ingress_mac_timestamp;

				meta.ts.timestamp_diff= meta.ig_mirror1.ingress_mac_timestamp - meta.ts.last_timestamp;
			}
			/* Timestamp -> MAC Src Address*/
			hdr.ethernet.src_addr = meta.ig_mirror1.ingress_mac_timestamp; // 48 bits
			/* time diff -> MAC Dst Address */
			hdr.ethernet.dst_addr = (bit<48>)meta.ts.timestamp_diff;
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