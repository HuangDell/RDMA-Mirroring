import socket
import sys
### HOW TO RUN ###
# $SDE/run_bfshell.sh -b `pwd`/setup.py -i
###

# mirroring forward interfaces
INFO_DEV_PORT_PATRONUS_ENS1F1 = 148

MIRROR_SESSION_RDMA_SNIFF_IG = 777 # mirroring's session id for sniffing RDMA packets for IG_MIRROR 
MIRROR_SESSION_RDMA_SNIFF_EG = 888 # mirroring's session id for sniffing RDMA packets for EG_MIRROR

# config_pktgen_script='..../config_pktgen.py'
devtest_cmds_file = "/home/user/Desktop/P4/conweave-p4/native_dcqcn/cp/devtest_cmds.py"

hostname = socket.gethostname()
print("Hostname: {}".format(hostname))
l2_forward = bfrt.rdma_mirroring.pipe.SwitchIngress.l2_forward


if hostname == 'P4-2':
    # Add entries to the l2_forward table
        # Add entries to the l2_forward table
    l2_forward.add_with_forward(dst_addr=0xe8ebd358a02c, switch_id=0, port=132) # to sender (DATA) 116
    l2_forward.add_with_forward(dst_addr=0xe8ebd358a0cc, switch_id=0, port=140) # to receiver (ACK) 114

    # XXX monitoring entry to patronus ens1f1 (dp 29/3)
    l2_forward.add_with_forward(dst_addr=0xe8ebd358a0cd, switch_id=0, port=148) #  114

    # #  Pktgen pkt's forwarding from sw2 to sw3
    # l2_forward.add_with_forward(dst_addr=RECEIVER_SW_ADDR, switch_id=2, port=172)
    bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION_RDMA_SNIFF_IG, direction='INGRESS', session_enable=True, ucast_egress_port=INFO_DEV_PORT_PATRONUS_ENS1F1, ucast_egress_port_valid=1, max_pkt_len=16384)
    bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION_RDMA_SNIFF_EG, direction='EGRESS', session_enable=True, ucast_egress_port=INFO_DEV_PORT_PATRONUS_ENS1F1, ucast_egress_port_valid=1, max_pkt_len=16384)

else:
    print("This setup script is for tofino1b/1c. But you are running on {}".format(hostname))
    sys.exit(1)



