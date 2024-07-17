import socket
import sys
### HOW TO RUN ###
# $SDE/run_bfshell.sh -b `pwd`/setup.py -i
###

# mirroring forward interfaces
INFO_DEV_PORT_PATRONUS_ENS1F1 = 64

MIRROR_SESSION_RDMA_SNIFF_IG = 777 # mirroring's session id for sniffing RDMA packets for IG_MIRROR 
MIRROR_SESSION_RDMA_SNIFF_EG = 888 # mirroring's session id for sniffing RDMA packets for EG_MIRROR

# config_pktgen_script='..../config_pktgen.py'
devtest_cmds_file = "/home/user/Desktop/P4/conweave-p4/native_dcqcn/cp/devtest_cmds.py"

hostname = socket.gethostname()
print("Hostname: {}".format(hostname))
hostname = 'tofino1b'   # NOTICE!
l2_forward = bfrt.rdma_mirroring.pipe.SwitchIngress.l2_forward


if hostname == 'tofino1b':
    # Add entries to the l2_forward table
    l2_forward.add_with_forward(dst_addr=0x123456789012, switch_id=0, port=1) # just for test
    bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION_RDMA_SNIFF_IG, direction='INGRESS', session_enable=True, ucast_egress_port=INFO_DEV_PORT_PATRONUS_ENS1F1, ucast_egress_port_valid=1, max_pkt_len=16384)

else:
    print("This setup script is for tofino1b/1c. But you are running on {}".format(hostname))
    sys.exit(1)



