
LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
 
# Here we give our module name and source file(s)
LOCAL_MODULE    := libpcap
LOCAL_SRC_FILES :=     pcapsrc/bpf_dump.c\
		       pcapsrc/bpf/net/bpf_filter.c\
	               pcapsrc/bpf_image.c\
	               pcapsrc/etherent.c\
	               pcapsrc/fad-gifc.c\
	               pcapsrc/gencode.c\
	               pcapsrc/grammar.c\
	               pcapsrc/inet.c\
	               pcapsrc/nametoaddr.c\
	               pcapsrc/optimize.c\
	               pcapsrc/pcap.c\
	               pcapsrc/pcap-linux.c\
	               pcapsrc/savefile.c\
	               pcapsrc/scanner.c\
	               pcapsrc/version.c
	               

LOCAL_LDLIBS := -llog	               
LOCAL_CFLAGS:=-O2 -g
LOCAL_CFLAGS+=-DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -Dlinux -D__GLIBC__ -D_GNU_SOURCE
include $(BUILD_SHARED_LIBRARY)
########################################
include $(CLEAR_VARS)
LOCAL_MODULE    := libJSON
LOCAL_SRC_FILES := JSON/arraylist.c\
                   JSON/debug.c\
                   JSON/json_object.c\
                   JSON/json_tokener.c\
                   JSON/json_util.c\
                   JSON/linkhash.c\
                   JSON/printbuf.c				   
	               

LOCAL_LDLIBS := -llog	               
LOCAL_CFLAGS:=-O2 -g -std=gnu99
include $(BUILD_SHARED_LIBRARY)
################################
include $(CLEAR_VARS)
LOCAL_MODULE    := blacksheep
LOCAL_SRC_FILES := http-parser/http_parser.c\
		           src/http_packet.cpp\
	           src/packet_sniffer.cpp\
	           src/main.cpp
	               
LOCAL_SHARED_LIBRARIES := libpcap libJSON 
LOCAL_LDLIBS := -llog	               
LOCAL_CPPFLAGS:=-O2 -g

include $(BUILD_EXECUTABLE)





