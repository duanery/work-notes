# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../bin/bpftool)
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -O2 -Wall -std=gnu99
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BINDIR ?= $(abspath ../bin)

APPS = \
	biolatency \
	biopattern \
	biosnoop \
	biostacks \
	bitesize \
	cpudist \
	drsnoop \
	execsnoop \
	filelife \
	hardirqs \
	llcstat \
	cpufreq \
	numamove \
	opensnoop \
	readahead \
	runqlat \
	runqlen \
	runqslower \
	softirqs \
	syscount \
	tcpconnect \
	tcpconnlat \
	vfsstat \
	xfsslower \
	rundelay \
	skbsniffer \
	f2flatency \
	#

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/syscall_helpers.o \
	$(OUTPUT)/errno_helpers.o \
	$(OUTPUT)/map_helpers.o \
	#

.PHONY: all
all: $(APPS)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

.PHONY: clean install uninstall skel
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

install:
	$(call msg, INSTALL)
	$(Q)install -s $(APPS) $(BINDIR)

uninstall:
	$(call msg, UNINSTALL)
	$(Q)rm -rf $(patsubst %,$(BINDIR)/%,$(APPS))

skel: $(LIBBPF_OBJ) $(patsubst %.bpf.c,$(OUTPUT)/%.skel.h,$(shell echo *.bpf.c))
	$(Q)rm -rf $(filter-out $^, $(shell echo $(OUTPUT)/*))

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -lpthread -o $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: $(LIBBPF_OBJ) %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/rundelay.o : $(OUTPUT)/rundelay_cpu.skel.h

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ &&		      \
	$(LLVM_STRIP) -g $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

