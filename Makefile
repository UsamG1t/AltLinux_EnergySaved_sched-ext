# SPDX-License-Identifier: GPL-2.0

ROOT_SRC_DIR := $(CURDIR)

BPF_CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
INSTALL_DIR ?= /usr/local/bin

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else ifeq ($(ARCH),s390x)
	TARGET_ARCH := s390
else
	TARGET_ARCH := $(ARCH)
endif

ENDIAN ?= $(shell printf '\1\0' | od -An -t x2 | awk '{print ($$1=="0001"?"little":"big")}')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types \
	-D__TARGET_ARCH_$(TARGET_ARCH) -mcpu=v3 -m$(ENDIAN)-endian
BPF_INCLUDES := -I$(ROOT_SRC_DIR)/scheds/include \
	-I$(ROOT_SRC_DIR)/scheds/include/bpf-compat \
	-I$(ROOT_SRC_DIR)/scheds/include/lib \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux/arch/$(TARGET_ARCH) \
	$(LIBBPF_CFLAGS)

LIBBPF_DEPS := $(LIBBPF_LIBS) -lelf -lz -lzstd
THREAD_DEPS := -lpthread

LIB_OBJ_DIR := $(ROOT_SRC_DIR)/build/lib
COMMON_OBJ_DIR := $(ROOT_SRC_DIR)/build/common
COMMON_CFLAGS := -O2 -std=c11 -Wall -Wextra -pedantic

SCHEDULERS := scx_stairs scx_erf scx_scheduler fixed_cpuperf

.PHONY: all clean install lib common $(SCHEDULERS) task_workload_origin

all: lib common $(SCHEDULERS)

lib:
	@mkdir -p $(LIB_OBJ_DIR)
	@$(MAKE) -C $(ROOT_SRC_DIR)/lib \
		SRC_DIR=$(ROOT_SRC_DIR)/lib \
		LIB_OBJ_DIR=$(LIB_OBJ_DIR) \
		BPF_CLANG="$(BPF_CLANG)" \
		BPFTOOL="$(BPFTOOL)" \
		BPF_CFLAGS="$(BPF_CFLAGS)" \
		BPF_INCLUDES="$(BPF_INCLUDES)"

common: task_workload_origin

task_workload_origin: $(COMMON_OBJ_DIR)/task_workload_origin

$(COMMON_OBJ_DIR)/task_workload_origin: $(ROOT_SRC_DIR)/launch/common/task_workload_origin.c
	@mkdir -p $(dir $@)
	$(CC) $(COMMON_CFLAGS) $< -o $@

define SCHED_RULES
$(ROOT_SRC_DIR)/build/$(1)/$(1).bpf.o: $(ROOT_SRC_DIR)/scheds/$(1)/$(1).bpf.c
	@echo "Compiling BPF: $$< -> $$@"
	@mkdir -p $$(dir $$@)
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $$< -o $$@

$(ROOT_SRC_DIR)/build/$(1)/$(1).bpf.skel.h: $(ROOT_SRC_DIR)/build/$(1)/$(1).bpf.o
	@echo "Generating skeleton: $$@"
	@mkdir -p $$(dir $$@)
	$(BPFTOOL) gen skeleton $$< name $(1) > $$@

$(ROOT_SRC_DIR)/build/$(1)/$(1): $(ROOT_SRC_DIR)/scheds/$(1)/$(1).c $(ROOT_SRC_DIR)/build/$(1)/$(1).bpf.skel.h
	@echo "Building scheduler: $$@"
	@mkdir -p $$(dir $$@)
	$(CC) -std=gnu11 -I$(ROOT_SRC_DIR)/scheds/include -I$(ROOT_SRC_DIR)/scheds/vmlinux -I$(ROOT_SRC_DIR)/build/$(1) -I$(ROOT_SRC_DIR)/scheds/$(1) $(LIBBPF_CFLAGS) $$< -o $$@ $(LIBBPF_DEPS) $(THREAD_DEPS)

$(1): lib $(ROOT_SRC_DIR)/build/$(1)/$(1)
endef

$(foreach sched,$(SCHEDULERS),$(eval $(call SCHED_RULES,$(sched))))

install: all
	@mkdir -p $(INSTALL_DIR)
	@for sched in $(SCHEDULERS); do \
		cp "$(ROOT_SRC_DIR)/build/$$sched/$$sched" "$(INSTALL_DIR)/"; \
	done
	@cp "$(COMMON_OBJ_DIR)/task_workload_origin" "$(INSTALL_DIR)/"

clean:
	$(MAKE) -C $(ROOT_SRC_DIR)/lib clean \
		SRC_DIR=$(ROOT_SRC_DIR)/lib \
		LIB_OBJ_DIR=$(LIB_OBJ_DIR)
	rm -rf $(ROOT_SRC_DIR)/build/common \
		$(ROOT_SRC_DIR)/build/scx_stairs \
		$(ROOT_SRC_DIR)/build/scx_erf \
		$(ROOT_SRC_DIR)/build/scx_scheduler \
		$(ROOT_SRC_DIR)/build/fixed_cpuperf
