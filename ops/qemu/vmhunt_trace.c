#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>
#include <qemu-plugin.h>

#include "win10_profile.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_VCPU 64
#define MAX_INSN_BYTES 16

#define PACKER_MARKER_MAGIC UINT32_C(0x5041434b)
#define MARK_ROOT_PID UINT32_C(1)
#define MARK_TRACE_START UINT32_C(2)
#define MARK_TRACE_STOP UINT32_C(3)
#define USER_LIMIT_64 UINT64_C(0x0000800000000000)

enum {
    R_EAX = 0,
    R_EBX,
    R_ECX,
    R_EDX,
    R_ESI,
    R_EDI,
    R_ESP,
    R_EBP,
    R_COUNT
};

typedef struct {
    struct qemu_plugin_register *gp[R_COUNT];
    bool has_gp[R_COUNT];
    struct qemu_plugin_register *cr3;
    struct qemu_plugin_register *gs_base;
    struct qemu_plugin_register *k_gs_base;
    bool has_cr3;
    bool has_gs_base;
    bool has_k_gs_base;
} RegisterSet;

typedef struct {
    uint64_t vaddr;
    uint32_t size;
    uint8_t bytes[MAX_INSN_BYTES];
    bool is_marker;
    char *disas;
} InsnData;

typedef struct {
    uint64_t vaddr;
} BlockData;

typedef struct {
    bool valid;
    uint64_t vaddr;
    const char *disas;
    uint32_t regs[R_COUNT];
} PendingInsn;

static const char *const reg_names64[R_COUNT] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
};
static const char *const reg_names32[R_COUNT] = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
};

static RegisterSet registers_by_vcpu[MAX_VCPU];
static uint32_t current_read_addr[MAX_VCPU];
static uint32_t current_write_addr[MAX_VCPU];
static PendingInsn pending_by_vcpu[MAX_VCPU];
static FILE *file_by_vcpu[MAX_VCPU];

static char *output_base;
static uint64_t monitored_asid;
static bool asid_known;
static uint64_t root_pid;
static bool armed;
static bool marker_seen;
static csh capstone_handle;
static bool capstone_ready;
static GMutex disas_lock;
static GMutex scope_lock;
static GHashTable *insn_cache;
static GHashTable *block_cache;

static uint64_t read_register_value(struct qemu_plugin_register *handle,
                                    bool *ok)
{
    g_autoptr(GByteArray) bytes = g_byte_array_new();
    uint64_t value = 0;

    if (!qemu_plugin_read_register(handle, bytes) || bytes->len == 0 ||
        bytes->len > sizeof(value)) {
        *ok = false;
        return 0;
    }
    memcpy(&value, bytes->data, bytes->len);
    *ok = true;
    return value;
}

static bool read_memory(uint64_t address, void *destination, size_t size)
{
    g_autoptr(GByteArray) bytes = g_byte_array_new();

    if (!qemu_plugin_read_memory_vaddr(address, bytes, size) ||
        bytes->len != size) {
        return false;
    }
    memcpy(destination, bytes->data, size);
    return true;
}

static bool read_u64(uint64_t address, uint64_t *value)
{
    return read_memory(address, value, sizeof(*value));
}

static bool canonical_kernel_pointer(uint64_t value)
{
    return value >= UINT64_C(0xffff800000000000);
}

static bool user_address(uint64_t address)
{
    return address < USER_LIMIT_64;
}

static bool current_asid(unsigned int vcpu_index, uint64_t *asid)
{
    RegisterSet *regs;
    bool ok;

    if (vcpu_index >= MAX_VCPU) {
        return false;
    }
    regs = &registers_by_vcpu[vcpu_index];
    if (!regs->has_cr3) {
        return false;
    }
    *asid = read_register_value(regs->cr3, &ok) & ~UINT64_C(0xfff);
    return ok;
}

static bool current_ethread(unsigned int vcpu_index, uint64_t *ethread)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    uint64_t candidates[2] = {0, 0};
    bool ok;

    if (regs->has_gs_base) {
        candidates[0] = read_register_value(regs->gs_base, &ok);
        if (!ok) {
            candidates[0] = 0;
        }
    }
    if (regs->has_k_gs_base) {
        candidates[1] = read_register_value(regs->k_gs_base, &ok);
        if (!ok) {
            candidates[1] = 0;
        }
    }
    for (int index = 0; index < 2; index++) {
        uint64_t kpcr = candidates[index];
        if (!canonical_kernel_pointer(kpcr) ||
            !read_u64(kpcr + KPCR_PRCB + KPRCB_CURRENT_THREAD, ethread)) {
            continue;
        }
        if (canonical_kernel_pointer(*ethread)) {
            return true;
        }
    }
    return false;
}

static bool resolve_source(unsigned int vcpu_index, uint64_t *source_pid,
                           uint64_t *attached_pid)
{
    uint64_t ethread;
    uint64_t source_eprocess;
    uint64_t verify_pid;
    uint64_t attached_eprocess;

    if (!current_ethread(vcpu_index, &ethread) ||
        !read_u64(ethread + ETHREAD_CID + CLIENT_ID_PID, source_pid) ||
        !read_u64(ethread + KTHREAD_PROCESS, &source_eprocess) ||
        !canonical_kernel_pointer(source_eprocess) ||
        !read_u64(source_eprocess + EPROCESS_PID, &verify_pid) ||
        verify_pid != *source_pid) {
        return false;
    }
    if (!read_u64(ethread + KTHREAD_APC_STATE + KAPC_STATE_PROCESS,
                  &attached_eprocess) ||
        !canonical_kernel_pointer(attached_eprocess) ||
        !read_u64(attached_eprocess + EPROCESS_PID, attached_pid)) {
        return false;
    }
    return true;
}

static void handle_marker(unsigned int vcpu_index)
{
    RegisterSet *regs = &registers_by_vcpu[vcpu_index];
    uint64_t magic;
    uint64_t pid;
    uint64_t action;
    bool ok;

    if (!regs->has_gp[R_EAX] || !regs->has_gp[R_EBX] ||
        !regs->has_gp[R_ECX]) {
        return;
    }
    magic = read_register_value(regs->gp[R_EAX], &ok);
    if (!ok || (uint32_t)magic != PACKER_MARKER_MAGIC) {
        return;
    }
    pid = read_register_value(regs->gp[R_EBX], &ok);
    if (!ok) {
        return;
    }
    action = read_register_value(regs->gp[R_ECX], &ok);
    if (!ok) {
        return;
    }

    g_mutex_lock(&scope_lock);
    marker_seen = true;
    if ((uint32_t)action == MARK_ROOT_PID) {
        root_pid = (uint32_t)pid;
        armed = true;
    } else if ((uint32_t)action == MARK_TRACE_START) {
        armed = true;
    } else if ((uint32_t)action == MARK_TRACE_STOP) {
        /* boundary marker; scoping remains by asid */
    }
    g_mutex_unlock(&scope_lock);
}

static char *disassemble_insn(const uint8_t *bytes, size_t length,
                              uint64_t vaddr)
{
    cs_insn *decoded = NULL;
    size_t count = cs_disasm(capstone_handle, bytes, length, vaddr, 1, &decoded);
    char *result;

    if (count < 1) {
        return g_strdup("(bad)");
    }
    if (decoded[0].op_str[0] != '\0') {
        result =
            g_strdup_printf("%s %s", decoded[0].mnemonic, decoded[0].op_str);
    } else {
        result = g_strdup(decoded[0].mnemonic);
    }
    cs_free(decoded, count);
    return result;
}

static bool marker_bytes(const uint8_t *bytes, size_t length)
{
    size_t offset = (length >= 9 && bytes[0] == 0x67) ? 1 : 0;

    return length >= offset + 8 && bytes[offset] == 0x0f &&
           bytes[offset + 1] == 0x1f && bytes[offset + 2] == 0x84 &&
           bytes[offset + 3] == 0x00 && bytes[offset + 4] == 0x4b &&
           bytes[offset + 5] == 0x43 && bytes[offset + 6] == 0x41 &&
           bytes[offset + 7] == 0x50;
}

static InsnData *intern_insn(struct qemu_plugin_insn *insn)
{
    uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
    size_t size = qemu_plugin_insn_size(insn);
    uint8_t bytes[MAX_INSN_BYTES] = {0};
    size_t copied;
    InsnData *data;

    if (size > MAX_INSN_BYTES) {
        size = MAX_INSN_BYTES;
    }
    copied = qemu_plugin_insn_data(insn, bytes, size);

    g_mutex_lock(&disas_lock);
    data = g_hash_table_lookup(insn_cache, &vaddr);
    if (data && data->size == copied &&
        memcmp(data->bytes, bytes, copied) == 0) {
        g_mutex_unlock(&disas_lock);
        return data;
    }
    if (!data) {
        data = g_new0(InsnData, 1);
        data->vaddr = vaddr;
        g_hash_table_insert(insn_cache, &data->vaddr, data);
    } else {
        g_free(data->disas);
    }
    data->size = (uint32_t)copied;
    memcpy(data->bytes, bytes, copied);
    data->is_marker = marker_bytes(bytes, copied);
    data->disas = disassemble_insn(bytes, copied, vaddr);
    g_mutex_unlock(&disas_lock);
    return data;
}

static BlockData *intern_block(struct qemu_plugin_tb *tb)
{
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
    BlockData *data;

    g_mutex_lock(&disas_lock);
    data = g_hash_table_lookup(block_cache, &vaddr);
    if (!data) {
        data = g_new0(BlockData, 1);
        data->vaddr = vaddr;
        g_hash_table_insert(block_cache, &data->vaddr, data);
    }
    g_mutex_unlock(&disas_lock);
    return data;
}

static FILE *vcpu_file(unsigned int vcpu_index)
{
    if (vcpu_index >= MAX_VCPU) {
        return NULL;
    }
    if (!file_by_vcpu[vcpu_index]) {
        char *path = g_strdup_printf("%s.%u", output_base, vcpu_index);
        FILE *file = fopen(path, "w");
        if (file) {
            setvbuf(file, NULL, _IOFBF, 4 * 1024 * 1024);
            file_by_vcpu[vcpu_index] = file;
        } else {
            fprintf(stderr, "vmhunt_trace: cannot open %s: %s\n", path,
                    strerror(errno));
        }
        g_free(path);
    }
    return file_by_vcpu[vcpu_index];
}

static void emit_pending(unsigned int vcpu_index)
{
    PendingInsn *pending = &pending_by_vcpu[vcpu_index];
    FILE *file;

    if (!pending->valid) {
        return;
    }
    file = vcpu_file(vcpu_index);
    if (!file) {
        return;
    }
    fprintf(file, "%x;%s;%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,\n",
            (uint32_t)pending->vaddr, pending->disas, pending->regs[R_EAX],
            pending->regs[R_EBX], pending->regs[R_ECX], pending->regs[R_EDX],
            pending->regs[R_ESI], pending->regs[R_EDI], pending->regs[R_ESP],
            pending->regs[R_EBP], current_read_addr[vcpu_index],
            current_write_addr[vcpu_index]);
}

static void learn_scope(unsigned int vcpu_index, void *userdata)
{
    BlockData *block = userdata;
    uint64_t source_pid;
    uint64_t attached_pid;
    uint64_t live;

    if (vcpu_index >= MAX_VCPU || asid_known || !armed) {
        return;
    }
    if (!user_address(block->vaddr)) {
        return;
    }
    if (!resolve_source(vcpu_index, &source_pid, &attached_pid)) {
        return;
    }
    if (source_pid != root_pid || source_pid != attached_pid) {
        return;
    }
    if (!current_asid(vcpu_index, &live)) {
        return;
    }
    g_mutex_lock(&scope_lock);
    if (!asid_known) {
        monitored_asid = live;
        asid_known = true;
    }
    g_mutex_unlock(&scope_lock);
}

static void on_mem(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *userdata)
{
    (void)userdata;
    if (vcpu_index >= MAX_VCPU) {
        return;
    }
    if (qemu_plugin_mem_is_store(info)) {
        current_write_addr[vcpu_index] = (uint32_t)vaddr;
    } else {
        current_read_addr[vcpu_index] = (uint32_t)vaddr;
    }
}

static void on_insn(unsigned int vcpu_index, void *userdata)
{
    InsnData *insn = userdata;
    PendingInsn *pending;
    RegisterSet *regs;
    uint64_t asid;
    bool in_scope;

    if (vcpu_index >= MAX_VCPU) {
        return;
    }

    emit_pending(vcpu_index);
    current_read_addr[vcpu_index] = 0;
    current_write_addr[vcpu_index] = 0;

    if (insn->is_marker) {
        handle_marker(vcpu_index);
    }

    in_scope = asid_known && current_asid(vcpu_index, &asid) &&
               asid == monitored_asid;
    pending = &pending_by_vcpu[vcpu_index];
    if (!in_scope) {
        pending->valid = false;
        return;
    }

    regs = &registers_by_vcpu[vcpu_index];
    for (int index = 0; index < R_COUNT; index++) {
        bool ok = false;
        pending->regs[index] =
            regs->has_gp[index]
                ? (uint32_t)read_register_value(regs->gp[index], &ok)
                : 0;
        if (!ok) {
            pending->regs[index] = 0;
        }
    }
    pending->vaddr = insn->vaddr;
    pending->disas = insn->disas;
    pending->valid = true;
}

static void translate_block(struct qemu_plugin_tb *tb, void *userdata)
{
    size_t count = qemu_plugin_tb_n_insns(tb);
    BlockData *block = intern_block(tb);

    (void)userdata;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, learn_scope, QEMU_PLUGIN_CB_R_REGS,
                                         block);
    for (size_t index = 0; index < count; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        InsnData *data = intern_insn(insn);

        qemu_plugin_register_vcpu_mem_cb(insn, on_mem, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, data);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, on_insn,
                                               QEMU_PLUGIN_CB_R_REGS, data);
    }
}

static void initialize_vcpu(unsigned int vcpu_index, void *userdata)
{
    GArray *descriptors;
    RegisterSet *regs;

    (void)userdata;
    if (vcpu_index >= MAX_VCPU) {
        return;
    }
    regs = &registers_by_vcpu[vcpu_index];
    descriptors = qemu_plugin_get_registers();
    for (guint index = 0; index < descriptors->len; index++) {
        qemu_plugin_reg_descriptor descriptor =
            g_array_index(descriptors, qemu_plugin_reg_descriptor, index);
        for (int slot = 0; slot < R_COUNT; slot++) {
            if (!regs->has_gp[slot] &&
                (g_strcmp0(descriptor.name, reg_names64[slot]) == 0 ||
                 g_strcmp0(descriptor.name, reg_names32[slot]) == 0)) {
                regs->gp[slot] = descriptor.handle;
                regs->has_gp[slot] = true;
            }
        }
        if (!regs->has_cr3 && g_strcmp0(descriptor.name, "cr3") == 0) {
            regs->cr3 = descriptor.handle;
            regs->has_cr3 = true;
        }
        if (!regs->has_gs_base && g_strcmp0(descriptor.name, "gs_base") == 0) {
            regs->gs_base = descriptor.handle;
            regs->has_gs_base = true;
        }
        if (!regs->has_k_gs_base &&
            g_strcmp0(descriptor.name, "k_gs_base") == 0) {
            regs->k_gs_base = descriptor.handle;
            regs->has_k_gs_base = true;
        }
    }
    g_array_free(descriptors, true);
    vcpu_file(vcpu_index);
}

static void plugin_exit(void *userdata)
{
    (void)userdata;
    for (unsigned int vcpu_index = 0; vcpu_index < MAX_VCPU; vcpu_index++) {
        emit_pending(vcpu_index);
        pending_by_vcpu[vcpu_index].valid = false;
        if (file_by_vcpu[vcpu_index]) {
            fflush(file_by_vcpu[vcpu_index]);
            fclose(file_by_vcpu[vcpu_index]);
            file_by_vcpu[vcpu_index] = NULL;
        }
    }
    if (capstone_ready) {
        cs_close(&capstone_handle);
        capstone_ready = false;
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    const char *output = NULL;

    if (!info->system_emulation) {
        fprintf(stderr, "vmhunt_trace requires QEMU system emulation\n");
        return -1;
    }
    for (int index = 0; index < argc; index++) {
        if (g_str_has_prefix(argv[index], "outfile=")) {
            output = argv[index] + strlen("outfile=");
        } else if (g_str_has_prefix(argv[index], "out=")) {
            output = argv[index] + strlen("out=");
        } else if (g_str_has_prefix(argv[index], "asid=")) {
            monitored_asid =
                g_ascii_strtoull(argv[index] + strlen("asid="), NULL, 16) &
                ~UINT64_C(0xfff);
            asid_known = true;
        } else {
            fprintf(stderr, "vmhunt_trace: unknown option %s\n", argv[index]);
            return -1;
        }
    }
    if (!output || !*output) {
        fprintf(stderr,
                "vmhunt_trace: required plugin option outfile=PATH missing\n");
        return -1;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &capstone_handle) != CS_ERR_OK) {
        fprintf(stderr, "vmhunt_trace: cs_open failed\n");
        return -1;
    }
    cs_option(capstone_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    capstone_ready = true;

    output_base = g_strdup(output);
    g_mutex_init(&disas_lock);
    g_mutex_init(&scope_lock);
    insn_cache =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    block_cache =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);

    qemu_plugin_register_vcpu_init_cb(id, initialize_vcpu, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate_block, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
