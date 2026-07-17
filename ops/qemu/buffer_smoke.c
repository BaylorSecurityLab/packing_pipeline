#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    uint64_t pc;
} Instruction;

typedef struct {
    bool eligible;
} Block;

static struct qemu_plugin_scoreboard *enabled_scoreboard;
static qemu_plugin_u64 enabled;
static struct qemu_plugin_mem_buffer *buffer;
static const char *output_path;
static uint64_t addresses[16];
static uint64_t physical_addresses[16];
static uint64_t ram_addresses[16];
static uint64_t pcs[16];
static size_t retained;
static size_t mapping_failures;

static void block_exec(unsigned int vcpu_index, void *userdata)
{
    const Block *block = userdata;

    qemu_plugin_u64_set(enabled, vcpu_index, block->eligible ? 1 : 0);
}

static void memory_write(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                         uint64_t address, void *userdata)
{
    const Instruction *instruction = userdata;
    uint64_t physical_address = UINT64_MAX;
    uint64_t ram_address = UINT64_MAX;

    (void)vcpu_index;
    if (!qemu_plugin_mem_is_store(info)) {
        abort();
    }
    if (!qemu_plugin_translate_vaddr(address, &physical_address)) {
        mapping_failures++;
    } else {
        ram_address = qemu_plugin_phys_addr_ram_addr(physical_address);
        if (ram_address == UINT64_MAX) {
            mapping_failures++;
        }
    }
    if (retained < sizeof(addresses) / sizeof(addresses[0])) {
        addresses[retained] = address;
        physical_addresses[retained] = physical_address;
        ram_addresses[retained] = ram_address;
        pcs[retained] = instruction->pc;
    }
    retained++;
}

static void translate_block(struct qemu_plugin_tb *tb, void *userdata)
{
    size_t count = qemu_plugin_tb_n_insns(tb);
    uint64_t address = qemu_plugin_tb_vaddr(tb);
    Block *block = malloc(sizeof(*block));

    (void)userdata;
    block->eligible = address >= UINT64_C(0x7c00) &&
                      address < UINT64_C(0x7e00);
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, block_exec, QEMU_PLUGIN_CB_NO_REGS, block);
    for (size_t index = 0; index < count; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        Instruction *instruction = malloc(sizeof(*instruction));
        instruction->pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_mem_buffered_cond_cb(
            insn, memory_write, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_W,
            QEMU_PLUGIN_COND_EQ, enabled, 1, buffer, instruction);
    }
}

static void plugin_exit(void *userdata)
{
    FILE *output;
    uint64_t overflows = qemu_plugin_mem_buffer_overflow_count(buffer);

    (void)userdata;
    output = fopen(output_path, "w");
    if (!output) {
        abort();
    }
    fprintf(output, "{\"retained\":%zu,\"overflows\":%" PRIu64
                    ",\"addresses\":[",
            retained, overflows);
    for (size_t index = 0; index < retained && index < 16; index++) {
        fprintf(output, "%s%" PRIu64, index ? "," : "", addresses[index]);
    }
    fputs("],\"physical_addresses\":[", output);
    for (size_t index = 0; index < retained && index < 16; index++) {
        fprintf(output, "%s%" PRIu64, index ? "," : "",
                physical_addresses[index]);
    }
    fputs("],\"ram_addresses\":[", output);
    for (size_t index = 0; index < retained && index < 16; index++) {
        fprintf(output, "%s%" PRIu64, index ? "," : "",
                ram_addresses[index]);
    }
    fputs("],\"pcs\":[", output);
    for (size_t index = 0; index < retained && index < 16; index++) {
        fprintf(output, "%s%" PRIu64, index ? "," : "", pcs[index]);
    }
    fprintf(output, "],\"mapping_failures\":%zu}\n", mapping_failures);
    fclose(output);
    qemu_plugin_mem_buffer_free(buffer);
    qemu_plugin_scoreboard_free(enabled_scoreboard);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    if (!info->system_emulation || argc != 1 ||
        !g_str_has_prefix(argv[0], "out=")) {
        return -1;
    }
    output_path = argv[0] + 4;
    enabled_scoreboard = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    enabled = qemu_plugin_scoreboard_u64(enabled_scoreboard);
    buffer = qemu_plugin_mem_buffer_new(64);
    if (!buffer) {
        return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate_block, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
