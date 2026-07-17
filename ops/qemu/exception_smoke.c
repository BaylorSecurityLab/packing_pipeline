#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static const char *output_path;
static uint64_t from_pc;
static uint64_t to_pc;
static unsigned int count;
static int exception_index = -1;

static void discontinuity(unsigned int vcpu_index,
                          enum qemu_plugin_discon_type type,
                          uint64_t from, uint64_t to, void *userdata)
{
    (void)vcpu_index;
    (void)userdata;
    if (type == QEMU_PLUGIN_DISCON_EXCEPTION && from >= UINT64_C(0x7c00) &&
        from < UINT64_C(0x7e00) && count++ == 0) {
        from_pc = from;
        to_pc = to;
        exception_index = qemu_plugin_vcpu_exception_index();
    }
}

static void plugin_exit(void *userdata)
{
    FILE *output;

    (void)userdata;
    output = fopen(output_path, "w");
    if (!output) {
        return;
    }
    fprintf(output,
            "{\"count\":%u,\"exception_index\":%d,"
            "\"from_pc\":%" PRIu64 ",\"to_pc\":%" PRIu64 "}\n",
            count, exception_index, from_pc, to_pc);
    fclose(output);
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
    qemu_plugin_register_vcpu_discon_cb(
        id, QEMU_PLUGIN_DISCON_EXCEPTION, discontinuity, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
