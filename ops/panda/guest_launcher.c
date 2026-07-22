/*
 * PANDA recording launcher for the Windows analysis guest.
 *
 * The launcher creates the packed program suspended, starts a deterministic
 * PANDA recording, emits the child PID in a CPUID marker, and only then lets
 * the first packed instruction execute.  It waits for the complete job (root
 * process plus descendants), so process-switching packers remain in scope.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECCTRL_MAGIC 0x666u
#define RECCTRL_TOGGLE ((uint32_t)-100)
#define RECCTRL_RET_START 1u
#define RECCTRL_RET_STOP 2u

#define PACKER_MARKER_MAGIC 0x5041434bu /* "PACK" */
#define PACKER_MARKER_ROOT_PID 1u
#define PACKER_MARKER_TRACE_START 2u
#define PACKER_MARKER_TRACE_STOP 3u
#define PACKER_MARKER_STATUS_QUERY 4u
#define PACKER_STOP_TIMEOUT_FLAG 0x80000000u
#define PACKER_STOP_IDLE_FLAG 0x40000000u
#define PACKER_STOP_QUERY_FAILURE_FLAG 0x20000000u
#define PACKER_STOP_EXCEPTION_FLAG 0x10000000u
#define PACKER_STATUS_MAGIC UINT64_C(0x5153544154555350)
#define PACKER_IDLE_MILLISECONDS UINT64_C(120000)

typedef struct {
    uint64_t magic;
    uint64_t status_ready;
    uint64_t sample_started;
    uint64_t active_processes;
    uint64_t execution_events;
    uint64_t pending_exceptions;
    uint64_t oldest_exception_age_ms;
} PACKER_STATUS;

static int service_argc;
static char **service_argv;
static SERVICE_STATUS_HANDLE service_status_handle;

static uint32_t cpuid_call(uint32_t eax_in, uintptr_t ebx_in,
                           uintptr_t ecx_in, uintptr_t edx_in) {
    uintptr_t eax = eax_in;
    uintptr_t ebx = ebx_in;
    uintptr_t ecx = ecx_in;
    uintptr_t edx = edx_in;
    /* QEMU TCG does not invoke instruction-execution plugin callbacks for
     * CPUID on this target.  This architectural long NOP embeds "PACK" in
     * its ignored displacement and is the QEMU marker point.  PANDA
     * continues to consume the following CPUID instruction. */
    __asm__ __volatile__(".byte 0x0f, 0x1f, 0x84, 0x00, "
                         "0x4b, 0x43, 0x41, 0x50\n\t"
                         "cpuid"
                         : "+a"(eax), "+b"(ebx), "+c"(ecx), "+d"(edx)
                         :
                         : "memory");
    return (uint32_t)eax;
}

static uint32_t recording_toggle(const char *recording_name) {
    return cpuid_call(RECCTRL_MAGIC, RECCTRL_TOGGLE,
                      (uintptr_t)recording_name, 0);
}

static int query_packer_status(DWORD root_pid, PACKER_STATUS *status) {
    ZeroMemory(status, sizeof(*status));
    cpuid_call(PACKER_MARKER_MAGIC, root_pid, PACKER_MARKER_STATUS_QUERY,
               (uintptr_t)status);
    return status->magic == PACKER_STATUS_MAGIC;
}

static void write_status(const char *path, const char *state, DWORD detail,
                         DWORD child_pid) {
    FILE *handle = fopen(path, "wb");
    if (handle == NULL) {
        return;
    }
    fprintf(handle, "state=%s\r\ndetail=%lu\r\nchild_pid=%lu\r\n",
            state, (unsigned long)detail, (unsigned long)child_pid);
    fclose(handle);
}

/* The 2-minute idle boundary is the paper's rule for real packer samples, which
 * run to a quiescent tail.  The cross-process VALIDATION FIXTURE instead spawns
 * cooperating children and blocks in WaitForSingleObject, and under exact
 * instrumentation a child's CreateProcess+bring-up can exceed 2 guest-minutes.
 * Only the fixture setup provides C:\Panda\idle_ms.txt, so real-sample runs keep
 * the 2-minute boundary while the fixture gets a longer, validation-only window.
 * The value is clamped to [2 min, 30 min] and never exceeds the 30-minute max. */
static uint64_t read_idle_milliseconds(void) {
    uint64_t idle = PACKER_IDLE_MILLISECONDS;
    FILE *override_file = fopen("C:\\Panda\\idle_ms.txt", "r");
    if (override_file != NULL) {
        unsigned long long value = 0;
        if (fscanf(override_file, "%llu", &value) == 1 &&
            value >= PACKER_IDLE_MILLISECONDS && value <= UINT64_C(1800000)) {
            idle = (uint64_t)value;
        }
        fclose(override_file);
    }
    return idle;
}

static int run_sample(int argc, char **argv) {
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    HANDLE job = NULL;
    char *command_line = NULL;
    DWORD timeout_seconds;
    uint64_t idle_milliseconds;
    DWORD wait_result;
    DWORD child_exit_code = STILL_ACTIVE;
    DWORD stop_detail = 0;
    uint32_t record_result;
    int live_mode;
    int result = 1;

    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <sample.exe> <timeout-seconds> "
                "<host-recording-name> <status-file>\n",
                argv[0]);
        return 2;
    }

    timeout_seconds = strtoul(argv[2], NULL, 10);
    live_mode = strcmp(argv[3], "-") == 0;
    if (timeout_seconds == 0 || timeout_seconds > 3600) {
        write_status(argv[4], "invalid_timeout", timeout_seconds, 0);
        return 2;
    }
    idle_milliseconds = read_idle_milliseconds();
    write_status(argv[4], "starting", timeout_seconds, 0);

    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    ZeroMemory(&limits, sizeof(limits));
    startup.cb = sizeof(startup);

    command_line = _strdup(argv[1]);
    if (command_line == NULL) {
        write_status(argv[4], "allocation_failed", ERROR_NOT_ENOUGH_MEMORY, 0);
        return 1;
    }

    job = CreateJobObjectA(NULL, NULL);
    if (job == NULL) {
        write_status(argv[4], "job_create_failed", GetLastError(), 0);
        goto cleanup;
    }
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        write_status(argv[4], "job_config_failed", GetLastError(), 0);
        goto cleanup;
    }

    if (!CreateProcessA(argv[1], command_line, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &startup, &process)) {
        write_status(argv[4], "create_process_failed", GetLastError(), 0);
        goto cleanup;
    }
    if (!AssignProcessToJobObject(job, process.hProcess)) {
        write_status(argv[4], "job_assign_failed", GetLastError(),
                     process.dwProcessId);
        TerminateProcess(process.hProcess, 1);
        goto process_cleanup;
    }

    if (!live_mode) {
        record_result = recording_toggle(argv[3]);
        if (record_result != RECCTRL_RET_START) {
            write_status(argv[4], "record_start_failed", record_result,
                         process.dwProcessId);
            TerminateProcess(process.hProcess, 1);
            goto process_cleanup;
        }
    }

    /* Replay learns the child's ASID from its TEB before the PE entry point. */
    cpuid_call(PACKER_MARKER_MAGIC, process.dwProcessId,
               PACKER_MARKER_ROOT_PID, process.dwThreadId);
    cpuid_call(PACKER_MARKER_MAGIC, process.dwProcessId,
               PACKER_MARKER_TRACE_START, process.dwThreadId);

    if (ResumeThread(process.hThread) == (DWORD)-1) {
        DWORD error = GetLastError();
        if (!live_mode) {
            recording_toggle(argv[3]);
        }
        write_status(argv[4], "resume_failed", error, process.dwProcessId);
        TerminateProcess(process.hProcess, 1);
        goto process_cleanup;
    }

    if (live_mode) {
        ULONGLONG started = GetTickCount64();
        ULONGLONG last_execution = started;
        uint64_t last_execution_events = 0;
        int sample_started = 0;

        for (;;) {
            PACKER_STATUS packer_status;
            ULONGLONG now;
            /* Wait on the SAMPLE PROCESS handle, not the job object.  A job is
             * never signaled by becoming empty, and the plugin's active-process
             * count cannot be trusted to reach 0 here: this launcher holds the
             * sample's handle, so its EPROCESS lingers on PsActiveProcessHead
             * after exit (referenced) and keeps getting counted.  The process
             * handle signals exactly when the sample exits — the reliable clean
             * completion boundary.  For the cross-process fixture the root exits
             * only after WaitForSingleObject on its children returns, so this is
             * the all-work-done boundary in both modes. */
            DWORD current_wait = WaitForSingleObject(process.hProcess, 1000u);

            if (current_wait == WAIT_OBJECT_0) {
                wait_result = WAIT_OBJECT_0;
                break;
            } else if (current_wait != WAIT_TIMEOUT) {
                wait_result = current_wait;
                break;
            }
            if (!query_packer_status(process.dwProcessId, &packer_status)) {
                wait_result = WAIT_FAILED;
                stop_detail = PACKER_STOP_QUERY_FAILURE_FLAG;
                break;
            }
            now = GetTickCount64();
            if (now - started >= (ULONGLONG)timeout_seconds * 1000u) {
                wait_result = WAIT_TIMEOUT;
                stop_detail = PACKER_STOP_TIMEOUT_FLAG | WAIT_TIMEOUT;
                break;
            }
            if (!packer_status.status_ready) {
                continue;
            }
            if (packer_status.sample_started && !sample_started) {
                sample_started = 1;
                last_execution_events = packer_status.execution_events;
                last_execution = now;
            }
            if (packer_status.execution_events != last_execution_events) {
                last_execution_events = packer_status.execution_events;
                last_execution = now;
            }
            /* Clean completion is detected by the process-handle wait above; the
             * plugin's active_processes count is unreliable for it (held-handle
             * EPROCESS lingering), so it is used only for exception scoping. */
            if (packer_status.pending_exceptions > 0 &&
                packer_status.oldest_exception_age_ms >=
                    PACKER_IDLE_MILLISECONDS) {
                wait_result = WAIT_TIMEOUT;
                stop_detail = PACKER_STOP_EXCEPTION_FLAG | WAIT_TIMEOUT;
                break;
            }
            if (sample_started &&
                now - last_execution >= idle_milliseconds) {
                wait_result = WAIT_TIMEOUT;
                stop_detail = PACKER_STOP_IDLE_FLAG | WAIT_TIMEOUT;
                break;
            }
        }
    } else {
        wait_result = WaitForSingleObject(job, timeout_seconds * 1000u);
        if (wait_result == WAIT_TIMEOUT) {
            stop_detail = PACKER_STOP_TIMEOUT_FLAG | WAIT_TIMEOUT;
        }
    }
    if (wait_result == WAIT_TIMEOUT) {
        TerminateJobObject(job, WAIT_TIMEOUT);
    }

    /* Persist termination before recctrl's nrec=1 setting quits PANDA. */
    if (wait_result == WAIT_TIMEOUT &&
        (stop_detail & PACKER_STOP_EXCEPTION_FLAG)) {
        write_status(argv[4], "unrecovered_exception", 120,
                     process.dwProcessId);
        result = 0;
    } else if (wait_result == WAIT_TIMEOUT &&
        (stop_detail & PACKER_STOP_IDLE_FLAG)) {
        write_status(argv[4], "idle", 120,
                     process.dwProcessId);
        result = 0;
    } else if (wait_result == WAIT_TIMEOUT) {
        write_status(argv[4], "timeout", timeout_seconds,
                     process.dwProcessId);
        result = 3;
    } else if (wait_result == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &child_exit_code);
        write_status(argv[4], "complete", child_exit_code, process.dwProcessId);
        result = 0;
    } else {
        write_status(argv[4], "wait_failed", GetLastError(),
                     process.dwProcessId);
    }
    cpuid_call(PACKER_MARKER_MAGIC, process.dwProcessId,
               PACKER_MARKER_TRACE_STOP,
               wait_result == WAIT_TIMEOUT || stop_detail
                   ? stop_detail : child_exit_code);
    if (live_mode) {
        /* Let Windows close NTFS cleanly.  The host tracer exits when QEMU
         * observes the guest power-off instead of aborting the VM at CPUID. */
        if (system("C:\\Windows\\System32\\shutdown.exe /s /t 0 /f") == -1) {
            write_status(argv[4], "shutdown_failed", GetLastError(),
                         process.dwProcessId);
            result = 1;
        }
    } else {
        record_result = recording_toggle(argv[3]);
        if (record_result != RECCTRL_RET_STOP) {
            write_status(argv[4], "record_stop_failed", record_result,
                         process.dwProcessId);
            result = 1;
        }
    }

process_cleanup:
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
cleanup:
    if (job != NULL) {
        CloseHandle(job);
    }
    free(command_line);
    return result;
}

static void WINAPI service_control(DWORD control) {
    (void)control;
}

static void WINAPI service_main(DWORD argc, char **argv) {
    SERVICE_STATUS status;
    int result;

    (void)argc;
    (void)argv;
    ZeroMemory(&status, sizeof(status));
    service_status_handle =
        RegisterServiceCtrlHandlerA("PandaPilot", service_control);
    if (service_status_handle == NULL) {
        return;
    }
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = 0;
    status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(service_status_handle, &status);

    result = run_sample(service_argc, service_argv);
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR;
    status.dwServiceSpecificExitCode = (DWORD)result;
    SetServiceStatus(service_status_handle, &status);
}

int main(int argc, char **argv) {
    SERVICE_TABLE_ENTRYA service_table[] = {
        {"PandaPilot", service_main},
        {NULL, NULL},
    };

    if (argc > 1 && strcmp(argv[1], "--service") == 0) {
        /* Keep the configured command-line arguments for ServiceMain. */
        service_argc = argc - 1;
        service_argv = argv + 1;
        if (!StartServiceCtrlDispatcherA(service_table)) {
            write_status(argc > 5 ? argv[5] : "C:\\Panda\\status.txt",
                         "service_dispatch_failed", GetLastError(), 0);
            return 1;
        }
        return 0;
    }
    return run_sample(argc, argv);
}
