/* cli.c - Command-line interactive interface for Krakken-Disk
 *
 * A GUI-free, menu-driven front end exposing the core volume operations:
 *   1. Create a new volume
 *   2. Open a volume
 *   3. Mount a volume
 *   4. Exit
 */

#include "config.h"
#include "permut2048.h"
#include "volume.h"
#include "fuse_mount.h"
#include "utils.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>

/* The currently open volume, if any. */
static volume_context_t *g_volume = NULL;

/* ----- input helpers ------------------------------------------------- */

/* Read a line from stdin into buf (NUL-terminated, newline stripped).
 * Returns 0 on success, -1 on EOF/error. */
static int read_line(char *buf, size_t size) {
    if (!fgets(buf, (int)size, stdin)) {
        return -1;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    return 0;
}

/* Read a single line. If show is non-zero the characters are echoed normally;
 * otherwise terminal echo is disabled so the password stays hidden.
 * Returns 0 on success, -1 on error. */
static int read_password(const char *prompt, char *buf, size_t size, int show) {
    if (show) {
        fputs(prompt, stdout);
        fflush(stdout);
        return read_line(buf, size);
    }

    struct termios old_term, new_term;
    int have_term = 0;

    fputs(prompt, stdout);
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
        have_term = 1;
        new_term = old_term;
        new_term.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term);
    }

    int rc = read_line(buf, size);

    if (have_term) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    }
    fputc('\n', stdout);
    return rc;
}

/* Ask the user whether they want the password revealed while typing.
 * Returns non-zero for "yes". */
static int ask_show_password(void) {
    char ans[16];
    printf("Show password while typing? [y/N]: ");
    fflush(stdout);
    if (read_line(ans, sizeof(ans)) != 0) {
        return 0;
    }
    return (ans[0] == 'y' || ans[0] == 'Y');
}

/* ----- progress callback --------------------------------------------- */

static void cli_progress(const char *label, size_t cur, size_t total, void *user_data) {
    (void)user_data;
    if (total == 0) {
        return;
    }
    int pct = (int)((cur * 100) / total);
    int filled = pct / 5; /* 20-char bar */
    char bar[21];
    for (int i = 0; i < 20; i++) {
        bar[i] = (i < filled) ? '#' : '-';
    }
    bar[20] = '\0';
    printf("\r[%s] %3d%% %-28s", bar, pct, label ? label : "");
    fflush(stdout);
    if (cur >= total) {
        fputc('\n', stdout);
    }
}

/* ----- menu actions -------------------------------------------------- */

static void action_create(void) {
    char path[512];
    char size_str[64];
    char password[256];
    char confirm[256];

    printf("\n--- Create a new volume ---\n");

    printf("Volume file path: ");
    fflush(stdout);
    if (read_line(path, sizeof(path)) != 0 || path[0] == '\0') {
        printf("Cancelled (no path given).\n");
        return;
    }

    printf("Volume size in MB (min 10): ");
    fflush(stdout);
    if (read_line(size_str, sizeof(size_str)) != 0) {
        printf("Cancelled.\n");
        return;
    }

    char *end = NULL;
    long size_mb_l = strtol(size_str, &end, 10);
    if (!end || *end != '\0' || size_mb_l < 10) {
        printf("Invalid size. Must be a number >= 10.\n");
        return;
    }
    if (size_mb_l > 1024L * 1024L) {
        printf("Size must not exceed 1048576 MB (1 TiB).\n");
        return;
    }

    int show = ask_show_password();
    if (read_password("Password: ", password, sizeof(password), show) != 0 || password[0] == '\0') {
        printf("Cancelled (no password).\n");
        secure_zero(password, sizeof(password));
        return;
    }
    if (read_password("Confirm password: ", confirm, sizeof(confirm), show) != 0) {
        secure_zero(password, sizeof(password));
        secure_zero(confirm, sizeof(confirm));
        return;
    }
    if (strcmp(password, confirm) != 0) {
        printf("Passwords do not match.\n");
        secure_zero(password, sizeof(password));
        secure_zero(confirm, sizeof(confirm));
        return;
    }
    secure_zero(confirm, sizeof(confirm));

    printf("Creating volume (this may take a while)...\n");
    int result = volume_create(path, (size_t)size_mb_l, password, cli_progress, NULL);
    secure_zero(password, sizeof(password));

    if (result == 0) {
        printf("Volume created successfully: %s\n", path);
    } else {
        printf("Failed to create volume. Check permissions and free space.\n");
    }
}

static void close_current_volume(void) {
    if (!g_volume) {
        return;
    }
    if (g_volume->is_open) {
        if (g_volume->vfs.is_mounted) {
            stop_fuse_mount(g_volume);
            volume_unmount(g_volume);
        }
        volume_close(g_volume, NULL, NULL);
    }
    free(g_volume);
    g_volume = NULL;
}

static void action_open(void) {
    char path[512];
    char password[256];

    printf("\n--- Open a volume ---\n");

    printf("Volume file path: ");
    fflush(stdout);
    if (read_line(path, sizeof(path)) != 0 || path[0] == '\0') {
        printf("Cancelled (no path given).\n");
        return;
    }

    if (read_password("Password: ", password, sizeof(password), ask_show_password()) != 0 ||
        password[0] == '\0') {
        printf("Cancelled (no password).\n");
        secure_zero(password, sizeof(password));
        return;
    }

    /* Replace any previously open volume. */
    close_current_volume();

    g_volume = malloc(sizeof(volume_context_t));
    if (!g_volume) {
        printf("Out of memory.\n");
        secure_zero(password, sizeof(password));
        return;
    }
    memset(g_volume, 0, sizeof(volume_context_t));

    if (lock_sensitive(g_volume, sizeof(volume_context_t)) != 0) {
        printf("Warning: memory locking failed; the master key may be swapped to disk.\n");
        printf("         Run as root or raise memlock limits for maximum security.\n");
    }

    printf("Opening volume (Argon2 needs ~1 GB RAM)...\n");
    int result = volume_open(path, password, g_volume, cli_progress, NULL);
    secure_zero(password, sizeof(password));

    if (result == 0) {
        printf("Volume opened successfully. Use 'Mount a volume' to access files.\n");
    } else {
        printf("Failed to open volume. Possible causes:\n");
        printf("  - Wrong password\n");
        printf("  - Corrupted volume file\n");
        printf("  - Insufficient RAM for Argon2 (needs ~1 GB free)\n");
        free(g_volume);
        g_volume = NULL;
    }
}

static void action_mount(void) {
    char mount_dir[512];

    printf("\n--- Mount a volume ---\n");

    if (!g_volume || !g_volume->is_open) {
        printf("No volume is currently open. Use 'Open a volume' first.\n");
        return;
    }

    if (g_volume->vfs.is_mounted) {
        printf("Volume is already mounted. Remounting...\n");
        stop_fuse_mount(g_volume);
        volume_unmount(g_volume);
    }

    printf("Mount directory: ");
    fflush(stdout);
    if (read_line(mount_dir, sizeof(mount_dir)) != 0 || mount_dir[0] == '\0') {
        printf("Cancelled (no mount directory).\n");
        return;
    }

    printf("Mounting volume...\n");
    int result = volume_mount(g_volume);
    if (result != 0) {
        printf("Failed to mount volume. The filesystem may be corrupted.\n");
        return;
    }

    if (start_fuse_mount(g_volume, mount_dir) != 0) {
        volume_unmount(g_volume);
        printf("Failed to start FUSE daemon. Check that FUSE is available and the\n");
        printf("mount directory exists and is empty.\n");
        return;
    }

    printf("Volume mounted successfully via FUSE at: %s\n", mount_dir);
    printf("Files are accessible there until you unmount or exit.\n");
}

static void action_unmount(void) {
    printf("\n--- Unmount volume ---\n");

    if (!g_volume || !g_volume->vfs.is_mounted) {
        printf("No volume is currently mounted.\n");
        return;
    }

    printf("Unmounting volume...\n");
    stop_fuse_mount(g_volume);
    int result = volume_unmount(g_volume);
    if (result == 0) {
        printf("Volume unmounted successfully.\n");
    } else {
        printf("Failed to unmount volume.\n");
    }
}

static void action_close(void) {
    printf("\n--- Close volume ---\n");

    if (!g_volume || !g_volume->is_open) {
        printf("No volume is currently open.\n");
        return;
    }

    if (g_volume->vfs.is_mounted) {
        printf("Unmounting before close...\n");
        stop_fuse_mount(g_volume);
        volume_unmount(g_volume);
    }

    printf("Closing volume (flushing to disk and wiping keys)...\n");
    int result = volume_close(g_volume, cli_progress, NULL);
    free(g_volume);
    g_volume = NULL;

    if (result == 0) {
        printf("Volume closed successfully.\n");
    } else {
        printf("Volume closed (with errors during flush).\n");
    }
}

static void action_migrate(void) {
    char path[512];
    char password[256];

    printf("\n--- Upgrade volume header (migrate to new format) ---\n");
    printf("This re-seals the volume header with the corrected authentication\n");
    printf("tag. Only the 32-byte header tag changes; your file data is NOT\n");
    printf("touched. The volume stays openable by both the CLI and GUI builds.\n");
    printf("\n");
    printf(">>> BACK UP THE VOLUME FILE FIRST. <<<\n\n");

    /* Operate on a closed file: drop any currently-open volume to avoid two
     * handles writing the same container. */
    close_current_volume();

    printf("Volume file path: ");
    fflush(stdout);
    if (read_line(path, sizeof(path)) != 0 || path[0] == '\0') {
        printf("Cancelled (no path given).\n");
        return;
    }

    if (read_password("Password: ", password, sizeof(password), ask_show_password()) != 0 ||
        password[0] == '\0') {
        printf("Cancelled (no password).\n");
        secure_zero(password, sizeof(password));
        return;
    }

    printf("Verifying password and migrating (Argon2 needs ~1 GB RAM)...\n");
    int result = volume_migrate_header(path, password);
    secure_zero(password, sizeof(password));

    if (result == 0) {
        printf("Success: header upgraded to the new authenticated format.\n");
        printf("Tip: re-run on this volume any time to confirm — it will report\n");
        printf("     'already up to date'.\n");
    } else if (result == 1) {
        printf("Already up to date: this volume already uses the new header.\n");
    } else {
        printf("Migration failed. Causes: wrong password, corrupt header, or the\n");
        printf("file is not writable. The volume was left unchanged.\n");
    }
}

/* ----- main loop ----------------------------------------------------- */

static void print_menu(void) {
    printf("\n========================================\n");
    printf(" %s v%s\n", APP_NAME, APP_VERSION);
    printf("========================================\n");
    printf(" 1. Create a new volume\n");
    printf(" 2. Open a volume\n");
    printf(" 3. Mount a volume\n");
    printf(" 4. Unmount volume\n");
    printf(" 5. Close volume\n");
    printf(" 6. Upgrade volume header (migrate)\n");
    printf(" 7. Exit\n");
    printf("----------------------------------------\n");
    if (g_volume && g_volume->is_open) {
        printf(" [open: %s%s]\n", g_volume->path,
               g_volume->vfs.is_mounted ? " | mounted" : "");
    }
    printf("Select an option [1-7]: ");
    fflush(stdout);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Disable core dumps for security. */
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };
    setrlimit(RLIMIT_CORE, &limit);

    if (sodium_init() < 0) {
        fprintf(stderr, "Error: Failed to initialize libsodium\n");
        return 1;
    }

    init_rc_vectors();

    printf("%s v%s - %s\n", APP_NAME, APP_VERSION, APP_TITLE);
    printf("Command-line interface\n");

    if (check_swap_security()) {
        printf("\nWARNING: Unencrypted swap detected! This may compromise security.\n");
        printf("Consider encrypting swap with LUKS or disabling swap entirely.\n");
    }

    char choice[16];
    for (;;) {
        print_menu();
        if (read_line(choice, sizeof(choice)) != 0) {
            printf("\n");
            break; /* EOF */
        }

        if (strcmp(choice, "1") == 0) {
            action_create();
        } else if (strcmp(choice, "2") == 0) {
            action_open();
        } else if (strcmp(choice, "3") == 0) {
            action_mount();
        } else if (strcmp(choice, "4") == 0) {
            action_unmount();
        } else if (strcmp(choice, "5") == 0) {
            action_close();
        } else if (strcmp(choice, "6") == 0) {
            action_migrate();
        } else if (strcmp(choice, "7") == 0 ||
                   strcmp(choice, "q") == 0 || strcmp(choice, "Q") == 0) {
            break;
        } else if (choice[0] == '\0') {
            continue;
        } else {
            printf("Invalid option: %s\n", choice);
        }
    }

    printf("Cleaning up...\n");
    close_current_volume();
    printf("Goodbye.\n");
    return 0;
}
