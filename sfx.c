#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>

/* =========================
 * Debug (hidden flag)
 * ========================= */
static int g_debug = 0;
#define DBG(fmt, ...) \
    do { if (g_debug) fprintf(stderr, "[SFX][DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)

/* =========================
 * Signal-safe cleanup state
 * ========================= */
static char g_tmpdir[PATH_MAX] = {0};
static int  g_in_install = 0;

/* =========================
 * Layout constants
 * ========================= */
#define PARAM_AREA_SIZE 4096u
#define PARAM_MAGIC "SFXP2"
#define FOOT_MAGIC  "SFXF2"
#define PARAM_VERSION 1u
#define EXEC_MAX 1024u

#pragma pack(push,1)
typedef struct {
    char     magic[5];
    uint8_t  version;
    uint8_t  flags;
    uint8_t  xor_mask;
    uint8_t  r0;

    uint32_t exec_len;
    uint32_t r1;

    uint8_t  exec_xor[EXEC_MAX];
    uint8_t  pass_md5_obf[32];

    uint64_t payload_offset;
    uint64_t payload_size;

    uint8_t  pad[PARAM_AREA_SIZE
                - (5+1+1+1+1)
                - (4+4)
                - EXEC_MAX
                - 32
                - 8 - 8];
} param_area_t;

typedef struct {
    char     magic[5];
    uint8_t  version;
    uint16_t footer_size;
    uint64_t param_offset;
    uint64_t payload_offset;
    uint64_t payload_size;
    uint8_t  pad[64 - (5+1+2+8+8+8)];
} footer_t;
#pragma pack(pop)

/* =========================
 * Utils
 * ========================= */
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static const char *bn(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static off_t file_size_fd(int fd) {
    off_t cur = lseek(fd, 0, SEEK_CUR);
    off_t end = lseek(fd, 0, SEEK_END);
    if (cur != (off_t)-1) lseek(fd, cur, SEEK_SET);
    return end;
}

static void ts_now(char out[32]) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    snprintf(out, 32, "%04d%02d%02d%02d%02d%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

/* =========================
 * Progress bar (stage-based)
 * ========================= */
static void progress_bar(const char *label, int percent) {
    const int width = 30;
    int filled = percent * width / 100;

    char line[128];
    int pos = 0;

    pos += snprintf(line + pos, sizeof(line) - pos, "\r[");

    for (int i = 0; i < width; i++) {
        line[pos++] = (i < filled) ? '=' : ' ';
    }

    pos += snprintf(line + pos, sizeof(line) - pos,
                    "] %3d%% %-12s", percent, label);

    while (pos < 120) {
        line[pos++] = ' ';
    }

    line[pos] = '\0';

    fputs(line, stderr);
    fflush(stderr);
}

static void progress_done(void) {
    fputc('\r', stderr);

    for (int i = 0; i < 120; i++) {
        fputc(' ', stderr);
    }

    fputc('\r', stderr);
    fputc('\n', stderr);

    fflush(stderr);
}

/* =========================
 * Cleanup keep *.log
 * ========================= */
static int cleanup_cb(const char *f, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb; (void)ftw;
    if (type == FTW_F) {
        size_t n = strlen(f);
        if (!(n >= 4 && strcmp(f + n - 4, ".log") == 0)) {
            unlink(f);
        }
    } else if (type == FTW_SL || type == FTW_SLN) {
        unlink(f);
    } else if (type == FTW_DP) {
        rmdir(f);
    }
    return 0;
}

static void cleanup_keep_logs(const char *dir) {
    nftw(dir, cleanup_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* =========================
 * Signal handler
 * ========================= */
static void on_signal(int sig) {
    if (g_in_install && g_tmpdir[0]) {
        fprintf(stderr, "\n[SFX] interrupted, cleaning up...\n");
        cleanup_keep_logs(g_tmpdir);
    }
    _exit(128 + sig);
}

/* =========================
 * Password prompt (no echo) - for -x
 * ========================= */
static int prompt_password_noecho(char *out, size_t outsz) {
    struct termios oldt, newt;

    if (tcgetattr(STDIN_FILENO, &oldt) != 0) return -1;
    newt = oldt;
    newt.c_lflag &= ~(ECHO);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) return -1;

    fprintf(stderr, "Password: ");
    fflush(stderr);

    if (!fgets(out, (int)outsz, stdin)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return -1;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fputc('\n', stderr);

    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

/* =========================
 * Filter OpenSSL warning lines (only those two)
 * Keep other stderr output.
 * ========================= */
static int is_kdf_deprecated_warning_line(const char *line) {
    if (!line) return 0;
    if (strstr(line, "WARNING : deprecated key derivation used") != NULL) return 1;
    if (strstr(line, "Using -iter or -pbkdf2 would be better") != NULL) return 1;
    return 0;
}

static void relay_stderr_filter(int rfd) {
    char buf[4096];
    char line[8192];
    size_t ln = 0;

    for (;;) {
        ssize_t n = read(rfd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (ln + 1 < sizeof(line)) line[ln++] = c;
            if (c == '\n' || ln + 1 >= sizeof(line)) {
                line[ln] = '\0';
                if (!is_kdf_deprecated_warning_line(line)) {
                    (void)write(STDERR_FILENO, line, ln);
                }
                ln = 0;
            }
        }
    }
    if (ln > 0) {
        line[ln] = '\0';
        if (!is_kdf_deprecated_warning_line(line)) {
            (void)write(STDERR_FILENO, line, ln);
        }
    }
}

/* =========================
 * MD5 via openssl dgst -md5
 * ========================= */
static int md5_hex_openssl(const char *in, char out[33]) {
    int pfd[2], p2c[2];
    if (pipe(pfd) || pipe(p2c)) return -1;

    pid_t p = fork();
    if (p == 0) {
        dup2(p2c[0], STDIN_FILENO);
        dup2(pfd[1], STDOUT_FILENO);
        close(p2c[0]); close(p2c[1]);
        close(pfd[0]); close(pfd[1]);
        execlp("openssl", "openssl", "dgst", "-md5", (char*)NULL);
        _exit(127);
    }
    if (p < 0) {
        close(pfd[0]); close(pfd[1]); close(p2c[0]); close(p2c[1]);
        return -1;
    }

    close(p2c[0]);
    close(pfd[1]);

    (void)write(p2c[1], in, strlen(in));
    close(p2c[1]);

    char buf[256];
    ssize_t n = read(pfd[0], buf, sizeof(buf) - 1);
    close(pfd[0]);

    int st = 0;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || n <= 0) return -1;

    buf[n] = '\0';
    char *hex = strrchr(buf, ' ');
    if (!hex) hex = strrchr(buf, '=');
    if (!hex) return -1;
    hex++;
    while (*hex == ' ') hex++;

    if (strlen(hex) < 32) return -1;
    for (int i = 0; i < 32; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) return -1;
        out[i] = (char)((c >= 'A' && c <= 'F') ? (c - 'A' + 'a') : c);
    }
    out[32] = '\0';
    return 0;
}

/* =========================
 * Param decode helpers
 * ========================= */
static void md5hex_to_bytes16(const char md5[33], uint8_t out16[16]) {
    for (int i = 0; i < 16; i++) {
        char a = md5[i*2], b = md5[i*2+1];
        uint8_t v1 = (a <= '9') ? (a - '0') : (a - 'a' + 10);
        uint8_t v2 = (b <= '9') ? (b - '0') : (b - 'a' + 10);
        out16[i] = (uint8_t)((v1 << 4) | v2);
    }
}

static void decode_pass_md5(const param_area_t *p, char out_md5[33]) {
    for (int i = 0; i < 32; i++) out_md5[i] = (char)(p->pass_md5_obf[i] ^ p->xor_mask);
    out_md5[32] = '\0';
}

static int decode_exec_path(const param_area_t *p, const char md5[33], char out_exec[EXEC_MAX+1]) {
    if (p->exec_len == 0 || p->exec_len > EXEC_MAX) return -1;
    uint8_t key[16];
    md5hex_to_bytes16(md5, key);
    for (uint32_t i = 0; i < p->exec_len; i++)
        out_exec[i] = (char)(p->exec_xor[i] ^ key[i % 16]);
    out_exec[p->exec_len] = '\0';
    return 0;
}

/* =========================
 * Footer / param read
 * ========================= */
static int read_footer(int fd, footer_t *f) {
    off_t end = file_size_fd(fd);
    if (end < (off_t)sizeof(*f)) return -1;
    if (lseek(fd, end - (off_t)sizeof(*f), SEEK_SET) == (off_t)-1) return -1;
    if (read(fd, f, sizeof(*f)) != (ssize_t)sizeof(*f)) return -1;
    if (memcmp(f->magic, FOOT_MAGIC, 5) != 0) return -1;
    if (f->version != 1) return -1;
    if (f->footer_size != sizeof(*f)) return -1;
    return 0;
}

static int read_param(int fd, const footer_t *f, param_area_t *p) {
    if (lseek(fd, (off_t)f->param_offset, SEEK_SET) == (off_t)-1) return -1;
    if (read(fd, p, sizeof(*p)) != (ssize_t)sizeof(*p)) return -1;
    if (memcmp(p->magic, PARAM_MAGIC, 5) != 0) return -1;
    if (p->version != PARAM_VERSION) return -1;
    if (!(p->flags & 1)) return -1;
    return 0;
}

/* =========================
 * Derive output filename (basename, strip suffix)
 * ========================= */
static void derive_output_name(const char *input, char out_name[PATH_MAX]) {
    snprintf(out_name, PATH_MAX, "%s", bn(input));
    size_t n = strlen(out_name);

    /* composite suffixes: longest first */
    if (n > 7 && strcmp(out_name + n - 7, ".tar.gz") == 0) out_name[n - 7] = '\0';
    else if (n > 8 && strcmp(out_name + n - 8, ".tar.bz2") == 0) out_name[n - 8] = '\0';
    else if (n > 7 && strcmp(out_name + n - 7, ".tar.xz") == 0) out_name[n - 7] = '\0';
    else if (n > 8 && strcmp(out_name + n - 8, ".tar.zst") == 0) out_name[n - 8] = '\0';
    else if (n > 4 && strcmp(out_name + n - 4, ".tgz") == 0) out_name[n - 4] = '\0';
    else if (n > 4 && strcmp(out_name + n - 4, ".tar") == 0) out_name[n - 4] = '\0';
    else if (n > 3 && strcmp(out_name + n - 3, ".gz") == 0) out_name[n - 3] = '\0';
    else if (n > 3 && strcmp(out_name + n - 3, ".xz") == 0) out_name[n - 3] = '\0';
    else if (n > 4 && strcmp(out_name + n - 4, ".bz2") == 0) out_name[n - 4] = '\0';
    else if (n > 4 && strcmp(out_name + n - 4, ".zst") == 0) out_name[n - 4] = '\0';
}

/* =========================
 * OpenSSL enc/dec (cross-version compatible)
 * -aes-256-cbc -salt -md md5 -pass pass:<md5(password)>
 * with stderr filter for the deprecated-KDF warning.
 * ========================= */
static int run_openssl_enc_common(int decrypt,
                                 const char *in_path,
                                 const char *pass_md5,
                                 const char *out_path) {
    int errpipe[2];
    if (pipe(errpipe) != 0) return -1;

    pid_t p = fork();
    if (p == 0) {
        dup2(errpipe[1], STDERR_FILENO);
        close(errpipe[0]);
        close(errpipe[1]);

        char passarg[80];
        snprintf(passarg, sizeof(passarg), "pass:%s", pass_md5);

        if (decrypt) {
            execlp("openssl", "openssl", "enc",
                   "-d",
                   "-aes-256-cbc",
                   "-salt",
                   "-md", "md5",
                   "-pass", passarg,
                   "-in", in_path,
                   "-out", out_path,
                   (char*)NULL);
        } else {
            execlp("openssl", "openssl", "enc",
                   "-aes-256-cbc",
                   "-salt",
                   "-md", "md5",
                   "-pass", passarg,
                   "-in", in_path,
                   "-out", out_path,
                   (char*)NULL);
        }
        _exit(127);
    }

    close(errpipe[1]);
    relay_stderr_filter(errpipe[0]);
    close(errpipe[0]);

    int st = 0;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    return 0;
}

static int openssl_encrypt_to_file(const char *in_path, const char *pass_md5, const char *out_enc) {
    DBG("openssl encrypt: in=%s out=%s", in_path, out_enc);
    return run_openssl_enc_common(0, in_path, pass_md5, out_enc);
}

static int openssl_decrypt_to_file(const char *in_enc, const char *pass_md5, const char *out_dec) {
    DBG("openssl decrypt: in=%s out=%s", in_enc, out_dec);
    return run_openssl_enc_common(1, in_enc, pass_md5, out_dec);
}

/* =========================
 * Dump payload from self to file
 * ========================= */
static int dump_payload_to_file(int self_fd, uint64_t off, uint64_t sz, const char *out_path) {
    if (lseek(self_fd, (off_t)off, SEEK_SET) == (off_t)-1) return -1;

    int out = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (out < 0) return -1;

    uint8_t buf[1 << 20];
    uint64_t left = sz;
    while (left > 0) {
        size_t chunk = (left > sizeof(buf)) ? sizeof(buf) : (size_t)left;
        ssize_t n = read(self_fd, buf, chunk);
        if (n <= 0) { close(out); return -1; }
        if (write(out, buf, (size_t)n) != n) { close(out); return -1; }
        left -= (uint64_t)n;
    }
    close(out);
    return 0;
}

/* =========================
 * Compression detect + tar extract (auto)
 * ========================= */
typedef enum { C_TAR, C_GZIP, C_XZ, C_BZIP2, C_ZSTD } comp_t;

static comp_t detect_comp(const uint8_t *h, size_t n) {
    if (n >= 2 && h[0] == 0x1F && h[1] == 0x8B) return C_GZIP;
    if (n >= 6 && h[0] == 0xFD && h[1] == 0x37 && h[2] == 0x7A &&
        h[3] == 0x58 && h[4] == 0x5A && h[5] == 0x00) return C_XZ;
    if (n >= 3 && h[0] == 'B' && h[1] == 'Z' && h[2] == 'h') return C_BZIP2;
    if (n >= 4 && h[0] == 0x28 && h[1] == 0xB5 && h[2] == 0x2F && h[3] == 0xFD) return C_ZSTD;
    return C_TAR;
}

static int tar_extract_auto(const char *dec_file, const char *dest_dir) {
    uint8_t hdr[16];
    int fd = open(dec_file, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, hdr, sizeof(hdr));
    close(fd);
    if (n <= 0) return -1;

    comp_t c = detect_comp(hdr, (size_t)n);
    const char *flag =
        (c == C_GZIP)  ? "xz" :
        (c == C_XZ)    ? "xJ" :
        (c == C_BZIP2) ? "xj" :
        (c == C_ZSTD)  ? "xZ" : "x";

    DBG("tar extract: comp=%s flag=%s dec=%s dest=%s",
        c==C_GZIP?"gzip":c==C_XZ?"xz":c==C_BZIP2?"bzip2":c==C_ZSTD?"zstd":"tar",
        flag, dec_file, dest_dir);

    pid_t p = fork();
    if (p == 0) {
        if (chdir(dest_dir) != 0) _exit(127);
        execlp("tar", "tar", flag, "-f", dec_file, (char*)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    return 0;
}

/* =========================
 * Find exec root
 * ========================= */
static int find_exec_root(const char *tmpdir, const char *exec_rel, char out_root[PATH_MAX]) {
    char direct[PATH_MAX];
    snprintf(direct, sizeof(direct), "%s/%s", tmpdir, exec_rel);
    if (access(direct, F_OK) == 0) {
        snprintf(out_root, PATH_MAX, "%s", tmpdir);
        return 0;
    }

    DIR *d = opendir(tmpdir);
    if (!d) return -1;

    struct dirent *e;
    int found = 0;
    char found_root[PATH_MAX] = {0};

    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;

        char cand_dir[PATH_MAX];
        snprintf(cand_dir, sizeof(cand_dir), "%s/%s", tmpdir, e->d_name);

        struct stat st;
        if (stat(cand_dir, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;

        char cand_exec[PATH_MAX];
        snprintf(cand_exec, sizeof(cand_exec), "%s/%s", cand_dir, exec_rel);
        if (access(cand_exec, F_OK) == 0) {
            found++;
            snprintf(found_root, sizeof(found_root), "%s", cand_dir);
            if (found > 1) break;
        }
    }
    closedir(d);

    if (found == 1) {
        snprintf(out_root, PATH_MAX, "%s", found_root);
        return 0;
    }
    return -1;
}

/* =========================
 * Run installer
 * ========================= */
static int run_exec(const char *root, const char *exec_rel) {
    DBG("exec: chdir=%s cmd=%s", root, exec_rel);
    if (chdir(root) != 0) return 1;

    pid_t p = fork();
    if (p == 0) {
        execl(exec_rel, exec_rel, (char*)NULL);
        execl("/bin/bash", "bash", exec_rel, (char*)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

/* =========================
 * Usage (no --debug shown)
 * ========================= */
static void usage_pack(void) {
    fprintf(stderr,
        "Usage (pack):\n"
        "  sfx --input <tar> --exec <path> --password <pw> [--output <dir>]\n");
}

/* =========================
 * main helpers
 * ========================= */
static int has_flag_x(int argc, char **argv) {
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "-x") == 0) return 1;
    return 0;
}

/* =========================
 * main
 * ========================= */
int main(int argc, char **argv) {
    /* signals */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGQUIT, on_signal);

    /* hidden debug */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) g_debug = 1;
    }

    char cwd[PATH_MAX] = {0};
    if (!getcwd(cwd, sizeof(cwd))) snprintf(cwd, sizeof(cwd), "%s", ".");

    char self_path[PATH_MAX] = {0};
    ssize_t r = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if (r <= 0) die("cannot resolve /proc/self/exe");
    self_path[r] = '\0';

    DBG("cwd=%s", cwd);
    DBG("self=%s", self_path);

    int self_fd = open(self_path, O_RDONLY);
    if (self_fd < 0) die("cannot open self");

    footer_t ft;
    int packed = (read_footer(self_fd, &ft) == 0);

    /* =========================
     * PACK MODE (no footer)
     * ========================= */
    if (!packed) {
        const char *input = NULL;
        const char *exec_rel = NULL;
        const char *password = NULL;
        const char *output_dir = NULL;

        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "--input") && i + 1 < argc) input = argv[++i];
            else if (!strcmp(argv[i], "--exec") && i + 1 < argc) exec_rel = argv[++i];
            else if (!strcmp(argv[i], "--password") && i + 1 < argc) password = argv[++i];
            else if (!strcmp(argv[i], "--output") && i + 1 < argc) output_dir = argv[++i];
        }

        if (!input || !exec_rel || !password) {
            usage_pack();
            close(self_fd);
            return 2;
        }

        /* validate output dir if given */
        if (output_dir) {
            struct stat st;
            if (stat(output_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
                die("output dir invalid: %s", output_dir);
            }
        }

        DBG("pack input=%s exec=%s output_dir=%s",
            input, exec_rel, output_dir ? output_dir : "(cwd)");

        /* pass_md5 = md5(password) */
        char pass_md5[33];
        if (md5_hex_openssl(password, pass_md5) != 0) die("md5(password) failed");

        /* encrypt input -> tmp enc */
        char tmp_enc[PATH_MAX];
        snprintf(tmp_enc, sizeof(tmp_enc), "/tmp/sfx_enc_%d.bin", getpid());
        if (openssl_encrypt_to_file(input, pass_md5, tmp_enc) != 0) {
            unlink(tmp_enc);
            die("openssl encrypt failed");
        }

        /* output path: basename stripped suffix */
        char out_name[PATH_MAX];
        derive_output_name(input, out_name);

        char final_path[PATH_MAX];
        if (output_dir) snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, out_name);
        else snprintf(final_path, sizeof(final_path), "%s/%s", cwd, out_name);

        DBG("pack output=%s", final_path);

        /* copy stub to output */
        int in = open(self_path, O_RDONLY);
        if (in < 0) die("open self failed");
        int out = open(final_path, O_CREAT | O_TRUNC | O_WRONLY, 0700);
        if (out < 0) die("open output failed: %s", final_path);

        uint8_t buf[1 << 20];
        ssize_t n;
        while ((n = read(in, buf, sizeof(buf))) > 0) {
            if (write(out, buf, (size_t)n) != n) die("write output failed");
        }
        close(in);

        off_t stub_end = file_size_fd(out);
        DBG("stub_end=%lld", (long long)stub_end);

        /* build param */
        param_area_t pa;
        memset(&pa, 0, sizeof(pa));
        memcpy(pa.magic, PARAM_MAGIC, 5);
        pa.version = PARAM_VERSION;
        pa.flags = 1;
        pa.xor_mask = 0x5A;

        for (int i = 0; i < 32; i++) pa.pass_md5_obf[i] = (uint8_t)(pass_md5[i] ^ pa.xor_mask);

        size_t elen = strlen(exec_rel);
        if (elen == 0 || elen > EXEC_MAX) die("--exec too long");
        pa.exec_len = (uint32_t)elen;

        uint8_t key16[16];
        md5hex_to_bytes16(pass_md5, key16);
        for (uint32_t i = 0; i < pa.exec_len; i++) pa.exec_xor[i] = (uint8_t)(exec_rel[i] ^ key16[i % 16]);

        pa.payload_offset = (uint64_t)stub_end + (uint64_t)PARAM_AREA_SIZE;

        int efd = open(tmp_enc, O_RDONLY);
        if (efd < 0) die("open tmp_enc failed");
        off_t encsz = file_size_fd(efd);
        close(efd);
        pa.payload_size = (uint64_t)encsz;

        /* append param */
        if (lseek(out, 0, SEEK_END) == (off_t)-1) die("seek output failed");
        if (write(out, &pa, sizeof(pa)) != (ssize_t)sizeof(pa)) die("append param failed");

        /* append payload */
        efd = open(tmp_enc, O_RDONLY);
        if (efd < 0) die("open tmp_enc failed");
        while ((n = read(efd, buf, sizeof(buf))) > 0) {
            if (write(out, buf, (size_t)n) != n) die("append payload failed");
        }
        close(efd);
        unlink(tmp_enc);

        /* footer */
        footer_t f;
        memset(&f, 0, sizeof(f));
        memcpy(f.magic, FOOT_MAGIC, 5);
        f.version = 1;
        f.footer_size = (uint16_t)sizeof(footer_t);
        f.param_offset = (uint64_t)stub_end;
        f.payload_offset = pa.payload_offset;
        f.payload_size = pa.payload_size;

        if (write(out, &f, sizeof(f)) != (ssize_t)sizeof(f)) die("append footer failed");
        close(out);

        chmod(final_path, 0755);
        fprintf(stderr, "[SFX] packed: %s\n", final_path);
        close(self_fd);
        return 0;
    }

    /* =========================
     * INSTALL / EXTRACT MODE
     * ========================= */
    DBG("install mode: payload_offset=%llu payload_size=%llu",
        (unsigned long long)ft.payload_offset, (unsigned long long)ft.payload_size);

    param_area_t pa;
    if (read_param(self_fd, &ft, &pa) != 0) die("invalid param area");

    char pass_md5[33];
    decode_pass_md5(&pa, pass_md5);

    char exec_rel[EXEC_MAX + 1];
    if (decode_exec_path(&pa, pass_md5, exec_rel) != 0) die("decode exec failed");

    int only_extract = has_flag_x(argc, argv);

    /* ---- -x: extract to cwd, no exec ---- */
    if (only_extract) {
        char inpw[256];

        /* 1) password no-echo */
        if (prompt_password_noecho(inpw, sizeof(inpw)) != 0) { close(self_fd); return 1; }

        char in_md5[33];
        if (md5_hex_openssl(inpw, in_md5) != 0) { close(self_fd); return 1; }
        if (strcmp(in_md5, pass_md5) != 0) { close(self_fd); return 1; }

        DBG("-x extract only to cwd=%s", cwd);

        char payload_pack[PATH_MAX];
        snprintf(payload_pack, sizeof(payload_pack), "./.sfx_payload_%d.pack", getpid());

        char payload_dec[PATH_MAX];
        snprintf(payload_dec, sizeof(payload_dec), "./.sfx_payload_%d.dec", getpid());

        /* 2) staged progress */
        progress_bar("Extracting", 10);
        if (dump_payload_to_file(self_fd, ft.payload_offset, ft.payload_size, payload_pack) != 0) {
            progress_done();
            unlink(payload_pack);
            unlink(payload_dec);
            close(self_fd);
            return 1;
        }
        progress_bar("Decrypting", 60);
        if (openssl_decrypt_to_file(payload_pack, pass_md5, payload_dec) != 0) {
            progress_done();
            unlink(payload_pack);
            unlink(payload_dec);
            close(self_fd);
            return 1;
        }
        progress_bar("Unpacking", 90);
        int rc = (tar_extract_auto(payload_dec, cwd) == 0) ? 0 : 1;
        progress_bar("Done", 100);
        progress_done();

        unlink(payload_pack);
        unlink(payload_dec);
        close(self_fd);
        return rc;
    }

    /* ---- normal install: extract to /tmp/<self>_<ts> ---- */
    char ts[32];
    ts_now(ts);

    char tmpdir[PATH_MAX];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/%s_%s", bn(self_path), ts);

    if (mkdir(tmpdir, 0700) != 0) {
        close(self_fd);
        return 1;
    }

    /* mark install state for signal cleanup */
    snprintf(g_tmpdir, sizeof(g_tmpdir), "%s", tmpdir);
    g_in_install = 1;

    DBG("tmpdir=%s", tmpdir);

    char payload_pack[PATH_MAX];
    snprintf(payload_pack, sizeof(payload_pack), "%s/payload.pack", tmpdir);

    char payload_dec[PATH_MAX];
    snprintf(payload_dec, sizeof(payload_dec), "%s/payload.dec", tmpdir);

    
    /* staged progress */
    progress_bar("Extracting", 10);
    if (dump_payload_to_file(self_fd, ft.payload_offset, ft.payload_size, payload_pack) != 0) {
        progress_done();
        cleanup_keep_logs(tmpdir);
        close(self_fd);
        return 1;
    }

    progress_bar("Decrypting", 60);
    if (openssl_decrypt_to_file(payload_pack, pass_md5, payload_dec) != 0) {
        progress_done();
        cleanup_keep_logs(tmpdir);
        close(self_fd);
        return 1;
    }

    progress_bar("Unpacking", 90);
    if (tar_extract_auto(payload_dec, tmpdir) != 0) {
        progress_done();
        cleanup_keep_logs(tmpdir);
        close(self_fd);
        return 1;
    }

    progress_bar("Done", 100);
    progress_done();

    /* IMPORTANT: remove SFX temp files before exec */
    DBG("remove temp files before exec: %s , %s", payload_pack, payload_dec);
    unlink(payload_pack);
    unlink(payload_dec);

    /* locate exec root */
    char root[PATH_MAX];
    if (find_exec_root(tmpdir, exec_rel, root) != 0) {
        fprintf(stderr, "install program not found: %s\n", exec_rel);
        cleanup_keep_logs(tmpdir);
        close(self_fd);
        return 1;
    }

    int rc = run_exec(root, exec_rel);

    cleanup_keep_logs(tmpdir);
    close(self_fd);

    g_in_install = 0;
    g_tmpdir[0] = '\0';
    return rc;
}
