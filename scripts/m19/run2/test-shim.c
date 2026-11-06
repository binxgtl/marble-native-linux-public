/* Driver for xorg-shim.c on the fake libdrm. Never staged. Modes:
 *   filter     print what drmModeGetConnector and drmModeGetConnectorCurrent return
 *   null-call  install its own SIGSEGV handler, as Xorg does, then call a NULL function pointer
 *   null-read  the same, then read address 0 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct fake_connector {
    uint32_t connector_id, encoder_id, connector_type, connector_type_id;
    int connection;
    uint32_t mm_width, mm_height;
    int subpixel, count_modes;
    void *modes;
    int count_props;
    uint32_t *props;
    uint64_t *prop_values;
    int count_encoders;
    uint32_t *encoders;
};

struct fake_connector *drmModeGetConnector(int fd, uint32_t id);
struct fake_connector *drmModeGetConnectorCurrent(int fd, uint32_t id);
void drmModeFreeConnector(struct fake_connector *c);

static void own_handler(int number)
{
    static const char text[] = "own-handler\n";
    ssize_t put = write(1, text, sizeof(text) - 1);
    (void)put;
    _exit(100 + number);
}

static void print(const char *name, struct fake_connector *c)
{
    printf("%s count %d\n", name, c->count_props);
    for (int i = 0; i < c->count_props; i++)
        printf("%s prop %u %llu\n", name, c->props[i], (unsigned long long)c->prop_values[i]);
    drmModeFreeConnector(c);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2)
        return 64;
    if (!strcmp(argv[1], "filter")) {
        print("get", drmModeGetConnector(3, 42));
        print("current", drmModeGetConnectorCurrent(3, 43));
        return 0;
    }
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = own_handler;
    printf("installed %d\n", sigaction(SIGSEGV, &act, NULL));
    if (!strcmp(argv[1], "null-call")) {
        void (*volatile call)(void) = NULL;
        call();
    } else if (!strcmp(argv[1], "null-read")) {
        volatile int *volatile pointer = NULL;
        printf("%d\n", *pointer);
    }
    return 65;
}
