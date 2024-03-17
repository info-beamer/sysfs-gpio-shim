/*
 *  Copyright (c) 2024 Florian Wesch <fw@dividuum.de>
 *
 *  (See LICENSE)
*/

#define VERSION "0.1"

#include <gpiod.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/epoll.h>

#define FUSE_USE_VERSION 31
#include <fuse.h>

#include "uthash.h"

// How many lines we expect the GPIO chip to expose.
#define NUM_PINS 54

#define v(...) do { fprintf(stderr, __VA_ARGS__); } while (0)

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("CRITICAL ERROR: ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
#ifdef DEBUG
    abort();
#else
    exit(1);
#endif
}

void *xmalloc(size_t size) {
    void *ptr = calloc(1, size);
    if (!ptr) die("cannot malloc");
    return ptr;
}

#define FILE2FH(p) ((uint64_t)(uintptr_t)(p))
#define FH2FILE(u) ((gpio_file_t*)(uintptr_t)(u))

#define str_equal(a, b) (strcmp(a, b) == 0)
#define str_startswith(a, b) (strncmp(a, b, sizeof(b)-1) == 0)
int str_buf_equal(const char *buf, size_t size, const char *value) {
    size_t value_len = strlen(value);
    if (size < value_len)
        return 0;
    size_t buf_len = 0;
    for (; buf_len < size; buf_len++) {
        if (buf[buf_len] == '\0' ||
            buf[buf_len] == '\n'
        )
            break;
    }
    if (buf_len != value_len)
        return 0;
    return strncmp(buf, value, buf_len) == 0;
}

static inline int min(int a, int b) {
    return a < b ? a : b;
}

typedef struct pin_s pin_t;

static void edge_detect_add_pin(pin_t *);
static void edge_detect_remove_pin(pin_t *);
static void edge_detect_setup();


/////////////////////////////////////////////////////////////////////

static struct gpiod_chip *gpio_chip = NULL;

static struct gpiod_chip *detect_chip() {
    DIR *dev_dir = opendir("/dev/");
    if (!dev_dir)
        return NULL;

    struct dirent *f;
    struct gpiod_chip *chip = NULL;
    while ((f = readdir(dev_dir)) != NULL) {
        char path[NAME_MAX + 6];
        snprintf(path, sizeof(path), "/dev/%s", f->d_name);
        struct stat sb;
        if (lstat(path, &sb) != 0 || S_ISLNK(sb.st_mode))
            continue;
        if (!gpiod_is_gpiochip_device(path))
            continue;
        chip = gpiod_chip_open(path);
        if (!chip)
            continue;
        struct gpiod_chip_info *info = gpiod_chip_get_info(chip);
        if (!info) {
            gpiod_chip_close(chip);
            chip = NULL;
            continue;
        }
        const char *label = gpiod_chip_info_get_label(info);
        // http://git.munts.com/muntsos/doc/AppNote11-link-gpiochip.pdf
        if (!str_equal(label, "pinctrl-bcm2835") && // Pi 1 to 3
            !str_equal(label, "pinctrl-bcm2711") && // Pi 4
            !str_equal(label, "pinctrl-rp1")        // Pi 5
        ) {
            gpiod_chip_close(chip);
            chip = NULL;
            continue;
        }
        if (gpiod_chip_info_get_num_lines(info) != NUM_PINS)
            die("unexpected number of lines. change NUM_PINS and recompile");
        // v("Using chip %s (%s)\n", path, gpiod_chip_info_get_label(info));
        gpiod_chip_info_free(info);
        break;
    }
    closedir(dev_dir);
    return chip;
}

/////////////////////////////////////////////////////////////////////

typedef struct {
    void *waiter_key;
    struct fuse_pollhandle *ph;
    int edge_detected;
    UT_hash_handle hh;
} pin_edge_wait_t;

struct pin_s {
    unsigned int n;
    int in_use;
    enum gpiod_line_direction direction;
    enum gpiod_line_edge edge;
    int active_low;
    pthread_mutex_t lock;
    struct gpiod_line_request *gpio_line_request;
    pin_edge_wait_t *edge_waiters;
};

static pin_t pins[NUM_PINS] = {0};

typedef struct {
    const char *suffix;
    pin_t *pin;
    int buf_fill;
    char buf[16];
} gpio_file_t;

static gpio_file_t *gpio_file(const char *path) {
    if (!str_startswith(path, "/gpio"))
        return NULL;
    const char *p_start = path + 5;
    char *p_end = NULL;
    long int p = strtol(p_start, &p_end, 10);
    if (errno == ERANGE) {
        return NULL;
    } else if (errno == EINVAL) {
        return NULL;
    } else if (p_start == p_end) {
        return NULL;
    } else if (p < 0 || p >= NUM_PINS) {
        return NULL;
    }
    pin_t *pin = &pins[p];
    gpio_file_t *file = NULL;
    pthread_mutex_lock(&pin->lock);
    if (!pin->in_use)
        goto out;
    const char *suffix = NULL;
    if (*p_end == '\0') {
        suffix = NULL;
    } else if (*p_end != '/') {
        goto out;
    } else {
        suffix = p_end;
    }
    file = xmalloc(sizeof(gpio_file_t));
    file->suffix = suffix ? strdup(suffix) : NULL;
    file->pin = pin;
out:
    pthread_mutex_unlock(&pin->lock);
    return file;
}

static void gpio_file_free(gpio_file_t *file) {
    assert(file);
    if (file->suffix)
        free((void*)file->suffix);
    free(file);
}

static pin_t *pin_from_num(const char *buf, size_t size) {
    if (size > 10)
        return NULL;
    char spec[8];
    snprintf(spec, sizeof(spec), "%%%dd", (int)size);
    int p;
    int s = sscanf(buf, spec, &p);
    if (s != 1)
        return NULL;
    if (p < 0 || p >= NUM_PINS)
        return NULL;
    return &pins[p];
}

static int pin_reconfigure_line(pin_t *pin) {
    struct gpiod_line_settings *settings = gpiod_line_settings_new();
    if (!settings)
        die("cannot alloc settings");

    gpiod_line_settings_set_direction(settings, pin->direction);
    gpiod_line_settings_set_active_low(settings, pin->active_low);
    // gpiod_line_settings_set_bias(settings, GPIOD_LINE_BIAS_PULL_UP);
    if (pin->direction == GPIOD_LINE_DIRECTION_INPUT) {
        gpiod_line_settings_set_debounce_period_us(settings, 300);
        gpiod_line_settings_set_event_clock(settings, GPIOD_LINE_CLOCK_MONOTONIC);
        gpiod_line_settings_set_edge_detection(settings, pin->edge);
    }

    struct gpiod_line_config *line_cfg = gpiod_line_config_new();
    if (!line_cfg)
        die("cannot alloc line config");

    if (gpiod_line_config_add_line_settings(
        line_cfg, &pin->n, 1, settings
    ))
        die("cannot add settings");

    if (!pin->gpio_line_request) {
        struct gpiod_request_config *req_cfg = gpiod_request_config_new();
        if (!req_cfg)
            die("cannot alloc request config");
        gpiod_request_config_set_consumer(req_cfg, "sysfs-gpio-shim");
        pin->gpio_line_request = gpiod_chip_request_lines(
            gpio_chip, req_cfg, line_cfg
        );
        gpiod_request_config_free(req_cfg);
    } else {
        if (gpiod_line_request_reconfigure_lines(
            pin->gpio_line_request, line_cfg
        ))
            pin->gpio_line_request = NULL;
    }
    gpiod_line_config_free(line_cfg);
    gpiod_line_settings_free(settings);
    return !!pin->gpio_line_request;
}

static int pin_setup(pin_t *pin) {
    pthread_mutex_lock(&pin->lock);
    assert(!pin->in_use);

    pin->direction = GPIOD_LINE_DIRECTION_INPUT;
    pin->edge = GPIOD_LINE_EDGE_NONE;
    pin->active_low = 0;
    pin->gpio_line_request = NULL;
    if (!pin_reconfigure_line(pin)) {
        pthread_mutex_unlock(&pin->lock);
        return 0;
    }

    pin->in_use = 1;
    pin->edge_waiters = NULL;
    pthread_mutex_unlock(&pin->lock);
    return 1;
}

static void pin_release(pin_t *pin) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    if (pin->edge != GPIOD_LINE_EDGE_NONE)
        edge_detect_remove_pin(pin);
    gpiod_line_request_release(pin->gpio_line_request);
    pin->in_use = 0;
    pin_edge_wait_t *waiter, *tmp;
    HASH_ITER(hh, pin->edge_waiters, waiter, tmp) {
        if (waiter->ph)
            fuse_pollhandle_destroy(waiter->ph);
        HASH_DEL(pin->edge_waiters, waiter);
        free(waiter);
    }
    assert(pin->edge_waiters == NULL);
    pthread_mutex_unlock(&pin->lock);
}

static void pin_set_dir_in(pin_t *pin) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    if (pin->direction != GPIOD_LINE_DIRECTION_INPUT) {
        pin->direction = GPIOD_LINE_DIRECTION_INPUT;
        pin_reconfigure_line(pin);
    }
    pthread_mutex_unlock(&pin->lock);
}

static void pin_set_dir_out(pin_t *pin, int initial_value) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    if (pin->direction != GPIOD_LINE_DIRECTION_OUTPUT) {
        pin->direction = GPIOD_LINE_DIRECTION_OUTPUT;
        pin_reconfigure_line(pin);
        gpiod_line_request_set_value(
            pin->gpio_line_request, pin->n, initial_value
        );
    }
    pthread_mutex_unlock(&pin->lock);
}

static void pin_set_edge(pin_t *pin, enum gpiod_line_edge edge) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    if (pin->edge != edge) {
        if (pin->edge != GPIOD_LINE_EDGE_NONE)
            edge_detect_remove_pin(pin);
        pin->edge = edge;
        pin_reconfigure_line(pin);
        if (pin->edge != GPIOD_LINE_EDGE_NONE)
            edge_detect_add_pin(pin);
    }
    pthread_mutex_unlock(&pin->lock);
}

static void pin_set_active_low(pin_t *pin, int active_low) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    if (pin->active_low != active_low) {
        pin->active_low = active_low;
        pin_reconfigure_line(pin);
    }
    pthread_mutex_unlock(&pin->lock);
}

static void pin_set_value(pin_t *pin, int value) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    gpiod_line_request_set_value(
        pin->gpio_line_request, pin->n, value
    );
    pthread_mutex_unlock(&pin->lock);
}

static int pin_get_value(pin_t *pin) {
    pthread_mutex_lock(&pin->lock);
    assert(pin->in_use);
    int value = gpiod_line_request_get_value(
        pin->gpio_line_request, pin->n
    );
    pthread_mutex_unlock(&pin->lock);
    return value;
}

static int pin_poll_edge(
    pin_t *pin, void *waiter_key, struct fuse_pollhandle *ph
) {
    pthread_mutex_lock(&pin->lock);
    pin_edge_wait_t *waiter = NULL;
    HASH_FIND_PTR(pin->edge_waiters, &waiter_key, waiter);
    if (!waiter) {
        waiter = xmalloc(sizeof(pin_edge_wait_t));
        waiter->waiter_key = waiter_key;
        waiter->edge_detected = 0;
        HASH_ADD_PTR(pin->edge_waiters, waiter_key, waiter);
    } else if (waiter->edge_detected) {
        HASH_DEL(pin->edge_waiters, waiter);
        assert(!waiter->ph);
        free(waiter);
        pthread_mutex_unlock(&pin->lock);
        return 1;
    }
    if (waiter->ph)
        fuse_pollhandle_destroy(waiter->ph);
    waiter->ph = ph;
    pthread_mutex_unlock(&pin->lock);
    return 0;
}

static void pin_release_poll(
    pin_t *pin, void *waiter_key
) {
    pthread_mutex_lock(&pin->lock);
    pin_edge_wait_t *waiter = NULL;
    HASH_FIND_PTR(pin->edge_waiters, &waiter_key, waiter);
    if (waiter) {
        if (waiter->ph)
            fuse_pollhandle_destroy(waiter->ph);
        HASH_DEL(pin->edge_waiters, waiter);
        free(waiter);
    }
    pthread_mutex_unlock(&pin->lock);
}

static void pin_edge_detected_locked(pin_t *pin) {
    pin_edge_wait_t *waiter, *tmp;
    HASH_ITER(hh, pin->edge_waiters, waiter, tmp) {
        if (waiter->ph) {
            waiter->edge_detected = 1;
            fuse_notify_poll(waiter->ph);
            fuse_pollhandle_destroy(waiter->ph);
            waiter->ph = NULL;
        }
    }
}

static int gpio_getattr(
    const char *path, struct stat *stbuf,
    struct fuse_file_info *fi
) {
    memset(stbuf, 0, sizeof(struct stat));
    if (str_equal(path, "/")) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    if (str_equal(path, "/export")) {
        stbuf->st_mode = S_IFREG | 0220;
        stbuf->st_nlink = 1;
        stbuf->st_size = 4096;
        return 0;
    }

    if (str_equal(path, "/unexport")) {
        stbuf->st_mode = S_IFREG | 0220;
        stbuf->st_nlink = 1;
        stbuf->st_size = 4096;
        return 0;
    }

    gpio_file_t *file = gpio_file(path);
    if (!file)
        return -ENOENT;
    if (!file->suffix) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0660;
        stbuf->st_nlink = 1;
        stbuf->st_size = 4096;
    }
    gpio_file_free(file);
    return 0;
}

static int gpio_readdir(
    const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi,
    enum fuse_readdir_flags flags
) {
    if (str_equal(path, "/")) {
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);
        filler(buf, "export", NULL, 0, 0);
        filler(buf, "unexport", NULL, 0, 0);
        for (int p = 0; p < NUM_PINS; p++) {
            pin_t *pin = &pins[p];
            if (!pin->in_use)
                continue;
            char name[10];
            snprintf(name, sizeof(name), "gpio%d", p);
            filler(buf, name, NULL, 0, 0);
        }
        return 0;
    }

    gpio_file_t *file = gpio_file(path);
    if (!file)
        return -ENOENT;

    if (file->suffix) {
        gpio_file_free(file);
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, "direction", NULL, 0, 0);
    filler(buf, "value", NULL, 0, 0);
    filler(buf, "edge", NULL, 0, 0);
    filler(buf, "active_low", NULL, 0, 0);
    gpio_file_free(file);
    return 0;
}

static int gpio_open(
    const char *path, struct fuse_file_info *fi
) {
    if (str_equal(path, "/export")) {
        if ((fi->flags & O_ACCMODE) != O_WRONLY)
            return -EACCES;
        return 0;
    } else if (str_equal(path, "/unexport")) {
        if ((fi->flags & O_ACCMODE) != O_WRONLY)
            return -EACCES;
        return 0;
    }

    gpio_file_t *file = gpio_file(path);
    if (!file)
        return -ENOENT;

    if (!file->suffix) {
        gpio_file_free(file);
        return -ENOENT;
    }

    if (!str_equal(file->suffix, "/direction") &&
        !str_equal(file->suffix, "/value") &&
        !str_equal(file->suffix, "/edge") &&
        !str_equal(file->suffix, "/active_low"))
    {
        gpio_file_free(file);
        return -ENOENT;
    }

    fi->fh = FILE2FH(file);
    fi->direct_io = 1;
    return 0;
}

static int gpio_release(
    const char *path, struct fuse_file_info *fi
) {
    if (fi->fh) {
        gpio_file_t *file = FH2FILE(fi->fh);
        assert(file->suffix);
        pin_release_poll(file->pin, file);
        gpio_file_free(file);
    }
    return 0;
}

#define buf_update_maybe(file, offset, fmt, value) do {                      \
    if (file->buf_fill == 0 || offset == 0) {                                \
        file->buf_fill = snprintf(file->buf, sizeof(file->buf), fmt, value); \
    }                                                                        \
} while (0)

static int gpio_read(
    const char *path, char *buf, size_t size,
    off_t offset, struct fuse_file_info *fi
) {
    if (!fi->fh)
        return -EINVAL;
    gpio_file_t *file = FH2FILE(fi->fh);
    assert(file->suffix);

    if (str_equal(file->suffix, "/value")) {
        buf_update_maybe(file, offset, "%d\n",
            pin_get_value(file->pin)
        );
    } else if (str_equal(file->suffix, "/direction")) {
        buf_update_maybe(file, offset, "%s\n",
            file->pin->direction == GPIOD_LINE_DIRECTION_INPUT ? "in" : "out"
        );
    } else if (str_equal(file->suffix, "/edge")) {
        buf_update_maybe(file, offset, "%s\n",
            file->pin->edge == GPIOD_LINE_EDGE_NONE    ? "none" :
            file->pin->edge == GPIOD_LINE_EDGE_RISING  ? "rising" :
            file->pin->edge == GPIOD_LINE_EDGE_FALLING ? "falling" :
                                                         "both"
        );
    } else if (str_equal(file->suffix, "/active_low")) {
        buf_update_maybe(file, offset, "%d\n",
            file->pin->active_low
        );
    } else {
        __builtin_unreachable();
    }
    assert(file->buf_fill > 0);
    if (offset >= file->buf_fill)
        return 0;
    int readable = min(size, file->buf_fill - offset);
    memcpy(buf, file->buf + offset, readable);
    return readable;
}

static int gpio_write(
    const char *path, const char *buf, size_t size,
    off_t offset, struct fuse_file_info *fi
) {
    if (str_equal(path, "/export")) {
        pin_t *pin = pin_from_num(buf, size);
        if (!pin)
            return -EINVAL;
        if (!pin->in_use && !pin_setup(pin))
            return -EBUSY;
        return size;
    }

    if (str_equal(path, "/unexport")) {
        pin_t *pin = pin_from_num(buf, size);
        if (!pin)
            return -EINVAL;
        if (!pin->in_use)
            return -EINVAL;
        pin_release(pin);
        return size;
    }

    if (!fi->fh)
        return -EINVAL;
    gpio_file_t *file = FH2FILE(fi->fh);
    assert(file->suffix);

    if (str_equal(file->suffix, "/value")) {
        if (file->pin->direction != GPIOD_LINE_DIRECTION_OUTPUT)
            return -EPERM;
        if (str_buf_equal(buf, size, "0")) {
            pin_set_value(file->pin, 0);
        } else { // non-zero. lol
            pin_set_value(file->pin, 1);
        }
    } else if (str_equal(file->suffix, "/direction")) {
        if (str_buf_equal(buf, size, "out")) {
            pin_set_dir_out(file->pin, 0);
        } else if (str_buf_equal(buf, size, "low")) {
            pin_set_dir_out(file->pin, 0);
        } else if (str_buf_equal(buf, size, "high")) {
            pin_set_dir_out(file->pin, 1);
        } else if (str_buf_equal(buf, size, "in")) {
            pin_set_dir_in(file->pin);
        } else {
            return -EINVAL;
        }
    } else if (str_equal(file->suffix, "/edge")) {
        if (str_buf_equal(buf, size, "none")) {
            pin_set_edge(file->pin, GPIOD_LINE_EDGE_NONE);
        } else if (str_buf_equal(buf, size, "rising")) {
            pin_set_edge(file->pin, GPIOD_LINE_EDGE_RISING);
        } else if (str_buf_equal(buf, size, "falling")) {
            pin_set_edge(file->pin, GPIOD_LINE_EDGE_FALLING);
        } else if (str_buf_equal(buf, size, "both")) {
            pin_set_edge(file->pin, GPIOD_LINE_EDGE_BOTH);
        } else {
            return -EINVAL;
        }
    } else if (str_equal(file->suffix, "/active_low")) {
        if (str_buf_equal(buf, size, "0")) {
            pin_set_active_low(file->pin, 0);
        } else { // non-zero. lol
            pin_set_active_low(file->pin, 1);
        }
    }
    return size;
}

static int gpio_poll(
    const char *path, struct fuse_file_info *fi,
    struct fuse_pollhandle *ph, unsigned *reventsp
) {
    if (!fi->fh)
        return -EINVAL;
    gpio_file_t *file = FH2FILE(fi->fh);
    assert(file->suffix);

    if (str_equal(file->suffix, "/value")) {
        if (pin_poll_edge(file->pin, file, ph))
            *reventsp |= POLLPRI;
        return 0;
    }
    return -EACCES;
}

static void *gpio_init(
    struct fuse_conn_info *conn,
    struct fuse_config *cfg
) {
    edge_detect_setup();
    return NULL;
}

static const struct fuse_operations gpio_oper = {
    .init    = gpio_init,
    .getattr = gpio_getattr,
    .readdir = gpio_readdir,
    .open    = gpio_open,
    .release = gpio_release,
    .read    = gpio_read,
    .write   = gpio_write,
    .poll    = gpio_poll,
};

/////////////////////////////////////////////////////////////////////

static int epoll_fd;
static pthread_t edge_detect_thread;

#define MAX_EPOLL_EVENTS 10
#define MAX_EDGE_EVENTS  32

static void *edge_detect_loop(void *data) {
    struct gpiod_edge_event_buffer *edge_events = \
        gpiod_edge_event_buffer_new(MAX_EDGE_EVENTS);
    if (!edge_events)
        die("no mem");
    while (1) {
        struct epoll_event epoll_events[MAX_EPOLL_EVENTS];
        int num_epolls = epoll_wait(epoll_fd, epoll_events, MAX_EPOLL_EVENTS, -1);
        if (num_epolls == -1) {
            if (errno == EINTR)
                continue;
            die("epoll failed");
        }
        for (int i = 0; i < num_epolls; i++) {
            pin_t *pin = epoll_events[i].data.ptr;
            pthread_mutex_lock(&pin->lock);
            if (!pin->in_use) {
                pthread_mutex_unlock(&pin->lock);
                continue;
            }
            // XXX: for unknown reasons this read seems to read a buffer
            // of the right size but completely filled with zeros. The
            // resulting gpiod_edge_events are useless as a result.
            // Not sure why that is. It doesn't really matter for what
            // the code does with the events, but if anyone knowns what's
            // going on, please get in contact.
            int num_edges = gpiod_line_request_read_edge_events(
                pin->gpio_line_request, edge_events, MAX_EDGE_EVENTS
            );
            if (num_edges < 0)
                die("edge buf fail");
            for (int j = 0; j < num_edges; j++) {
                struct gpiod_edge_event *edge_event = \
                    gpiod_edge_event_buffer_get_event(edge_events, j);
                if (!edge_event)
                    die("event fetch fail");
                // if (gpiod_edge_event_get_event_type(edge_event) == GPIOD_EDGE_EVENT_RISING_EDGE) {
                //     v("rising\n");
                // } else {
                //     v("falling\n");
                // }
                pin_edge_detected_locked(pin);
            }
            pthread_mutex_unlock(&pin->lock);
        }
    }
    return NULL;
}

static void edge_detect_add_pin(pin_t *pin) {
    int pin_fd = gpiod_line_request_get_fd(pin->gpio_line_request);
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = pin;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pin_fd, &ev) == -1)
        die("cannot epoll_ctl");
}

static void edge_detect_remove_pin(pin_t *pin) {
    int pin_fd = gpiod_line_request_get_fd(pin->gpio_line_request);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pin_fd, NULL) == -1)
        die("cannot epoll_ctl");
}

static void edge_detect_setup() {
    epoll_fd = epoll_create1(0);
    if (pthread_create(&edge_detect_thread, NULL, edge_detect_loop, NULL) != 0)
        die("cannot start thread\n");
}

int main(int argc, char **argv) {
    gpio_chip = detect_chip();
    if (!gpio_chip)
        die("cannot detect GPIO chip to use");
    for (int p = 0; p < NUM_PINS; p++) {
        pins[p].n = p;
        pthread_mutex_init(&pins[p].lock, NULL);
    }
    return fuse_main(argc, argv, &gpio_oper, NULL);
}
