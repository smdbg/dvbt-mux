/* SPDX-License-Identifier: GPL-2.0-only */
/* DVB VBR remultiplexer. No codec decoding, software stuffing or per-packet
 * sleep. One poll loop owns all PSI, queues and continuity counters. */
#include "eit_forward.h"
#include "json.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <iconv.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define MAX_INPUTS 64
#define MAX_PID 8192
#define SECTION_MAX 4096
#define CAT_MAX 65536
#define READ_BATCH 16
#define UDP_SIZE 65536
#define ES 1
#define PCR 2
#define ECM 4
#define EMM 8
struct mux;
struct assembler {
  uint8_t data[SECTION_MAX], previous[188];
  size_t used, need;
  int cc, valid;
};
struct part {
  uint8_t *data;
  size_t size;
};
struct table {
  struct part part[256];
  int version, last, extension, initialized;
};
struct input {
  struct mux *m;
  int index, fd, enabled, ready;
  char id[96], url[128], interface[INET_ADDRSTRLEN], name[1024], provider[1024],
      emm_group[96];
  uint8_t encoded_name[256], encoded_provider[256];
  size_t encoded_name_size, encoded_provider_size;
  uint16_t requested_sid, input_sid, pmt_pid, service_id, output_pmt, lcn;
  uint8_t service_type;
  int scrambled;
  struct sockaddr_in address;
  uint16_t map[MAX_PID];
  uint8_t roles[MAX_PID], map_kind[MAX_PID];
  uint16_t emm_caid, emm_input_pid;
  uint64_t last_payload;
  struct assembler pat_asm, pmt_asm, cat_asm;
  EIT_FORWARD eit;
  struct table pat_table, cat_table;
  uint8_t pmt_candidate[1024], pmt[1024];
  size_t pmt_candidate_size, pmt_size;
  uint8_t *cat_candidate, *cat;
  size_t cat_candidate_size, cat_size;
  uint64_t received, forwarded, invalid, last_received, last_psi_error;
};
struct shared_emm {
  char group[96];
  uint16_t caid, pid;
  uint8_t private_data[251];
  size_t private_size;
  int owner;
  uint64_t last;
};
struct nit_peer {
  uint16_t tsid, onid;
  int frequency_khz, bandwidth, modulation, fec, guard, transmission;
  uint16_t sid[MAX_INPUTS], lcn[MAX_INPUTS];
  size_t count;
};
struct mux {
  struct nit_peer peers[32];
  size_t peer_count;
  struct input inputs[MAX_INPUTS];
  size_t count;
  uint16_t network_id, tsid, onid;
  char network_name[1024], provider_name[1024], country[4], codepage[32];
  uint8_t encoded_network[256];
  size_t encoded_network_size;
  int utc_offset, frequency_khz, bandwidth, modulation, fec, guard,
      transmission;
  uint64_t capacity;
  int version, nit_version;
  uint8_t *queue;
  size_t queue_size, queue_head, queue_used;
  uint8_t cc[MAX_PID];
  bool used_pid[MAX_PID];
  uint16_t next_pid;
  struct shared_emm shared[256];
  size_t shared_count;
  uint64_t input_packets, output_bytes, dropped, invalid, errors, null_dropped,
      sequence;
  uint64_t started, status_at, status_bytes, psi_at, si_at, time_at, max_queue;
  char status_path[1024];
  int failed;
};
static volatile sig_atomic_t stopping;
static void stop_handler(int s) {
  (void)s;
  stopping = 1;
}
static uint16_t u16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void w16(uint8_t *p, unsigned v) {
  p[0] = v >> 8;
  p[1] = v;
}
static uint64_t clock_ms(clockid_t id) {
  struct timespec t;
  clock_gettime(id, &t);
  return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static uint64_t now_ms(void) { return clock_ms(CLOCK_MONOTONIC); }
static void error(struct mux *m, const char *text) {
  m->errors++;
  fprintf(stderr, "dvb-mux: %s\n", text);
}
static void input_error(struct input *in, const char *text) {
  in->m->errors++;
  uint64_t now = now_ms();
  if (!in->last_psi_error || now - in->last_psi_error >= 5000) {
    fprintf(stderr, "dvb-mux: input %s: %s\n", in->id, text);
    in->last_psi_error = now;
  }
}
static int cfg_string(struct json *j, int obj, const char *key, char *dst,
                      size_t cap, const char *fallback) {
  int t = json_get(j, obj, key);
  if (t < 0) {
    if (strlen(fallback) >= cap)
      return -1;
    strcpy(dst, fallback);
    return 0;
  }
  int result = json_string(j, t, dst, cap);
  if (result)
    dst[0] = 0;
  return result;
}
static long long cfg_int(struct json *j, int obj, const char *key,
                         long long fallback, long long min, long long max,
                         int *bad) {
  int t = json_get(j, obj, key);
  long long v = fallback;
  if (t >= 0 && json_integer(j, t, &v))
    *bad = 1;
  if (v < min || v > max)
    *bad = 1;
  return v;
}
static int choice(const char *v, const char *const *choices, size_t count) {
  for (size_t i = 0; i < count; i++)
    if (!strcmp(v, choices[i]))
      return (int)i;
  return -1;
}
/* JSON always contains UTF-8. Convert only our generated names once at config
 * load; input EIT descriptors and their own character selectors are untouched.
 * No transliteration, substitution or byte truncation is permitted. */
static int encode_text(const struct mux *m, const char *name, const char *text,
                       uint8_t encoded[256], size_t *encoded_size) {
  const char *target = m->codepage;
  size_t prefix = 1;
  if (!strcmp(target, "ISO-6937")) {
    target = "ISO_6937";
    prefix = 0;
  } else {
    encoded[0] = !strcmp(target, "ISO-8859-5") ? 0x01 : 0x15;
  }
  iconv_t converter = iconv_open(target, "UTF-8");
  if (converter == (iconv_t)-1) {
    fprintf(stderr, "dvb-mux: unavailable text encoding %s\n", m->codepage);
    return -1;
  }
  char *input = (char *)text;
  size_t remaining = strlen(text);
  char *output = (char *)encoded + prefix;
  size_t available = 255 - prefix;
  int failed = 0;
  while (remaining) {
    if (iconv(converter, &input, &remaining, &output, &available) != (size_t)-1)
      break;
    /* DVB's default table adds the Euro sign to ISO 6937 at byte 0xa4. */
    if (!prefix && errno == EILSEQ && remaining >= 3 && available &&
        !memcmp(input, "\xe2\x82\xac", 3)) {
      *output++ = (char)0xa4;
      available--;
      input += 3;
      remaining -= 3;
      continue;
    }
    failed = 1;
    break;
  }
  if (!failed && iconv(converter, NULL, NULL, &output, &available) == (size_t)-1)
    failed = 1;
  iconv_close(converter);
  if (failed) {
    fprintf(stderr, "dvb-mux: %s cannot be represented in %s within 255 encoded "
                    "bytes\n", name, m->codepage);
    return -1;
  }
  *encoded_size = (size_t)(output - (char *)encoded);
  return 0;
}
static int load_config(struct mux *m, const char *path) {
  struct json j;
  char why[256];
  if (json_load(&j, path, why, sizeof(why))) {
    fprintf(stderr, "%s\n", why);
    return -1;
  }
  int bad = j.tokens[0].type != J_OBJECT;
  char s[64];
  m->network_id = cfg_int(&j, 0, "network_id", 1, 1, 65535, &bad);
  m->tsid = cfg_int(&j, 0, "transport_stream_id", 1, 1, 65535, &bad);
  m->onid = cfg_int(&j, 0, "original_network_id", 1, 0, 65535, &bad);
  bad |= cfg_string(&j, 0, "network_name", m->network_name,
                    sizeof(m->network_name), "DVB Headend");
  bad |= cfg_string(&j, 0, "provider_name", m->provider_name,
                    sizeof(m->provider_name), "DVB Headend");
  bad |= cfg_string(&j, 0, "country", m->country, sizeof(m->country), "BGR");
  if (strlen(m->country) != 3)
    bad = 1;
  for (int i = 0; i < 3; i++)
    if (m->country[i] < 'A' || m->country[i] > 'Z')
      bad = 1;
  m->utc_offset = cfg_int(&j, 0, "utc_offset_minutes", 0, -720, 780, &bad);
  bad |= cfg_string(&j, 0, "codepage", m->codepage, sizeof(m->codepage), "UTF-8");
  if (!strcmp(m->codepage, "utf-8"))
    strcpy(m->codepage, "UTF-8");
  if (strcmp(m->codepage, "UTF-8") && strcmp(m->codepage, "ISO-8859-5") &&
      strcmp(m->codepage, "ISO-6937"))
    bad = 1;
  if (!bad)
    bad |= encode_text(m, "network name", m->network_name, m->encoded_network,
                       &m->encoded_network_size);
  m->frequency_khz =
      cfg_int(&j, 0, "frequency_khz", 474000, 174000, 862000, &bad);
  m->bandwidth = cfg_int(&j, 0, "bandwidth_mhz", 8, 6, 8, &bad);
  const char *const mods[] = {"QPSK", "16-QAM", "64-QAM"};
  bad |= cfg_string(&j, 0, "modulation", s, sizeof(s), "64-QAM");
  m->modulation = choice(s, mods, 3);
  if (m->modulation < 0)
    bad = 1;
  const char *const fec[] = {"1/2", "2/3", "3/4", "5/6", "7/8"};
  bad |= cfg_string(&j, 0, "fec", s, sizeof(s), "3/4");
  m->fec = choice(s, fec, 5);
  if (m->fec < 0)
    bad = 1;
  const char *const guard[] = {"1/32", "1/16", "1/8", "1/4"};
  bad |= cfg_string(&j, 0, "guard", s, sizeof(s), "1/32");
  m->guard = choice(s, guard, 4);
  if (m->guard < 0)
    bad = 1;
  const char *const tx[] = {"2K", "8K"};
  bad |= cfg_string(&j, 0, "transmission_mode", s, sizeof(s), "8K");
  m->transmission = choice(s, tx, 2);
  if (m->transmission < 0)
    bad = 1;
  m->capacity =
      cfg_int(&j, 0, "capacity_bps", 27144384, 100000, 100000000, &bad);
  m->version = cfg_int(&j, 0, "version", time(NULL) & 31, 0, 31, &bad);
  m->nit_version = cfg_int(&j, 0, "network_version", m->version, 0, 31, &bad);
  m->queue_size = cfg_int(&j, 0, "buffer_bytes", 8 * 1024 * 1024, 1024 * 1024,
                          64 * 1024 * 1024, &bad);
  int list = json_get(&j, 0, "inputs");
  if (list < 0 || j.tokens[list].type != J_ARRAY)
    bad = 1;
  if (!bad)
    for (int t = list + 1; t < j.tokens[list].after; t = j.tokens[t].after) {
      if (m->count >= MAX_INPUTS || j.tokens[t].type != J_OBJECT) {
        bad = 1;
        break;
      }
      struct input *in = &m->inputs[m->count];
      in->index = (int)m->count;
      in->m = m;
      in->fd = -1;
      in->output_pmt = 0x100 + m->count;
      in->pmt_pid = 8191;
      char ident[32];
      snprintf(ident, sizeof(ident), "input-%zu", m->count + 1);
      bad |= cfg_string(&j, t, "id", in->id, sizeof(in->id), ident);
      bad |= cfg_string(&j, t, "url", in->url, sizeof(in->url), "");
      bad |= cfg_string(&j, t, "interface", in->interface,
                        sizeof(in->interface), "0.0.0.0");
      bad |= cfg_string(&j, t, "name", in->name, sizeof(in->name), ident);
      bad |= cfg_string(&j, t, "provider_name", in->provider,
                        sizeof(in->provider), m->provider_name);
      bad |= cfg_string(&j, t, "emm_group", in->emm_group,
                        sizeof(in->emm_group), "");
      if (!bad) {
        bad |= encode_text(m, "service name", in->name, in->encoded_name,
                           &in->encoded_name_size);
        bad |= encode_text(m, "provider name", in->provider, in->encoded_provider,
                           &in->encoded_provider_size);
        if (in->encoded_name_size + in->encoded_provider_size > 252) {
          fprintf(stderr, "dvb-mux: service name plus provider exceed the SDT "
                          "descriptor's 252-byte encoded text budget\n");
          bad = 1;
        }
      }
      in->emm_caid = cfg_int(&j, t, "emm_caid", 0, 0, 65535, &bad);
      in->emm_input_pid = cfg_int(&j, t, "emm_pid", 0, 0, 8190, &bad);
      in->requested_sid = cfg_int(&j, t, "input_service_id", 0, 0, 65535, &bad);
      in->input_sid = in->requested_sid;
      in->service_id =
          cfg_int(&j, t, "service_id", m->count + 1, 1, 65535, &bad);
      in->lcn = cfg_int(&j, t, "lcn", m->count + 1, 0, 1023, &bad);
      in->service_type = cfg_int(&j, t, "service_type", 1, 1, 255, &bad);
      int sc = json_get(&j, t, "scrambled");
      if (sc >= 0 && json_boolean(&j, sc, &in->scrambled))
        bad = 1;
      char host[64], tail;
      int port = 0;
      if (sscanf(in->url, "udp://%63[^:]:%d%c", host, &port, &tail) != 2 ||
          port < 1 || port > 65535 ||
          inet_pton(AF_INET, host, &in->address.sin_addr) != 1)
        bad = 1;
      struct in_addr iface;
      if (inet_pton(AF_INET, in->interface, &iface) != 1)
        bad = 1;
      in->address.sin_family = AF_INET;
      in->address.sin_port = htons(port);
      for (size_t k = 0; k < m->count; k++)
        if (m->inputs[k].service_id == in->service_id ||
            (in->lcn && m->inputs[k].lcn == in->lcn) ||
            !strcmp(m->inputs[k].id, in->id))
          bad = 1;
      m->used_pid[in->output_pmt] = true;
      m->count++;
    }
  if (!m->count)
    bad = 1;
  int peers = json_get(&j, 0, "network_transports");
  if (peers >= 0 && j.tokens[peers].type != J_ARRAY)
    bad = 1;
  if (!bad && peers >= 0)
    for (int t = peers + 1; t < j.tokens[peers].after; t = j.tokens[t].after) {
      if (m->peer_count >= 32 || j.tokens[t].type != J_OBJECT) {
        bad = 1;
        break;
      }
      struct nit_peer *p = &m->peers[m->peer_count];
      p->tsid = cfg_int(&j, t, "transport_stream_id", 0, 1, 65535, &bad);
      p->onid = cfg_int(&j, t, "original_network_id", m->onid, 0, 65535, &bad);
      p->frequency_khz =
          cfg_int(&j, t, "frequency_khz", 474000, 174000, 862000, &bad);
      p->bandwidth = cfg_int(&j, t, "bandwidth_mhz", 8, 6, 8, &bad);
      bad |= cfg_string(&j, t, "modulation", s, sizeof(s), "64-QAM");
      p->modulation = choice(s, mods, 3);
      bad |= cfg_string(&j, t, "fec", s, sizeof(s), "3/4");
      p->fec = choice(s, fec, 5);
      bad |= cfg_string(&j, t, "guard", s, sizeof(s), "1/32");
      p->guard = choice(s, guard, 4);
      bad |= cfg_string(&j, t, "transmission_mode", s, sizeof(s), "8K");
      p->transmission = choice(s, tx, 2);
      if (p->modulation < 0 || p->fec < 0 || p->guard < 0 ||
          p->transmission < 0)
        bad = 1;
      for (size_t k = 0; k < m->peer_count; k++)
        if (m->peers[k].tsid == p->tsid && m->peers[k].onid == p->onid)
          bad = 1;
      int services = json_get(&j, t, "inputs");
      if (services >= 0 && j.tokens[services].type != J_ARRAY)
        bad = 1;
      if (!bad && services >= 0)
        for (int x = services + 1; x < j.tokens[services].after;
             x = j.tokens[x].after) {
          if (p->count >= MAX_INPUTS || j.tokens[x].type != J_OBJECT) {
            bad = 1;
            break;
          }
          p->sid[p->count] = cfg_int(&j, x, "service_id", 0, 1, 65535, &bad);
          p->lcn[p->count] = cfg_int(&j, x, "lcn", 0, 0, 1023, &bad);
          for (size_t k = 0; k < p->count; k++)
            if (p->sid[k] == p->sid[p->count] ||
                (p->lcn[p->count] && p->lcn[k] == p->lcn[p->count]))
              bad = 1;
          p->count++;
        }
      m->peer_count++;
    }
  json_free(&j);
  if (bad) {
    fprintf(stderr, "dvb-mux: invalid configuration (RF, text encoding, IPv4 UDP "
                    "inputs, SID/LCN or limits)\n");
    return -1;
  }
  for (int i = 0; i < 0x100; i++)
    m->used_pid[i] = true;
  m->used_pid[8191] = true;
  m->next_pid = 0x200;
  return 0;
}
static int open_input(struct input *in) {
  /* A unicast UDP datagram goes to one socket, not every SO_REUSEADDR socket.
   * Share the endpoint subscription and fan each datagram out to selected SIDs.
   */
  for (int i = 0; i < in->index; i++) {
    struct input *previous = &in->m->inputs[i];
    if (previous->address.sin_addr.s_addr == in->address.sin_addr.s_addr &&
        previous->address.sin_port == in->address.sin_port &&
        !strcmp(previous->interface, in->interface)) {
      in->fd = previous->fd;
      return 0;
    }
  }
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  int yes = 1, buffer = 2 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));
#ifdef IP_MULTICAST_ALL
  int no = 0;
  setsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &no, sizeof(no));
#endif
  struct sockaddr_in bindaddr = in->address;
  if (bind(fd, (struct sockaddr *)&bindaddr, sizeof(bindaddr))) {
    close(fd);
    return -1;
  }
  uint32_t host = ntohl(in->address.sin_addr.s_addr);
  if ((host & 0xf0000000) == 0xe0000000) {
    struct ip_mreq membership = {.imr_multiaddr = in->address.sin_addr};
    inet_pton(AF_INET, in->interface, &membership.imr_interface);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership,
                   sizeof(membership))) {
      close(fd);
      return -1;
    }
  }
  in->fd = fd;
  return 0;
}
static uint16_t alloc_pid(struct mux *m) {
  while (m->next_pid < 0x1f00 && m->used_pid[m->next_pid])
    m->next_pid++;
  if (m->next_pid >= 0x1f00) {
    error(m, "output PID space exhausted; restart required");
    m->failed = 1;
    return 0;
  }
  uint16_t pid = m->next_pid++;
  m->used_pid[pid] = true;
  return pid;
}
static void enqueue(struct mux *m, const uint8_t *bytes, size_t n) {
  if (n > m->queue_size - m->queue_used) {
    m->dropped += (n + 187) / 188;
    return;
  }
  size_t at = (m->queue_head + m->queue_used) % m->queue_size,
         first = m->queue_size - at;
  if (first > n)
    first = n;
  memcpy(m->queue + at, bytes, first);
  memcpy(m->queue, bytes + first, n - first);
  m->queue_used += n;
  if (m->queue_used > m->max_queue)
    m->max_queue = m->queue_used;
}
static void packet_emit(struct mux *m, uint8_t packet[188], uint16_t pid) {
  packet[1] = (packet[1] & 0xe0) | (pid >> 8);
  packet[2] = pid;
  if (packet[3] & 0x10)
    packet[3] = (packet[3] & 0xf0) | (m->cc[pid]++ & 15);
  else
    packet[3] = (packet[3] & 0xf0) | ((m->cc[pid] - 1) & 15);
  enqueue(m, packet, 188);
}
static void section_emit(struct mux *m, uint16_t pid, const uint8_t *data,
                         size_t n) {
  size_t packets = (n + 1 + 183) / 184;
  if (packets * 188 > m->queue_size - m->queue_used) {
    m->dropped += packets;
    return;
  }
  int first = 1;
  while (n) {
    uint8_t p[188];
    memset(p, 0xff, 188);
    p[0] = 0x47;
    p[1] = first ? 0x40 : 0;
    p[2] = 0;
    p[3] = 0x10;
    size_t at = first ? 5 : 4;
    if (first)
      p[4] = 0;
    size_t take = 188 - at;
    if (take > n)
      take = n;
    memcpy(p + at, data, take);
    packet_emit(m, p, pid);
    data += take;
    n -= take;
    first = 0;
  }
}
static void finish(uint8_t *s, size_t n) {
  unsigned l = (unsigned)n - 3;
  s[1] = (s[1] & 0xf0) | (l >> 8);
  s[2] = l;
  uint32_t crc = eit_crc32(s, n - 4);
  for (int i = 0; i < 4; i++)
    s[n - 4 + i] = crc >> (24 - 8 * i);
}
static void header(struct mux *m, uint8_t *s, uint8_t tid, uint16_t ext,
                   int section, int last) {
  s[0] = tid;
  s[1] = 0xb0;
  s[2] = 0;
  w16(s + 3, ext);
  s[5] = 0xc1 | ((m->version & 31) << 1);
  s[6] = section;
  s[7] = last;
}
static int valid_section(const uint8_t *s, size_t n, size_t min) {
  return n >= min && n <= 1024 && (s[1] & 0x80) && (s[5] & 1) && s[6] <= s[7] &&
         eit_crc32(s, n) == 0;
}
static void table_clear(struct table *t) {
  for (int i = 0; i < 256; i++) {
    free(t->part[i].data);
    t->part[i].data = NULL;
    t->part[i].size = 0;
  }
  t->initialized = 0;
}
static int table_collect(struct table *t, const uint8_t *s, size_t n) {
  int ver = (s[5] >> 1) & 31, ext = u16(s + 3);
  if (!t->initialized || t->version != ver || t->extension != ext ||
      t->last != s[7]) {
    table_clear(t);
    t->version = ver;
    t->extension = ext;
    t->last = s[7];
    t->initialized = 1;
  }
  struct part *p = &t->part[s[6]];
  if (p->size != n || !p->data || memcmp(p->data, s, n)) {
    uint8_t *copy = malloc(n);
    if (!copy)
      return -1;
    memcpy(copy, s, n);
    free(p->data);
    p->data = copy;
    p->size = n;
  }
  for (int i = 0; i <= t->last; i++)
    if (!t->part[i].data)
      return 0;
  return 1;
}
typedef void (*section_fn)(struct input *, const uint8_t *, size_t);
static void consume(struct assembler *a, struct input *in, const uint8_t *p,
                    size_t n, int start, section_fn fn) {
  while (n) {
    if (!a->used && (!start || *p == 0xff))
      return;
    size_t target = a->used < 3 ? 3 : a->need, take = target - a->used;
    if (take > n)
      take = n;
    memcpy(a->data + a->used, p, take);
    a->used += take;
    p += take;
    n -= take;
    if (a->used == 3) {
      a->need = 3 + ((a->data[1] & 15) << 8) + a->data[2];
      if (a->need < 8 || a->need > SECTION_MAX) {
        a->used = a->need = 0;
        return;
      }
    }
    if (a->need && a->used == a->need) {
      fn(in, a->data, a->need);
      a->used = a->need = 0;
      if (!start)
        return;
    }
  }
}
static void assemble(struct assembler *a, struct input *in,
                     const uint8_t p[188], section_fn fn) {
  if ((p[1] & 0x80) || (p[3] & 0xc0) || !(p[3] & 0x30)) {
    a->used = a->need = 0;
    a->valid = 0;
    return;
  }
  size_t off = 4;
  if (p[3] & 0x20) {
    off += 1 + p[4];
    if (off > 188) {
      a->used = a->need = 0;
      a->valid = 0;
      return;
    }
    if (p[4] && (p[5] & 0x80)) {
      a->used = a->need = 0;
      a->valid = 0;
    }
  }
  if (!(p[3] & 0x10) || off >= 188)
    return;
  int cc = p[3] & 15;
  if (a->valid) {
    if (a->cc == cc && !memcmp(a->previous, p, 188))
      return;
    if (cc != ((a->cc + 1) & 15))
      a->used = a->need = 0;
  }
  a->cc = cc;
  a->valid = 1;
  memcpy(a->previous, p, 188);
  if (p[1] & 0x40) {
    unsigned ptr = p[off++];
    if (ptr > 188 - off) {
      a->used = a->need = 0;
      return;
    }
    if (a->used && ptr)
      consume(a, in, p + off, ptr, 0, fn);
    a->used = a->need = 0;
    off += ptr;
    consume(a, in, p + off, 188 - off, 1, fn);
  } else if (a->used)
    consume(a, in, p + off, 188 - off, 0, fn);
}
static int role_add(uint8_t roles[MAX_PID], uint16_t pid, int role,
                    uint16_t pmt) {
  if (pid < 32 || pid == 8191 || pid == pmt)
    return -1;
  if (((role & (ES | PCR)) && (roles[pid] & (ECM | EMM))) ||
      ((role & (ECM | EMM)) && (roles[pid] & (ES | PCR))) ||
      ((role == EMM) && (roles[pid] & ECM)) ||
      ((role == ECM) && (roles[pid] & EMM)))
    return -1;
  roles[pid] |= role;
  return 0;
}
static int descriptor_roles(const uint8_t *p, size_t n, uint8_t roles[MAX_PID],
                            int role, uint16_t pmt) {
  while (n) {
    if (n < 2 || 2u + p[1] > n)
      return -1;
    size_t len = 2 + p[1];
    if (p[0] == 9) {
      if (p[1] < 4 || role_add(roles, u16(p + 4) & 8191, role, pmt))
        return -1;
    }
    p += len;
    n -= len;
  }
  return 0;
}
static int validate_pmt(struct input *in, const uint8_t *p, size_t n,
                        uint8_t roles[MAX_PID]) {
  if (!valid_section(p, n, 16) || p[0] != 2 || u16(p + 3) != in->input_sid ||
      p[6] || p[7])
    return -1;
  unsigned pcr = u16(p + 8) & 8191, info = u16(p + 10) & 4095;
  if (pcr != 8191 && role_add(roles, pcr, PCR, in->pmt_pid))
    return -1;
  if (12u + info > n - 4 ||
      descriptor_roles(p + 12, info, roles, ECM, in->pmt_pid))
    return -1;
  for (size_t at = 12 + info; at < n - 4;) {
    if (at + 5 > n - 4)
      return -1;
    unsigned len = u16(p + at + 3) & 4095;
    if (at + 5 + len > n - 4 ||
        role_add(roles, u16(p + at + 1) & 8191, ES, in->pmt_pid) ||
        descriptor_roles(p + at + 5, len, roles, ECM, in->pmt_pid))
      return -1;
    at += 5 + len;
  }
  return 0;
}
static uint16_t emm_pid(struct input *in, const uint8_t *d) {
  struct mux *m = in->m;
  unsigned len = d[1] - 4;
  uint16_t caid = u16(d + 2);
  if (!in->emm_group[0] || (in->emm_caid && in->emm_caid != caid) ||
      (in->emm_input_pid && in->emm_input_pid != (u16(d + 4) & 8191)))
    return 0;
  for (size_t i = 0; i < m->shared_count; i++) {
    struct shared_emm *g = &m->shared[i];
    if (!strcmp(g->group, in->emm_group) && g->caid == caid &&
        g->private_size == len && !memcmp(g->private_data, d + 6, len))
      return g->pid;
  }
  if (m->shared_count >= 256) {
    m->failed = 1;
    error(m, "shared EMM descriptor limit exceeded");
    return 0;
  }
  struct shared_emm *g = &m->shared[m->shared_count++];
  strcpy(g->group, in->emm_group);
  g->caid = caid;
  g->private_size = len;
  memcpy(g->private_data, d + 6, len);
  g->owner = -1;
  /* First common EMM PID matches the headend convention (8064). */
  for (int pid = 8064; pid >= 0x1f00; pid--)
    if (!m->used_pid[pid]) {
      g->pid = pid;
      m->used_pid[pid] = true;
      return pid;
    }
  g->pid = alloc_pid(m);
  return g->pid;
}
static void remap_descriptors(struct input *in, uint8_t *p, size_t n) {
  while (n) {
    size_t len = 2 + p[1];
    if (p[0] == 9)
      w16(p + 4, 0xe000 | in->map[u16(p + 4) & 8191]);
    p += len;
    n -= len;
  }
}
static int rebuild(struct input *in) {
  if (!in->pmt_candidate_size)
    return 0;
  uint8_t roles[MAX_PID] = {0};
  if (validate_pmt(in, in->pmt_candidate, in->pmt_candidate_size, roles))
    return -1;
  if (descriptor_roles(in->cat_candidate, in->cat_candidate_size, roles, EMM,
                       in->pmt_pid))
    return -1;
  for (unsigned pid = 32; pid < 8191; pid++)
    if (roles[pid] && in->map_kind[pid] && (in->map_kind[pid] & EMM) &&
        !(roles[pid] & EMM))
      in->map[pid] = 0;
  for (size_t at = 0; at < in->cat_candidate_size;) {
    const uint8_t *d = in->cat_candidate + at;
    if (d[0] == 9) {
      uint16_t original = u16(d + 4) & 8191;
      uint16_t shared = emm_pid(in, d);
      if (shared)
        in->map[original] = shared;
    }
    at += 2 + d[1];
  }
  for (unsigned pid = 32; pid < 8191; pid++)
    if (roles[pid] && !in->map[pid])
      in->map[pid] = alloc_pid(in->m);
  if (in->m->failed)
    return -1;
  uint8_t pmt[1024];
  memcpy(pmt, in->pmt_candidate, in->pmt_candidate_size);
  w16(pmt + 3, in->service_id);
  unsigned pcr = u16(pmt + 8) & 8191;
  if (pcr != 8191)
    w16(pmt + 8, 0xe000 | in->map[pcr]);
  unsigned info = u16(pmt + 10) & 4095;
  remap_descriptors(in, pmt + 12, info);
  for (size_t at = 12 + info; at < in->pmt_candidate_size - 4;) {
    unsigned len = u16(pmt + at + 3) & 4095;
    w16(pmt + at + 1, 0xe000 | in->map[u16(pmt + at + 1) & 8191]);
    remap_descriptors(in, pmt + at + 5, len);
    at += 5 + len;
  }
  in->m->version = (in->m->version + 1) & 31;
  pmt[5] = 0xc1 | (in->m->version << 1);
  finish(pmt, in->pmt_candidate_size);
  uint8_t *cat = NULL;
  if (in->cat_candidate_size) {
    cat = malloc(in->cat_candidate_size);
    if (!cat) {
      in->m->failed = 1;
      return -1;
    }
    memcpy(cat, in->cat_candidate, in->cat_candidate_size);
    remap_descriptors(in, cat, in->cat_candidate_size);
  }
  memcpy(in->roles, roles, sizeof(roles));
  for (unsigned pid = 32; pid < 8191; pid++)
    if (roles[pid])
      in->map_kind[pid] = roles[pid];
  memcpy(in->pmt, pmt, in->pmt_candidate_size);
  in->pmt_size = in->pmt_candidate_size;
  free(in->cat);
  in->cat = cat;
  in->cat_size = in->cat_candidate_size;
  in->ready = 1;
  in->m->psi_at = 0;
  in->m->si_at = 0;
  fprintf(stderr, "dvb-mux: input %s SID %u -> %u ready, PMT PID %u\n", in->id,
          in->input_sid, in->service_id, in->output_pmt);
  return 0;
}
static void on_pat(struct input *in, const uint8_t *s, size_t n) {
  if (!valid_section(s, n, 12) || s[0] || ((n - 12) % 4))
    return;
  int complete = table_collect(&in->pat_table, s, n);
  if (complete < 0) {
    in->m->failed = 1;
    return;
  }
  if (!complete)
    return;
  uint16_t found = 8191, sid = in->requested_sid;
  for (int i = 0; i <= in->pat_table.last; i++) {
    struct part *p = &in->pat_table.part[i];
    for (size_t at = 8; at < p->size - 4; at += 4) {
      uint16_t next = u16(p->data + at);
      if (!sid && next)
        sid = next;
      if (next && next == sid) {
        uint16_t pid = u16(p->data + at + 2) & 8191;
        if (pid < 32 || pid == 8191 || (found != 8191 && found != pid)) {
          input_error(in, "invalid PAT PID");
          return;
        }
        found = pid;
      }
    }
  }
  if (found != in->pmt_pid || sid != in->input_sid) {
    in->ready = 0;
    in->pmt_size = in->pmt_candidate_size = 0;
    memset(in->roles, 0, sizeof(in->roles));
    memset(&in->pmt_asm, 0, sizeof(in->pmt_asm));
    memset(&in->eit, 0, sizeof(in->eit));
    in->pmt_pid = found;
    in->input_sid = sid;
    in->m->version = (in->m->version + 1) & 31;
    in->m->psi_at = in->m->si_at = 0;
  }
}
static void on_pmt(struct input *in, const uint8_t *s, size_t n) {
  uint8_t roles[MAX_PID] = {0};
  if (validate_pmt(in, s, n, roles)) {
    input_error(in, "invalid PMT or conflicting elementary/CA PID");
    return;
  }
  if (in->pmt_candidate_size == n && !memcmp(in->pmt_candidate, s, n))
    return;
  memcpy(in->pmt_candidate, s, n);
  in->pmt_candidate_size = n;
  if (rebuild(in))
    input_error(in, "PMT/CAT PID conflict; keeping last coherent tables");
}
static void on_cat(struct input *in, const uint8_t *s, size_t n) {
  if (!valid_section(s, n, 12) || s[0] != 1)
    return;
  int done = table_collect(&in->cat_table, s, n);
  if (done < 0) {
    in->m->failed = 1;
    return;
  }
  if (!done)
    return;
  size_t total = 0;
  for (int i = 0; i <= in->cat_table.last; i++)
    total += in->cat_table.part[i].size - 12;
  if (total > CAT_MAX) {
    input_error(in, "CAT descriptor limit exceeded");
    return;
  }
  uint8_t *cat = malloc(total ? total : 1);
  if (!cat) {
    in->m->failed = 1;
    return;
  }
  size_t at = 0;
  for (int i = 0; i <= in->cat_table.last; i++) {
    struct part *p = &in->cat_table.part[i];
    memcpy(cat + at, p->data + 8, p->size - 12);
    at += p->size - 12;
  }
  uint8_t roles[MAX_PID] = {0};
  if (descriptor_roles(cat, total, roles, EMM, in->pmt_pid)) {
    free(cat);
    input_error(in, "invalid CAT descriptors");
    return;
  }
  if (in->cat_candidate_size == total &&
      (!total || !memcmp(in->cat_candidate, cat, total))) {
    free(cat);
    return;
  }
  free(in->cat_candidate);
  in->cat_candidate = cat;
  in->cat_candidate_size = total;
  if (rebuild(in))
    input_error(in, "CAT/PMT PID conflict; keeping last coherent tables");
}
static void eit_emit(void *opaque, const uint8_t *packets, size_t n) {
  struct input *in = opaque;
  struct mux *m = in->m;
  if (n > m->queue_size - m->queue_used) {
    m->dropped += n / 188;
    return;
  }
  while (n) {
    uint8_t packet[188];
    memcpy(packet, packets, 188);
    packet_emit(m, packet, 0x12);
    packets += 188;
    n -= 188;
  }
}
static int forward_emm(struct input *in, uint16_t pid, uint64_t now,
                       int start) {
  struct mux *m = in->m;
  for (size_t i = 0; i < m->shared_count; i++) {
    struct shared_emm *g = &m->shared[i];
    if (g->pid == pid) {
      if (g->owner < 0 || now - g->last > 2000) {
        if (!start)
          return 0;
        g->owner = in->index;
      }
      if (g->owner != in->index)
        return 0;
      g->last = now;
      return 1;
    }
  }
  return 1;
}
static void input_packet(struct input *in, const uint8_t p[188], uint64_t now) {
  struct mux *m = in->m;
  in->received++;
  m->input_packets++;
  in->last_received = now;
  if (p[0] != 0x47 || (p[1] & 0x80) || !(p[3] & 0x30) ||
      ((p[3] & 0x20) && p[4] > 183)) {
    in->invalid++;
    m->invalid++;
    return;
  }
  uint16_t pid = ((p[1] & 31) << 8) | p[2];
  if (pid == 8191) {
    m->null_dropped++;
    return;
  }
  if (pid == 0) {
    assemble(&in->pat_asm, in, p, on_pat);
    return;
  }
  if (pid == 1) {
    assemble(&in->cat_asm, in, p, on_cat);
    return;
  }
  if (pid == in->pmt_pid) {
    assemble(&in->pmt_asm, in, p, on_pmt);
    return;
  }
  if (!in->ready)
    return;
  if (pid == 0x12) {
    eit_forward_packet(&in->eit, p, in->input_sid, in->service_id, m->tsid,
                       m->onid, eit_emit, in);
    return;
  }
  if (!in->roles[pid])
    return;
  uint16_t mapped = in->map[pid];
  if ((in->roles[pid] & EMM) && !forward_emm(in, mapped, now, p[1] & 0x40))
    return;
  uint8_t packet[188];
  memcpy(packet, p, 188);
  if (in->roles[pid] & EMM)
    packet_emit(m, packet, mapped);
  else {
    packet[1] = (packet[1] & 0xe0) | (mapped >> 8);
    packet[2] = mapped;
    enqueue(m, packet, 188);
  }
  in->forwarded++;
  if (in->roles[pid] & (ES | PCR))
    in->last_payload = now;
}
static void read_datagram(struct input *in, uint8_t *data, size_t n,
                          uint64_t now) {
  /* Accept MPEG-TS UDP and RTP/AVP payload type 33. */
  if (n >= 12 && data[0] >> 6 == 2 && (data[1] & 127) == 33) {
    size_t at = 12 + 4 * (data[0] & 15);
    if (at > n)
      goto bad;
    if (data[0] & 16) {
      if (at + 4 > n)
        goto bad;
      at += 4 + 4 * u16(data + at + 2);
      if (at > n)
        goto bad;
    }
    if (data[0] & 32) {
      unsigned pad = data[n - 1];
      if (!pad || pad > n - at)
        goto bad;
      n -= pad;
    }
    data += at;
    n -= at;
  }
  if (!n || n % 188)
    goto bad;
  for (size_t at = 0; at < n; at += 188)
    input_packet(in, data + at, now);
  return;
bad:
  in->invalid++;
  in->m->invalid++;
}
static size_t dvb_text(uint8_t *dst, const uint8_t *text, size_t n) {
  memcpy(dst, text, n);
  return n;
}
static void emit_pat_pmt(struct mux *m) {
  uint8_t s[1024];
  header(m, s, 0, m->tsid, 0, 0);
  size_t n = 8;
  w16(s + n, 0);
  w16(s + n + 2, 0xe010);
  n += 4;
  for (size_t i = 0; i < m->count; i++) {
    struct input *in = &m->inputs[i];
    if (!in->ready)
      continue;
    w16(s + n, in->service_id);
    w16(s + n + 2, 0xe000 | in->output_pmt);
    n += 4;
  }
  n += 4;
  finish(s, n);
  section_emit(m, 0, s, n);
  for (size_t i = 0; i < m->count; i++)
    if (m->inputs[i].ready)
      section_emit(m, m->inputs[i].output_pmt, m->inputs[i].pmt,
                   m->inputs[i].pmt_size);
  /* Collect and deduplicate complete descriptors, then split CAT on descriptor
   * boundaries. */
  const uint8_t *desc[4096];
  size_t lengths[4096], count = 0;
  for (size_t i = 0; i < m->count; i++) {
    struct input *in = &m->inputs[i];
    if (!in->ready)
      continue;
    for (size_t at = 0; at < in->cat_size;) {
      const uint8_t *d = in->cat + at;
      size_t len = 2 + d[1];
      int duplicate = 0;
      for (size_t j = 0; j < count; j++)
        if (lengths[j] == len && !memcmp(desc[j], d, len)) {
          duplicate = 1;
          break;
        }
      if (!duplicate) {
        if (count >= 4096) {
          error(m, "combined CAT descriptor limit exceeded");
          m->failed = 1;
          return;
        }
        desc[count] = d;
        lengths[count++] = len;
      }
      at += len;
    }
  }
  size_t sections = 1, len = 8;
  for (size_t i = 0; i < count; i++) {
    if (len + lengths[i] + 4 > 1024) {
      sections++;
      len = 8;
    }
    len += lengths[i];
  }
  if (sections > 256) {
    m->failed = 1;
    return;
  }
  size_t at = 0;
  for (size_t sec = 0; sec < sections; sec++) {
    header(m, s, 1, 0xffff, (int)sec, (int)sections - 1);
    n = 8;
    while (at < count && n + lengths[at] + 4 <= 1024) {
      memcpy(s + n, desc[at], lengths[at]);
      n += lengths[at++];
    }
    n += 4;
    finish(s, n);
    section_emit(m, 1, s, n);
  }
}
static void emit_sdt(struct mux *m) {
  uint8_t entries[MAX_INPUTS][264];
  size_t lens[MAX_INPUTS], count = 0;
  for (size_t i = 0; i < m->count; i++) {
    struct input *in = &m->inputs[i];
    if (!in->ready)
      continue;
    uint8_t *d = entries[count];
    w16(d, in->service_id);
    d[2] = 0xff;
    d[3] = 0x80 | (in->scrambled ? 0x10 : 0);
    d[4] = 0;
    d[5] = 0x48;
    d[7] = in->service_type;
    size_t pn = dvb_text(d + 9, in->encoded_provider, in->encoded_provider_size);
    d[8] = pn;
    size_t nn = dvb_text(d + 10 + pn, in->encoded_name, in->encoded_name_size);
    d[9 + pn] = nn;
    size_t dl = 3 + pn + nn;
    d[6] = dl;
    unsigned loop = dl + 2;
    d[3] |= loop >> 8;
    d[4] = loop;
    lens[count++] = 5 + loop;
  }
  size_t sections = 1, n = 11;
  for (size_t i = 0; i < count; i++) {
    if (n + lens[i] + 4 > 1024) {
      sections++;
      n = 11;
    }
    n += lens[i];
  }
  size_t at = 0;
  for (size_t sec = 0; sec < sections; sec++) {
    uint8_t s[1024];
    header(m, s, 0x42, m->tsid, sec, sections - 1);
    s[1] = 0xf0;
    w16(s + 8, m->onid);
    s[10] = 0xff;
    n = 11;
    while (at < count && n + lens[at] + 4 <= 1024) {
      memcpy(s + n, entries[at], lens[at]);
      n += lens[at++];
    }
    n += 4;
    finish(s, n);
    section_emit(m, 0x11, s, n);
  }
}
static size_t nit_entry(uint8_t *s, const struct nit_peer *p) {
  w16(s, p->tsid);
  w16(s + 2, p->onid);
  size_t n = 6;
  s[n++] = 0x5a;
  s[n++] = 11;
  uint32_t f = (uint32_t)p->frequency_khz * 100;
  for (int i = 0; i < 4; i++)
    s[n++] = f >> (24 - 8 * i);
  s[n++] = ((8 - p->bandwidth) << 5) | 0x1f;
  s[n++] = (p->modulation << 6) | p->fec;
  s[n++] = (p->fec << 5) | (p->guard << 3) | (p->transmission << 1);
  memset(s + n, 0xff, 4);
  n += 4;
  s[n++] = 0x5f;
  s[n++] = 4;
  s[n++] = 0;
  s[n++] = 0;
  s[n++] = 0;
  s[n++] = 0x28;
  size_t dstart = n;
  s[n++] = 0x83;
  size_t lcnlen = n++;
  for (size_t i = 0; i < p->count; i++) {
    if (!p->lcn[i])
      continue;
    if (n - dstart - 2 + 4 > 252) {
      s[lcnlen] = n - dstart - 2;
      dstart = n;
      s[n++] = 0x83;
      lcnlen = n++;
    }
    w16(s + n, p->sid[i]);
    w16(s + n + 2, 0xfc00 | p->lcn[i]);
    n += 4;
  }
  s[lcnlen] = n - dstart - 2;
  w16(s + 4, 0xf000 | (n - 6));
  return n;
}
static void emit_nit(struct mux *m) {
  struct nit_peer self = {.tsid = m->tsid,
                          .onid = m->onid,
                          .frequency_khz = m->frequency_khz,
                          .bandwidth = m->bandwidth,
                          .modulation = m->modulation,
                          .fec = m->fec,
                          .guard = m->guard,
                          .transmission = m->transmission};
  for (size_t i = 0; i < m->count; i++) {
    self.sid[self.count] = m->inputs[i].service_id;
    self.lcn[self.count++] = m->inputs[i].lcn;
  }
  uint8_t entries[33][300];
  size_t lengths[33], count = 0;
  int found_self = 0;
  for (size_t i = 0; i < m->peer_count; i++) {
    const struct nit_peer *p = &m->peers[i];
    if (p->tsid == m->tsid && p->onid == m->onid) {
      p = &self;
      found_self = 1;
    }
    lengths[count] = nit_entry(entries[count], p);
    count++;
  }
  if (!found_self) {
    lengths[count] = nit_entry(entries[count], &self);
    count++;
  }
  uint8_t network[257];
  network[0] = 0x40;
  size_t name = dvb_text(network + 2, m->encoded_network, m->encoded_network_size);
  network[1] = name;
  size_t netlen = name + 2;
  size_t base = 12 + netlen, sections = 1, n = base;
  for (size_t i = 0; i < count; i++) {
    if (n + lengths[i] + 4 > 1024) {
      sections++;
      n = base;
    }
    n += lengths[i];
  }
  size_t at = 0;
  for (size_t sec = 0; sec < sections; sec++) {
    uint8_t s[1024];
    header(m, s, 0x40, m->network_id, sec, sections - 1);
    s[5] = 0xc1 | (m->nit_version << 1);
    s[1] = 0xf0;
    w16(s + 8, 0xf000 | netlen);
    memcpy(s + 10, network, netlen);
    size_t loop = 10 + netlen;
    n = loop + 2;
    while (at < count && n + lengths[at] + 4 <= 1024) {
      memcpy(s + n, entries[at], lengths[at]);
      n += lengths[at++];
    }
    w16(s + loop, 0xf000 | (n - loop - 2));
    n += 4;
    finish(s, n);
    section_emit(m, 0x10, s, n);
  }
}
static unsigned bcd(unsigned v) { return ((v / 10) << 4) | (v % 10); }
static void utc_bytes(uint8_t *p, time_t stamp) {
  struct tm t;
  gmtime_r(&stamp, &t);
  uint64_t mjd = (uint64_t)stamp / 86400 + 40587;
  w16(p, mjd);
  p[2] = bcd(t.tm_hour);
  p[3] = bcd(t.tm_min);
  p[4] = bcd(t.tm_sec);
}
static void emit_time(struct mux *m) {
  time_t now = time(NULL);
  uint8_t tdt[8] = {0x70, 0x70, 5};
  utc_bytes(tdt + 3, now);
  section_emit(m, 0x14, tdt, 8);
  uint8_t tot[29] = {0x73, 0x70, 26};
  utc_bytes(tot + 3, now);
  tot[8] = 0xf0;
  tot[9] = 15;
  tot[10] = 0x58;
  tot[11] = 13;
  memcpy(tot + 12, m->country, 3);
  tot[15] = 2 | (m->utc_offset < 0);
  unsigned offset = abs(m->utc_offset);
  tot[16] = bcd(offset / 60);
  tot[17] = bcd(offset % 60);
  utc_bytes(tot + 18, now + 365 * 86400);
  tot[23] = tot[16];
  tot[24] = tot[17];
  finish(tot, 29);
  section_emit(m, 0x14, tot, 29);
}
static void publish_status(struct mux *m, uint64_t now) {
  if (!m->status_path[0])
    return;
  char temp[1100];
  snprintf(temp, sizeof(temp), "%s.tmp.%ld", m->status_path, (long)getpid());
  FILE *f = fopen(temp, "w");
  if (!f)
    return;
  double elapsed = (now - m->status_at) / 1000.0;
  double rate = elapsed > 0 ? (m->output_bytes - m->status_bytes) * 8.0 /
                                  elapsed / 1000000
                            : 0;
  size_t ready = 0, active = 0;
  for (size_t i = 0; i < m->count; i++) {
    ready += m->inputs[i].ready;
    active += m->inputs[i].ready && m->inputs[i].last_payload &&
              now - m->inputs[i].last_payload <= 10000;
  }
  fprintf(
      f,
      "{\"pid\":%ld,\"sequence\":%" PRIu64 ",\"sample_unix_ms\":%" PRIu64
      ",\"window_seconds\":%.3f,\"output_mbps\":%.6f,\"capacity_bps\":%" PRIu64
      ",\"occupancy_pct\":%.6f,\"input_packets\":%" PRIu64
      ",\"output_packets\":%" PRIu64 ",\"dropped_packets\":%" PRIu64
      ",\"null_dropped\":%" PRIu64 ",\"invalid_packets\":%" PRIu64
      ",\"errors\":%" PRIu64
      ",\"queue_bytes\":%zu,\"queue_peak_bytes\":%" PRIu64
      ",\"ready_services\":%zu,\"active_services\":%zu,\"ready_inputs\":%zu,"
      "\"total_inputs\":%zu,\"vbr\":true}\n",
      (long)getpid(), ++m->sequence, clock_ms(CLOCK_REALTIME), elapsed, rate,
      m->capacity, rate * 1000000 * 100 / m->capacity, m->input_packets,
      m->output_bytes / 188, m->dropped, m->null_dropped, m->invalid, m->errors,
      m->queue_used, m->max_queue, ready, active, ready, m->count);
  int bad = ferror(f);
  if (fclose(f))
    bad = 1;
  if (!bad)
    rename(temp, m->status_path);
  else
    unlink(temp);
  m->status_at = now;
  m->status_bytes = m->output_bytes;
}
static int write_queue(struct mux *m) {
  if (!m->queue_used)
    return 0;
  size_t first = m->queue_size - m->queue_head;
  if (first > m->queue_used)
    first = m->queue_used;
  struct iovec v[2] = {{m->queue + m->queue_head, first},
                       {m->queue, m->queue_used - first}};
  ssize_t n = writev(STDOUT_FILENO, v, v[1].iov_len ? 2 : 1);
  if (n < 0) {
    if (errno == EINTR || errno == EAGAIN)
      return 0;
    return -1;
  }
  if (n == 0)
    return -1;
  m->queue_head = (m->queue_head + (size_t)n) % m->queue_size;
  m->queue_used -= n;
  m->output_bytes += n;
  return 0;
}
static int run(struct mux *m) {
  m->queue = malloc(m->queue_size);
  uint8_t (*packets)[UDP_SIZE] = malloc(READ_BATCH * UDP_SIZE);
  if (!m->queue || !packets)
    return -1;
  struct mmsghdr messages[READ_BATCH];
  struct iovec vectors[READ_BATCH];
  memset(messages, 0, sizeof(messages));
  for (int i = 0; i < READ_BATCH; i++) {
    vectors[i].iov_base = packets[i];
    vectors[i].iov_len = UDP_SIZE;
    messages[i].msg_hdr.msg_iov = &vectors[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }
  for (size_t i = 0; i < m->count; i++)
    if (open_input(&m->inputs[i])) {
      fprintf(stderr, "dvb-mux: cannot join %s on %s: %s\n", m->inputs[i].url,
              m->inputs[i].interface, strerror(errno));
      free(packets);
      return -1;
    }
  int oldflags = fcntl(STDOUT_FILENO, F_GETFL);
  if (oldflags < 0 ||
      fcntl(STDOUT_FILENO, F_SETFL, oldflags | O_NONBLOCK) < 0) {
    free(packets);
    return -1;
  }
  struct pollfd fds[MAX_INPUTS + 1];
  for (size_t i = 0; i < m->count; i++) {
    fds[i].fd = m->inputs[i].fd;
    for (size_t j = 0; j < i; j++)
      if (m->inputs[j].fd == m->inputs[i].fd)
        fds[i].fd = -1;
    fds[i].events = POLLIN;
  }
  fds[m->count].fd = STDOUT_FILENO;
  m->started = m->status_at = now_ms();
  fprintf(stderr,
          "dvb-mux: VBR started, %zu inputs, capacity %" PRIu64
          " bit/s, buffer %zu bytes; no generated NULL packets\n",
          m->count, m->capacity, m->queue_size);
  size_t rotate = 0;
  int result = 0;
  while (!stopping && !m->failed) {
    uint64_t now = now_ms();
    if (now - m->psi_at >= 100) {
      emit_pat_pmt(m);
      m->psi_at = now;
    }
    if (now - m->si_at >= 500) {
      emit_sdt(m);
      emit_nit(m);
      m->si_at = now;
    }
    if (now - m->time_at >= 5000) {
      emit_time(m);
      m->time_at = now;
    }
    if (now - m->status_at >= 10000)
      publish_status(m, now);
    fds[m->count].events = m->queue_used ? POLLOUT : 0;
    int ready = poll(fds, m->count + 1, 10);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      result = -1;
      break;
    }
    if (fds[m->count].revents & (POLLERR | POLLHUP | POLLNVAL)) {
      result = -1;
      break;
    }
    for (size_t offset = 0; offset < m->count; offset++) {
      size_t i = (rotate + offset) % m->count;
      if (fds[i].revents & POLLIN) {
        for (int k = 0; k < READ_BATCH; k++)
          messages[k].msg_hdr.msg_flags = 0;
        int n = recvmmsg(fds[i].fd, messages, READ_BATCH, MSG_DONTWAIT, NULL);
        if (n < 0) {
          if (errno != EAGAIN && errno != EINTR)
            m->errors++;
          continue;
        }
        for (int k = 0; k < n; k++) {
          if (messages[k].msg_hdr.msg_flags & MSG_TRUNC) {
            m->invalid++;
            continue;
          }
          for (size_t selected = 0; selected < m->count; selected++)
            if (m->inputs[selected].fd == fds[i].fd)
              read_datagram(&m->inputs[selected], packets[k],
                            messages[k].msg_len, now);
        }
      }
    }
    rotate = (rotate + 1) % m->count;
    if (write_queue(m)) {
      result = -1;
      break;
    }
  }
  publish_status(m, now_ms());
  fcntl(STDOUT_FILENO, F_SETFL, oldflags);
  free(packets);
  if (m->failed)
    result = -1;
  fprintf(stderr,
          "dvb-mux: stopped; input=%" PRIu64 " output=%" PRIu64
          " dropped=%" PRIu64 " invalid=%" PRIu64 " errors=%" PRIu64 "\n",
          m->input_packets, m->output_bytes / 188, m->dropped, m->invalid,
          m->errors);
  return result;
}
static void cleanup(struct mux *m) {
  for (size_t i = 0; i < m->count; i++) {
    struct input *in = &m->inputs[i];
    int owned = 1;
    for (size_t j = 0; j < i; j++)
      if (m->inputs[j].fd == in->fd)
        owned = 0;
    if (in->fd >= 0 && owned)
      close(in->fd);
    table_clear(&in->pat_table);
    table_clear(&in->cat_table);
    free(in->cat);
    free(in->cat_candidate);
  }
  free(m->queue);
  free(m);
}
int main(int argc, char **argv) {
  const char *config = NULL, *status = "";
  int check = 0;
  static const struct option opts[] = {
      {"config", 1, 0, 'c'},       {"status-file", 1, 0, 's'},
      {"check-config", 0, 0, 'n'}, {"version", 0, 0, 'v'},
      {"help", 0, 0, 'h'},         {0, 0, 0, 0}};
  int c;
  while ((c = getopt_long(argc, argv, "c:s:nvh", opts, NULL)) != -1) {
    if (c == 'c')
      config = optarg;
    else if (c == 's')
      status = optarg;
    else if (c == 'n')
      check = 1;
    else if (c == 'v') {
      puts("dvb-mux 0.1 (VBR, libusb pipeline)");
      return 0;
    } else {
      fprintf(c == 'h' ? stdout : stderr,
              "Usage: dvb-mux --config FILE [--status-file FILE] "
              "[--check-config]\nOutputs raw MPEG-TS on stdout. No NULL "
              "generation.\n");
      return c == 'h' ? 0 : 2;
    }
  }
  if (!config || optind != argc || strlen(status) >= 1024)
    return 2;
  struct mux *m = calloc(1, sizeof(*m));
  if (!m)
    return 1;
  for (size_t i = 0; i < MAX_INPUTS; i++)
    m->inputs[i].fd = -1;
  if (load_config(m, config)) {
    cleanup(m);
    return 2;
  }
  strcpy(m->status_path, status);
  if (check) {
    printf("{\"valid\":true,\"inputs\":%zu,\"capacity_bps\":%" PRIu64
           ",\"vbr\":true}\n",
           m->count, m->capacity);
    cleanup(m);
    return 0;
  }
  struct sigaction action = {0};
  action.sa_handler = stop_handler;
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);
  signal(SIGPIPE, SIG_IGN);
  int result = run(m);
  cleanup(m);
  return result ? 1 : 0;
}
