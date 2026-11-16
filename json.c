/* SPDX-License-Identifier: GPL-2.0-only */
/* Bounded JSON reader for locally generated configuration. */
#include "json.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_JSON (256 * 1024)
#define MAX_TOKENS 16384
struct parser {
  struct json *j;
  size_t pos, size;
};
static void ws(struct parser *p) {
  while (p->pos < p->size && strchr(" \t\r\n", p->j->text[p->pos]))
    p->pos++;
}
static int hex(char c) {
  return c >= '0' && c <= '9'   ? c - '0'
         : c >= 'a' && c <= 'f' ? c - 'a' + 10
         : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                : -1;
}
static int value(struct parser *p, int depth) {
  ws(p);
  if (depth > 16 || p->pos >= p->size || p->j->count >= MAX_TOKENS)
    return -1;
  int id = p->j->count++;
  struct json_token *t = &p->j->tokens[id];
  t->start = p->pos;
  char c = p->j->text[p->pos++];
  if (c == '{' || c == '[') {
    t->type = c == '{' ? J_OBJECT : J_ARRAY;
    char end = c == '{' ? '}' : ']';
    ws(p);
    if (p->pos < p->size && p->j->text[p->pos] == end) {
      p->pos++;
      goto done;
    }
    for (;;) {
      if (c == '{' && (p->pos >= p->size || p->j->text[p->pos] != '"'))
        return -1;
      if (value(p, depth + 1) < 0)
        return -1;
      t->children++;
      if (c == '{') {
        ws(p);
        if (p->pos >= p->size || p->j->text[p->pos++] != ':')
          return -1;
        if (value(p, depth + 1) < 0)
          return -1;
        t->children++;
      }
      ws(p);
      if (p->pos >= p->size)
        return -1;
      char sep = p->j->text[p->pos++];
      if (sep == end)
        break;
      if (sep != ',')
        return -1;
      ws(p);
    }
  } else if (c == '"') {
    t->type = J_STRING;
    t->start = p->pos;
    int closed = 0;
    while (p->pos < p->size) {
      unsigned char x = p->j->text[p->pos++];
      if (x == '"') {
        closed = 1;
        break;
      }
      if (x < 32)
        return -1;
      if (x == '\\') {
        if (p->pos >= p->size)
          return -1;
        char esc = p->j->text[p->pos++];
        if (esc == 'u') {
          for (int n = 0; n < 4; n++)
            if (p->pos >= p->size || hex(p->j->text[p->pos++]) < 0)
              return -1;
        } else if (!strchr("\"\\/bfnrt", esc))
          return -1;
      }
    }
    if (!closed)
      return -1;
    t->end = p->pos - 1;
    t->after = p->j->count;
    return id;
  } else {
    t->type = J_PRIMITIVE;
    while (p->pos < p->size && !strchr(" \t\r\n,]}", p->j->text[p->pos]))
      p->pos++;
    size_t n = p->pos - t->start;
    const char *v = p->j->text + t->start;
    if (!((n == 4 && !memcmp(v, "true", 4)) ||
          (n == 5 && !memcmp(v, "false", 5)) ||
          (n == 4 && !memcmp(v, "null", 4)))) {
      size_t i = 0;
      if (i < n && v[i] == '-')
        i++;
      if (i == n)
        return -1;
      if (v[i] == '0')
        i++;
      else {
        if (v[i] < '1' || v[i] > '9')
          return -1;
        while (i < n && isdigit((unsigned char)v[i]))
          i++;
      }
      if (i < n && v[i] == '.') {
        i++;
        size_t begin = i;
        while (i < n && isdigit((unsigned char)v[i]))
          i++;
        if (i == begin)
          return -1;
      }
      if (i < n && (v[i] == 'e' || v[i] == 'E')) {
        i++;
        if (i < n && (v[i] == '+' || v[i] == '-'))
          i++;
        size_t begin = i;
        while (i < n && isdigit((unsigned char)v[i]))
          i++;
        if (i == begin)
          return -1;
      }
      if (i != n)
        return -1;
    }
  }
done:
  t->end = p->pos;
  t->after = p->j->count;
  return id;
}
int json_load(struct json *j, const char *path, char *error, size_t cap) {
  memset(j, 0, sizeof(*j));
  FILE *f = fopen(path, "rb");
  if (!f) {
    snprintf(error, cap, "%s: %s", path, strerror(errno));
    return -1;
  }
  j->text = calloc(MAX_JSON + 1, 1);
  j->tokens = calloc(MAX_TOKENS, sizeof(*j->tokens));
  if (!j->text || !j->tokens) {
    fclose(f);
    goto invalid;
  }
  size_t n = fread(j->text, 1, MAX_JSON + 1, f);
  int bad = ferror(f);
  fclose(f);
  if (bad || !n || n > MAX_JSON || memchr(j->text, 0, n))
    goto invalid;
  struct parser p = {j, 0, n};
  if (value(&p, 0) != 0)
    goto invalid;
  ws(&p);
  if (p.pos != n)
    goto invalid;
  return 0;
invalid:
  snprintf(error, cap, "Invalid or oversized JSON configuration");
  json_free(j);
  return -1;
}
void json_free(struct json *j) {
  free(j->text);
  free(j->tokens);
  memset(j, 0, sizeof(*j));
}
int json_string(const struct json *j, int id, char *out, size_t cap) {
  if (id < 0 || id >= j->count || j->tokens[id].type != J_STRING || !cap)
    return -1;
  size_t a = j->tokens[id].start, b = j->tokens[id].end, n = 0;
  while (a < b) {
    unsigned c = (unsigned char)j->text[a++];
    if (c == '\\') {
      c = (unsigned char)j->text[a++];
      if (c == 'u') {
        c = 0;
        for (int i = 0; i < 4; i++)
          c = (c << 4) | hex(j->text[a++]);
        if (c >= 0xd800 && c <= 0xdbff) {
          if (a + 6 > b || j->text[a] != '\\' || j->text[a + 1] != 'u')
            return -1;
          a += 2;
          unsigned lo = 0;
          for (int i = 0; i < 4; i++)
            lo = (lo << 4) | hex(j->text[a++]);
          if (lo < 0xdc00 || lo > 0xdfff)
            return -1;
          c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
        } else if (c >= 0xdc00 && c <= 0xdfff)
          return -1;
        if (c < 32)
          return -1;
        unsigned char utf[4];
        int k = 0;
        if (c < 128)
          utf[k++] = c;
        else if (c < 2048) {
          utf[k++] = 0xc0 | (c >> 6);
          utf[k++] = 0x80 | (c & 63);
        } else if (c < 65536) {
          utf[k++] = 0xe0 | (c >> 12);
          utf[k++] = 0x80 | ((c >> 6) & 63);
          utf[k++] = 0x80 | (c & 63);
        } else {
          utf[k++] = 0xf0 | (c >> 18);
          utf[k++] = 0x80 | ((c >> 12) & 63);
          utf[k++] = 0x80 | ((c >> 6) & 63);
          utf[k++] = 0x80 | (c & 63);
        }
        if (n + (size_t)k >= cap)
          return -1;
        memcpy(out + n, utf, k);
        n += k;
        continue;
      }
      if (c == 'b' || c == 'f' || c == 'n' || c == 'r' || c == 't')
        return -1;
    }
    if (c < 32 || n + 1 >= cap)
      return -1;
    out[n++] = c;
  }
  out[n] = 0;
  return 0;
}
int json_get(const struct json *j, int obj, const char *key) {
  if (obj < 0 || obj >= j->count || j->tokens[obj].type != J_OBJECT)
    return -1;
  for (int p = obj + 1; p < j->tokens[obj].after;) {
    char name[128];
    int val = p + 1;
    if (!json_string(j, p, name, sizeof(name)) && !strcmp(name, key))
      return val;
    p = j->tokens[val].after;
  }
  return -1;
}
int json_integer(const struct json *j, int id, long long *out) {
  if (id < 0 || id >= j->count || j->tokens[id].type != J_PRIMITIVE)
    return -1;
  size_t n = j->tokens[id].end - j->tokens[id].start;
  if (!n || n >= 32)
    return -1;
  char s[32];
  memcpy(s, j->text + j->tokens[id].start, n);
  s[n] = 0;
  char *end;
  errno = 0;
  long long v = strtoll(s, &end, 10);
  if (errno || *end)
    return -1;
  *out = v;
  return 0;
}
int json_boolean(const struct json *j, int id, int *out) {
  if (id < 0 || id >= j->count || j->tokens[id].type != J_PRIMITIVE)
    return -1;
  size_t n = j->tokens[id].end - j->tokens[id].start;
  const char *s = j->text + j->tokens[id].start;
  if (n == 4 && !memcmp(s, "true", 4)) {
    *out = 1;
    return 0;
  }
  if (n == 5 && !memcmp(s, "false", 5)) {
    *out = 0;
    return 0;
  }
  return -1;
}
