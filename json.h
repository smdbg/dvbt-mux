/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DVB_MUX_JSON_H
#define DVB_MUX_JSON_H
#include <stddef.h>
enum json_type { J_OBJECT, J_ARRAY, J_STRING, J_PRIMITIVE };
struct json_token {
  enum json_type type;
  size_t start, end;
  int after, children;
};
struct json {
  char *text;
  struct json_token *tokens;
  int count;
};
int json_load(struct json *, const char *, char *, size_t);
void json_free(struct json *);
int json_get(const struct json *, int, const char *);
int json_string(const struct json *, int, char *, size_t);
int json_integer(const struct json *, int, long long *);
int json_boolean(const struct json *, int, int *);
#endif
