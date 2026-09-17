/* selector.h - boolean selectors over the device table */
#ifndef SELECTOR_H
#define SELECTOR_H
#include "lanternet.h"

/* Evaluate a selector against one host. NULL/empty selector matches everything. */
int sel_match(const struct host *h, const char *sel);
/* Syntax check: 1 = ok, 0 = malformed. NULL/empty is valid. */
int sel_valid(const char *sel);
/* Human description of a host's tags ("random-mac", "v6", ...) as a comma list,
   or "" if none. */
void host_tags(const struct host *h, char *out, int n);

#endif
