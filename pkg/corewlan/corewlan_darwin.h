#ifndef MSN_COREWLAN_BRIDGE_H
#define MSN_COREWLAN_BRIDGE_H

// cw_scan performs a Wi-Fi scan and returns a malloc'd JSON string that the
// caller owns and must release with cw_free. Returns NULL when the host has no
// Wi-Fi interface.
char *cw_scan(void);

// cw_current returns the current association as a malloc'd JSON string in the
// same shape as cw_scan, with at most one network. Returns NULL when the host
// has no Wi-Fi interface.
char *cw_current(void);

void cw_free(char *s);

#endif // MSN_COREWLAN_BRIDGE_H
