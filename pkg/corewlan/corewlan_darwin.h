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

// cw_interfaces returns a malloc'd JSON array of Wi-Fi interface names.
char *cw_interfaces(void);

// cw_saved_networks returns a malloc'd JSON array of remembered network names,
// or NULL when the host has no Wi-Fi interface.
char *cw_saved_networks(void);

// The action calls below return NULL on success, or a malloc'd error message
// the caller owns and must release with cw_free.
char *cw_associate(const char *ssid, const char *password);
char *cw_disassociate(void);
char *cw_set_power(int on);
char *cw_forget(const char *ssid);

void cw_free(char *s);

#endif // MSN_COREWLAN_BRIDGE_H
