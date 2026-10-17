#ifndef MSN_COREBLUETOOTH_BRIDGE_H
#define MSN_COREBLUETOOTH_BRIDGE_H

// cbt_scan listens for LE advertisements for duration_seconds and returns a
// malloc'd JSON string holding the radio state and the peripherals heard, which
// the caller owns and must release with cbt_free. Returns NULL only when the
// payload cannot be serialized.
char *cbt_scan(double duration_seconds);

// cbt_authorization returns the process's CBManagerAuthorization without
// prompting.
int cbt_authorization(void);

void cbt_free(char *s);

#endif // MSN_COREBLUETOOTH_BRIDGE_H
