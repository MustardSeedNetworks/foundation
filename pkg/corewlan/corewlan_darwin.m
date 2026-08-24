#import <CoreLocation/CoreLocation.h>
#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

#include <stdlib.h>
#include <string.h>

#include "corewlan_darwin.h"

// Upper bound on waiting for locationd to report the process's real grant.
static const NSTimeInterval cw_auth_settle_seconds = 2.0;

// Location Services authorization is what un-redacts SSID and BSSID. Without it
// CoreWLAN still returns networks, so this is the only reliable way to tell a
// genuinely empty airspace from a redacted one.
//
// The first CLLocationManager in a process connects to locationd asynchronously
// and reports kCLAuthorizationStatusNotDetermined until that completes, so a
// freshly-created manager reads as unauthorized even when the grant is held.
// Create one manager for the process lifetime and let it settle before trusting
// the first read.
static BOOL cw_authorized(void) {
  static CLLocationManager *manager;
  static dispatch_once_t once;

  dispatch_once(&once, ^{
    manager = [[CLLocationManager alloc] init];

    NSDate *deadline =
        [NSDate dateWithTimeIntervalSinceNow:cw_auth_settle_seconds];
    while (manager.authorizationStatus == kCLAuthorizationStatusNotDetermined &&
           [deadline timeIntervalSinceNow] > 0) {
      [[NSRunLoop currentRunLoop]
             runMode:NSDefaultRunLoopMode
          beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
    }
  });

  return manager.authorizationStatus == kCLAuthorizationStatusAuthorizedAlways;
}

static int cw_band(CWChannelBand b) {
  switch (b) {
  case kCWChannelBand2GHz:
    return 2;
  case kCWChannelBand5GHz:
    return 5;
  case kCWChannelBand6GHz:
    return 6;
  default:
    return 0;
  }
}

static int cw_width(CWChannelWidth w) {
  switch (w) {
  case kCWChannelWidth20MHz:
    return 20;
  case kCWChannelWidth40MHz:
    return 40;
  case kCWChannelWidth80MHz:
    return 80;
  case kCWChannelWidth160MHz:
    return 160;
  default:
    return 0;
  }
}

static NSString *cw_phy(CWPHYMode p) {
  switch (p) {
  case kCWPHYMode11a:
    return @"802.11a";
  case kCWPHYMode11b:
    return @"802.11b";
  case kCWPHYMode11g:
    return @"802.11g";
  case kCWPHYMode11n:
    return @"802.11n";
  case kCWPHYMode11ac:
    return @"802.11ac";
  case kCWPHYMode11ax:
    return @"802.11ax";
  default:
    return @"";
  }
}

static NSString *cw_security(CWSecurity s) {
  switch (s) {
  case kCWSecurityNone:
    return @"none";
  case kCWSecurityWEP:
    return @"wep";
  case kCWSecurityWPAPersonal:
    return @"wpaPersonal";
  case kCWSecurityWPAPersonalMixed:
    return @"wpaPersonalMixed";
  case kCWSecurityWPA2Personal:
    return @"wpa2Personal";
  case kCWSecurityWPA3Personal:
    return @"wpa3Personal";
  case kCWSecurityWPA3Transition:
    return @"wpa3Transition";
  case kCWSecurityWPAEnterprise:
    return @"wpaEnterprise";
  case kCWSecurityWPA2Enterprise:
    return @"wpa2Enterprise";
  case kCWSecurityWPA3Enterprise:
    return @"wpa3Enterprise";
  case kCWSecurityEnterprise:
    return @"enterprise";
  default:
    return @"";
  }
}

// CWNetwork has no security property; the framework only answers yes/no per
// scheme. Probe strongest-first and report the first match, which is what a
// client would negotiate.
static NSString *cw_network_security(CWNetwork *n) {
  const CWSecurity ordered[] = {
      kCWSecurityWPA3Enterprise,
      kCWSecurityWPA3Personal,
      kCWSecurityWPA3Transition,
      kCWSecurityWPA2Enterprise,
      kCWSecurityWPA2Personal,
      kCWSecurityWPAEnterprise,
      kCWSecurityWPAPersonalMixed,
      kCWSecurityWPAPersonal,
      kCWSecurityWEP,
      kCWSecurityNone,
  };
  for (size_t i = 0; i < sizeof(ordered) / sizeof(ordered[0]); i++) {
    if ([n supportsSecurity:ordered[i]]) {
      return cw_security(ordered[i]);
    }
  }
  return @"";
}

static NSDictionary *cw_network_dict(CWNetwork *n) {
  return @{
    @"ssid" : n.ssid ?: @"",
    @"bssid" : n.bssid ?: @"",
    @"rssi" : @(n.rssiValue),
    @"noise" : @(n.noiseMeasurement),
    @"channel" : @(n.wlanChannel.channelNumber),
    @"width" : @(cw_width(n.wlanChannel.channelWidth)),
    @"band" : @(cw_band(n.wlanChannel.channelBand)),
    // CWNetwork reports no PHY mode; only a live association does.
    @"phyMode" : @"",
    @"security" : cw_network_security(n),
  };
}

// cw_encode serializes the payload and hands ownership of a C string to the
// caller. Returns NULL if serialization fails, which callers treat as no
// interface — there is no partial-result case worth reporting.
static char *cw_encode(NSDictionary *payload) {
  NSError *err = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:payload
                                                 options:0
                                                   error:&err];
  if (!data || err) {
    return NULL;
  }
  char *out = malloc(data.length + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, data.bytes, data.length);
  out[data.length] = '\0';
  return out;
}

char *cw_scan(void) {
  @autoreleasepool {
    CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
    if (!iface) {
      return NULL;
    }

    NSError *err = nil;
    NSSet<CWNetwork *> *found = [iface scanForNetworksWithSSID:nil
                                                 includeHidden:YES
                                                         error:&err];

    NSMutableArray *networks = [NSMutableArray arrayWithCapacity:found.count];
    for (CWNetwork *n in found) {
      [networks addObject:cw_network_dict(n)];
    }

    return cw_encode(
        @{@"authorized" : @(cw_authorized()),
          @"networks" : networks});
  }
}

char *cw_current(void) {
  @autoreleasepool {
    CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
    if (!iface) {
      return NULL;
    }

    NSMutableArray *networks = [NSMutableArray array];
    if (iface.ssid || iface.bssid) {
      [networks addObject:@{
        @"ssid" : iface.ssid ?: @"",
        @"bssid" : iface.bssid ?: @"",
        @"rssi" : @(iface.rssiValue),
        @"noise" : @(iface.noiseMeasurement),
        @"channel" : @(iface.wlanChannel.channelNumber),
        @"width" : @(cw_width(iface.wlanChannel.channelWidth)),
        @"band" : @(cw_band(iface.wlanChannel.channelBand)),
        @"phyMode" : cw_phy(iface.activePHYMode),
        @"security" : cw_security(iface.security),
      }];
    }

    return cw_encode(
        @{@"authorized" : @(cw_authorized()),
          @"networks" : networks});
  }
}

void cw_free(char *s) { free(s); }
