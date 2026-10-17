#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>

#include <stdlib.h>
#include <string.h>

#include "corebluetooth_darwin.h"

// Upper bound on waiting for the central manager to report a settled state.
// A new manager starts in CBManagerStateUnknown and moves to its real state
// asynchronously, usually within a few hundred milliseconds.
static const int64_t cbt_state_settle_seconds = 5;

// CoreBluetooth reports this RSSI for a packet it could not measure.
static const NSInteger cbt_rssi_unavailable = 127;

// CBTScanner collects advertisements on its own serial queue. Every access to
// seen happens on that queue, so it needs no lock.
@interface CBTScanner : NSObject <CBCentralManagerDelegate>
@end

@implementation CBTScanner {
  dispatch_semaphore_t _settled;
  NSMutableDictionary<NSUUID *, NSMutableDictionary *> *_seen;
  NSMutableDictionary<NSUUID *, NSMutableOrderedSet<NSString *> *> *_services;
}

- (instancetype)init {
  if ((self = [super init])) {
    _settled = dispatch_semaphore_create(0);
    _seen = [NSMutableDictionary dictionary];
    _services = [NSMutableDictionary dictionary];
  }
  return self;
}

- (BOOL)waitForSettledState {
  return dispatch_semaphore_wait(
             _settled, dispatch_time(DISPATCH_TIME_NOW,
                                     cbt_state_settle_seconds * NSEC_PER_SEC)) ==
         0;
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
  if (central.state != CBManagerStateUnknown &&
      central.state != CBManagerStateResetting) {
    dispatch_semaphore_signal(_settled);
  }
}

// A peripheral sends its advertisement and its scan response as separate
// callbacks, often with the name only in one of them, so each callback adds to
// the peripheral's record rather than replacing it.
- (void)centralManager:(CBCentralManager *)central
    didDiscoverPeripheral:(CBPeripheral *)peripheral
        advertisementData:(NSDictionary<NSString *, id> *)adv
                     RSSI:(NSNumber *)rssi {
  NSUUID *key = peripheral.identifier;
  NSMutableDictionary *entry = _seen[key];
  if (!entry) {
    entry = [NSMutableDictionary dictionaryWithDictionary:@{
      @"identifier" : key.UUIDString,
      @"name" : @"",
      @"rssi" : @(cbt_rssi_unavailable),
      @"connectable" : @NO,
    }];
    _seen[key] = entry;
    _services[key] = [NSMutableOrderedSet orderedSet];
  }

  if (rssi.integerValue != cbt_rssi_unavailable) {
    entry[@"rssi"] = rssi;
  }

  NSString *name = adv[CBAdvertisementDataLocalNameKey] ?: peripheral.name;
  if (name.length > 0) {
    entry[@"name"] = name;
  }
  if ([adv[CBAdvertisementDataIsConnectable] boolValue]) {
    entry[@"connectable"] = @YES;
  }
  NSNumber *tx = adv[CBAdvertisementDataTxPowerLevelKey];
  if (tx) {
    entry[@"txPower"] = tx;
  }
  NSData *mfg = adv[CBAdvertisementDataManufacturerDataKey];
  if (mfg) {
    entry[@"manufacturerData"] = [mfg base64EncodedStringWithOptions:0];
  }
  for (CBUUID *uuid in adv[CBAdvertisementDataServiceUUIDsKey]) {
    [_services[key] addObject:uuid.UUIDString];
  }
}

- (NSArray *)peripherals {
  NSMutableArray *out = [NSMutableArray arrayWithCapacity:_seen.count];
  [_seen enumerateKeysAndObjectsUsingBlock:^(NSUUID *key,
                                             NSMutableDictionary *entry,
                                             BOOL *stop) {
    entry[@"serviceUuids"] = _services[key].array;
    [out addObject:entry];
  }];
  return out;
}
@end

static char *cbt_encode(NSDictionary *payload) {
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

char *cbt_scan(double duration_seconds) {
  @autoreleasepool {
    dispatch_queue_t queue = dispatch_queue_create(
        "com.mustardseednetworks.foundation.corebluetooth",
        DISPATCH_QUEUE_SERIAL);
    CBTScanner *scanner = [[CBTScanner alloc] init];

    // The power alert would ask a user at the console to switch Bluetooth on
    // for a scan they did not start; report the state instead.
    CBCentralManager *central = [[CBCentralManager alloc]
        initWithDelegate:scanner
                   queue:queue
                 options:@{CBCentralManagerOptionShowPowerAlertKey : @NO}];

    [scanner waitForSettledState];

    __block CBManagerState state;
    dispatch_sync(queue, ^{
      state = central.state;
      if (state == CBManagerStatePoweredOn) {
        [central scanForPeripheralsWithServices:nil
                                        options:@{
                                          CBCentralManagerScanOptionAllowDuplicatesKey :
                                              @YES
                                        }];
      }
    });

    __block NSArray *peripherals = @[];
    if (state == CBManagerStatePoweredOn) {
      [NSThread sleepForTimeInterval:duration_seconds];
      dispatch_sync(queue, ^{
        [central stopScan];
        peripherals = [scanner peripherals];
      });
    }

    // Detach the delegate on its own queue so no callback can arrive once the
    // scanner is released.
    dispatch_sync(queue, ^{
      central.delegate = nil;
    });

    return cbt_encode(@{@"state" : @(state), @"peripherals" : peripherals});
  }
}

int cbt_authorization(void) { return (int)CBManager.authorization; }

void cbt_free(char *s) { free(s); }
