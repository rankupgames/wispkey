// In-process OS verification. No helper executable, shell command, credentials,
// cached approval token, or diagnostic output crosses this bridge.
#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>

static LAContext *freshContext(void) {
    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @"";
    context.localizedCancelTitle = @"Cancel fill";
    context.touchIDAuthenticationAllowableReuseDuration = 0;
    return context;
}

int wispkey_macos_biometry_available(void) {
    @autoreleasepool {
        LAContext *context = nil;
        @try {
            context = freshContext();
            return [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                        error:nil] ? 1 : 0;
        } @catch (NSException *exception) {
            return 0;
        } @finally {
            [context invalidate];
        }
    }
}

// 1 = verified, 0 = denial/cancellation/timeout, -1 = unavailable.
// The Rust caller retains the full immutable request and revalidates the vault
// transaction after this returns; this result is never an external capability.
int wispkey_macos_verify(const char *reason, const char *details, unsigned int seconds) {
    @autoreleasepool {
        LAContext *context = nil;
        NSWindow *window = nil;
        @try {
            if (![NSThread isMainThread] || seconds == 0 || seconds > 110) return -1;
            NSString *prompt = [NSString stringWithUTF8String:reason];
            NSString *metadata = [NSString stringWithUTF8String:details];
            if (prompt.length == 0 || metadata.length == 0) return -1;
            context = freshContext();
            if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil]) {
                return -1;
            }
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
            // Read-only full metadata, including untrusted labels, even if the OS
            // truncates its compact reason string. Closing this window cancels.
            window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 680, 440)
                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                backing:NSBackingStoreBuffered defer:NO];
            window.releasedWhenClosed = NO;
            window.title = @"WispKey — review browser fill";
            NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:window.contentView.bounds];
            scroll.hasVerticalScroller = YES;
            NSTextView *text = [[NSTextView alloc] initWithFrame:scroll.bounds];
            text.editable = NO;
            text.selectable = YES;
            text.font = [NSFont systemFontOfSize:15];
            text.textContainerInset = NSMakeSize(16, 16);
            text.string = metadata;
            scroll.documentView = text;
            window.contentView = scroll;
            [window center];
            [window makeKeyAndOrderFront:nil];

            dispatch_semaphore_t completed = dispatch_semaphore_create(0);
            __block BOOL verified = NO;
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                    localizedReason:prompt reply:^(BOOL success, NSError *error) {
                verified = success && error == nil;
                dispatch_semaphore_signal(completed);
            }];
            NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + seconds;
            int result = 0;
            while (window.visible && NSProcessInfo.processInfo.systemUptime < deadline) {
                if (dispatch_semaphore_wait(completed, DISPATCH_TIME_NOW) == 0) {
                    result = verified ? 1 : 0;
                    break;
                }
                NSEvent *event = [NSApp nextEventMatchingMask:NSEventMaskAny
                    untilDate:[NSDate dateWithTimeIntervalSinceNow:0.02]
                    inMode:NSDefaultRunLoopMode dequeue:YES];
                if (event) [NSApp sendEvent:event];
            }
            // Invalidate on every exit. A late callback only updates its retained
            // block storage and can never turn cancellation into approval.
            return result;
        } @catch (NSException *exception) {
            // Objective-C exceptions must never unwind through the Rust ABI.
            return -1;
        } @finally {
            [context invalidate];
            [window close];
        }
    }
}
