#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <dispatch/dispatch.h>

#import <Foundation/Foundation.h>
#import "usbmuxd.h"


void send_connect_usb_packet(void);
void communicate_to_idevice(void);
void send_msg(NSString *msg);

void read_packet_on_channle(dispatch_io_t channel);

dispatch_queue_t usbmuxd_io_queue;
void (^err_handler)(int);
static NSNumber *deviceID;
static int port = 2345;
static int address = INADDR_LOOPBACK;

void print_empty_lines() {
    printf("\n\n\n");
}

static dispatch_io_t listen_channel;
static dispatch_io_t connect_channel;

int connect_to_usbmuxd() {
    // Create Unix domain socket
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    // prevent SIGPIPE
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));

    // Connect socket
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    // 这个路径就相当于ip地址，为了理解这个过程，可以和TCP进行对比
    strcpy(addr.sun_path, "/var/run/usbmuxd");
    socklen_t socklen = sizeof(addr);

    if (connect(fd, (struct sockaddr *)&addr, socklen) == -1) {
        printf("Connect failure, fd is: %d.\n", fd);
    } else {
        printf("Connect successifully, fd is: %d.\n", fd);
    }

    return fd;
}

dispatch_io_t connect_to_usbmuxd_channel() {
    int fd = connect_to_usbmuxd();
    dispatch_io_t channel = dispatch_io_create(DISPATCH_IO_STREAM, fd, usbmuxd_io_queue, err_handler);
    return channel;
}

void send_packet(NSDictionary *packetDict, int tag, dispatch_io_t channel) {
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:packetDict format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    
    int protocol = USBMuxPacketProtocolPlist;
    int type = USBMuxPacketTypePlistPayload;
    
    usbmux_packet_t *upacket = usbmux_packet_create(
                                                    protocol,
                                                    type,
                                                    tag,
                                                    plistData ? plistData.bytes : nil,
                                                    (uint32_t)(plistData.length)
                                                    );
    
    dispatch_data_t data = dispatch_data_create((const void*)upacket, upacket->size, usbmuxd_io_queue, ^{
        usbmux_packet_free(upacket);
    });
    
    dispatch_io_write(channel, 0, data, usbmuxd_io_queue, ^(bool done, dispatch_data_t data, int _errno) {
        NSLog(@"dispatch_io_write: done=%d data=%p error=%d", done, data, _errno);
        if (!done) { return; }
    });
}

void send_listen_packet() {
    listen_channel = connect_to_usbmuxd_channel();
    
    NSDictionary *packet = @{
                             @"ClientVersionString": @"1",
                             @"MessageType": @"Listen",
                             @"ProgName": @"Peertalk Example"
                             };
    NSLog(@"send listen packet: %@", packet);
    send_packet(packet, 0, listen_channel);
}


void read_packet_on_channle(dispatch_io_t channel) {
    // Read
    usbmux_packet_t ref_upacket;
    dispatch_io_read(channel, 0, sizeof(ref_upacket.size), usbmuxd_io_queue, ^(bool done, dispatch_data_t  _Nullable data, int error) {
        NSLog(@"dispatch_io_read 0, %lu: done=%d data=%p error=%d", sizeof(ref_upacket.size), done, data, error);
        
        if (!done) { return; }
        
        // Read size of incoming usbmux_packet_t
        uint32_t upacket_len = 0;
        char *buffer = NULL;
        size_t buffer_size = 0;
        // data 是读取到的数据，这一步获取到读取到的data的长度，并将buffer指向对应的缓冲区
        dispatch_data_t map_data = dispatch_data_create_map(data, (const void **)&buffer, &buffer_size);
        assert(buffer_size == sizeof(ref_upacket.size));
        assert(sizeof(upacket_len) == sizeof(ref_upacket.size));
        memcpy((void *)&(upacket_len), (const void *)buffer, buffer_size);
        
        // Allocate a new usbmux_packet_t for the expected size
        uint32_t payloadLength = upacket_len - (uint32_t)sizeof(usbmux_packet_t);
        usbmux_packet_t *upacket = usbmux_packet_alloc(payloadLength);
        
        // Read rest of the incoming usbmux_packet_t
        off_t offset = sizeof(ref_upacket.size);
        dispatch_io_read(channel, offset, upacket->size - offset, usbmuxd_io_queue, ^(bool done, dispatch_data_t data, int error) {
            NSLog(@"dispatch_io_read %lld,%lld: done=%d data=%p error=%d", offset, upacket->size - offset, done, data, error);
            
            if (!done) { return; }
            
            // Copy read bytes onto our usbmux_packet_t
            char *buffer = NULL;
            size_t buffer_size = 0;
            dispatch_data_t map_data = dispatch_data_create_map(data, (const void **)&buffer, &buffer_size);
            assert(buffer_size == upacket->size - offset);
            memcpy(((void *)(upacket))+offset, (const void *)buffer, buffer_size);
            NSLog(@"package protocol is: %u, type is: %u", upacket->protocol, upacket->type);
            
            // Try to decode any payload as plist
            NSError *err = nil;
            NSDictionary *dict = nil;
            if (usbmux_packet_payload_size(upacket)) {
                dict = [NSPropertyListSerialization propertyListWithData:[NSData dataWithBytesNoCopy:usbmux_packet_payload(upacket) length:usbmux_packet_payload_size(upacket) freeWhenDone:NO] options:NSPropertyListImmutable format:NULL error:&err];
            }
            NSLog(@"packaget tag is: %u, payload is: %@", upacket->tag, dict);
            
            
            if (dict[@"DeviceID"]) {
                deviceID = dict[@"DeviceID"];
                send_connect_usb_packet();
            }
            
            if ([dict[@"Number"] integerValue] == 0 && upacket->tag == 1) {
                NSLog(@"connected.");
                communicate_to_idevice();
                usbmux_packet_free(upacket);
                return;
            }
            
            // Invoke callback
//            callback(err, dict, upacket->tag);
            
            // Read next
            read_packet_on_channle(channel);
            
            usbmux_packet_free(upacket);
        });
        
    });
    
}

void listen_usb() {
    // 向usbmuxd发送一个Listen的报文，表明要监听iDevice的插拔事件
    send_listen_packet();
    read_packet_on_channle(listen_channel);
    
    NSLog(@"end call listen_usb");
}




void send_connect_usb_packet() {
    print_empty_lines();
    
    connect_channel = connect_to_usbmuxd_channel();
    

    port = ((port<<8) & 0xFF00) | (port>>8);
    NSDictionary *packet = @{
                             @"ClientVersionString" : @"1",
                             @"DeviceID" : deviceID,
                             @"MessageType" : @"Connect",
                             @"PortNumber" : [NSNumber numberWithInt:port],
                             @"ProgName" : @"Peertalk Example"
                             };
    
    NSLog(@"send connect to usb packet: %@", packet);
    send_packet(packet, 1, connect_channel);
    read_packet_on_channle(connect_channel);
}

typedef struct _PTExampleTextFrame {
    uint32_t length;
    uint8_t utf8text[0];
} PTExampleTextFrame;


static dispatch_data_t PTExampleTextDispatchDataWithString(NSString *message) {
    // Use a custom struct
    const char *utf8text = [message cStringUsingEncoding:NSUTF8StringEncoding];
    size_t length = strlen(utf8text);
    PTExampleTextFrame *textFrame = CFAllocatorAllocate(nil, sizeof(PTExampleTextFrame) + length, 0);
    memcpy(textFrame->utf8text, utf8text, length); // Copy bytes to utf8text array
    textFrame->length = htonl(length); // Convert integer to network byte order
    
    // Wrap the textFrame in a dispatch data object
    return dispatch_data_create((const void*)textFrame, sizeof(PTExampleTextFrame)+length, nil, ^{
        CFAllocatorDeallocate(nil, textFrame);
    });
}

// This is what we send as the header for each frame.
typedef struct _PTFrame {
    // The version of the frame and protocol.
    uint32_t version;
    
    // Type of frame
    uint32_t type;
    
    // Unless zero, a tag is retained in frames that are responses to previous
    // frames. Applications can use this to build transactions or request-response
    // logic.
    uint32_t tag;
    
    // If payloadSize is larger than zero, *payloadSize* number of bytes are
    // following, constituting application-specific data.
    uint32_t payloadSize;
    
} PTFrame;


dispatch_data_t createDispatchDataWithFrameOfType(uint32_t type, uint32_t frameTag, dispatch_data_t payload) {
    PTFrame *frame = CFAllocatorAllocate(kCFAllocatorDefault, sizeof(PTFrame), 0);
    frame->version = htonl(1);
    frame->type = htonl(type);
    frame->tag = htonl(frameTag);
    
    if (payload) {
        size_t payloadSize = dispatch_data_get_size(payload);
        assert(payloadSize <= UINT32_MAX);
        frame->payloadSize = htonl((uint32_t)payloadSize);
    } else {
        frame->payloadSize = 0;
    }
    
    dispatch_data_t frameData = dispatch_data_create((const void*)frame, sizeof(PTFrame), usbmuxd_io_queue, ^{
        CFAllocatorDeallocate(kCFAllocatorDefault, (void*)frame);
    });
    
    if (payload && frame->payloadSize != 0) {
        // chain frame + payload
        dispatch_data_t data = dispatch_data_create_concat(frameData, payload);
#if PT_DISPATCH_RETAIN_RELEASE
        dispatch_release(frameData);
#endif
        frameData = data;
    }
    
    return frameData;
}

void communicate_to_idevice() {
    NSString *msg = @"Hello iPhone. I am mac.";

    send_msg(msg);
}

void send_msg(NSString *msg) {
    dispatch_data_t payload = PTExampleTextDispatchDataWithString(msg);
    dispatch_data_t frame = createDispatchDataWithFrameOfType(101, 0, payload);
    
    NSLog(@"connect_channel is: %@", connect_channel);
    NSLog(@"listen_channel is: %@", listen_channel);
    
    // send through connect channel, not tcp_channel
    dispatch_io_write(connect_channel, 0, frame, usbmuxd_io_queue, ^(bool done, dispatch_data_t  _Nullable data, int error) {
        NSLog(@"error is: %d", error);
    });
}



int main(int argc, char const *argv[]) {
    usbmuxd_io_queue = dispatch_queue_create("usbmuxd_io_queue", NULL);
//    usbmuxd_io_queue = dispatch_get_main_queue();
    err_handler = ^(int error) {
        printf("Error is: %d\n", error);
    };

    listen_usb();
    
    [[NSRunLoop currentRunLoop] run];
    
    return 0;
}
