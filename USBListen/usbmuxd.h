#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <err.h>

#import <Foundation/Foundation.h>

typedef uint32_t USBMuxPacketType;
enum {
  USBMuxPacketTypeResult = 1,
	USBMuxPacketTypeConnect = 2,
	USBMuxPacketTypeListen = 3,
  USBMuxPacketTypeDeviceAdd = 4,
  USBMuxPacketTypeDeviceRemove = 5,
  // ? = 6,
  // ? = 7,
  USBMuxPacketTypePlistPayload = 8,
};

typedef uint32_t USBMuxPacketProtocol;
enum {
  USBMuxPacketProtocolBinary = 0,
  USBMuxPacketProtocolPlist = 1,
};

typedef uint32_t USBMuxReplyCode;
enum {
  USBMuxReplyCodeOK = 0,
  USBMuxReplyCodeBadCommand = 1,
  USBMuxReplyCodeBadDevice = 2,
  USBMuxReplyCodeConnectionRefused = 3,
  // ? = 4,
  // ? = 5,
  USBMuxReplyCodeBadVersion = 6,
};


typedef struct usbmux_packet {
  uint32_t size;
  USBMuxPacketProtocol protocol;
  USBMuxPacketType type;
  uint32_t tag;
  char data[0];
} __attribute__((__packed__)) usbmux_packet_t;

static const uint32_t kUsbmuxPacketMaxPayloadSize = UINT32_MAX - (uint32_t)sizeof(usbmux_packet_t);


static uint32_t usbmux_packet_payload_size(usbmux_packet_t *upacket) {
  return upacket->size - sizeof(usbmux_packet_t);
}


static void *usbmux_packet_payload(usbmux_packet_t *upacket) {
  return (void*)upacket->data;
}


static void usbmux_packet_set_payload(usbmux_packet_t *upacket,
                                      const void *payload,
                                      uint32_t payloadLength)
{
  memcpy(usbmux_packet_payload(upacket), payload, payloadLength);
}


static usbmux_packet_t *usbmux_packet_alloc(uint32_t payloadSize) {
  assert(payloadSize <= kUsbmuxPacketMaxPayloadSize);
  uint32_t upacketSize = sizeof(usbmux_packet_t) + payloadSize;
  usbmux_packet_t *upacket = CFAllocatorAllocate(kCFAllocatorDefault, upacketSize, 0);
  memset(upacket, 0, sizeof(usbmux_packet_t));
  upacket->size = upacketSize;
  return upacket;
}


static usbmux_packet_t *usbmux_packet_create(USBMuxPacketProtocol protocol,
                                             USBMuxPacketType type,
                                             uint32_t tag,
                                             const void *payload,
                                             uint32_t payloadSize)
{
  usbmux_packet_t *upacket = usbmux_packet_alloc(payloadSize);
  if (!upacket) {
    return NULL;
  }
  
  upacket->protocol = protocol;
  upacket->type = type;
  upacket->tag = tag;
  
  if (payload && payloadSize) {
    usbmux_packet_set_payload(upacket, payload, (uint32_t)payloadSize);
  }
  
  return upacket;
}


static void usbmux_packet_free(usbmux_packet_t *upacket) {
  CFAllocatorDeallocate(kCFAllocatorDefault, upacket);
}
