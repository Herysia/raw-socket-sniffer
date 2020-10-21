// Copyright 2018 NoSpaceships Ltd

#include <napi.h>
#include <iostream>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <thread>

// We use defines and structures copied from libpcap to synthesize a PCAP file.
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define DLT_EN10MB 1

struct pcap_timeval {
    int32_t tv_sec;
    int32_t tv_usec;
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;
    uint32_t caplen;
    uint32_t len;
};

// Various sizes and offsets for our packet read buffer.
#define BUFFER_SIZE_HDR sizeof(struct pcap_sf_pkthdr)
#define BUFFER_SIZE_PKT ((256 * 256) - 1)
#define BUFFER_SIZE_ETH 14
#define BUFFER_SIZE_IP (BUFFER_SIZE_PKT - BUFFER_SIZE_ETH)
#define BUFFER_OFFSET_ETH sizeof(struct pcap_sf_pkthdr)
#define BUFFER_OFFSET_IP (BUFFER_OFFSET_ETH + BUFFER_SIZE_ETH)

// A couple of defines used to calculate high resolution timestamps.
#define EPOCH_BIAS 116444736000000000
#define UNITS_PER_SEC 10000000

using namespace Napi;

std::thread nativeThread;
ThreadSafeFunction tsfn;

const unsigned char* _END_OF_PACKET_ = reinterpret_cast<const unsigned char*>("_END_OF_PACKET_");

// Normally we would break this up into smaller functions, but here we lay out
// all the steps to capture packets using raw sockets one step after another.
Value sniff(const CallbackInfo& args) {
    Napi::Env env = args.Env();
    // Windows winsock requires this.
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    std::string std_str_ip_address = args[0].ToString().Utf8Value();
    const char* c_str_ip_address = std_str_ip_address.c_str();

    // Create a raw socket which supports IPv4 only.
    SOCKET sd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sd == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %u", WSAGetLastError());
        exit(-1);
    }

    // Captured IP packets sent and received by the network interface the
    // specified IP address is associated with.
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr = inet_addr(argv[1]);
    addr.sin_addr.s_addr = inet_addr(c_str_ip_address);
    addr.sin_port = htons(0);

    // Bind the socket to the specified IP address.
    int rc = bind(sd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed: %u", WSAGetLastError());
        exit(-1);
    }

    // Give us ALL IPv4 packets sent and received to the specific IP address.
    int value = RCVALL_IPLEVEL;
    DWORD out = 0;
    rc = WSAIoctl(sd, SIO_RCVALL, &value, sizeof(value), NULL, 0, &out, NULL, NULL);
    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "WSAIoctl() failed: %u", WSAGetLastError());
        exit(-1);
    }

    // First 14 bytes are a fake ethernet header with IPv4 as the protocol.
    unsigned char buffer[BUFFER_SIZE_HDR + BUFFER_SIZE_PKT];
    memset(buffer, 0, sizeof(buffer));
    buffer[BUFFER_OFFSET_ETH + 12] = 0x08;
    struct pcap_sf_pkthdr* pkt = (struct pcap_sf_pkthdr*)buffer;

    // Reuse this on each loop to calculate a high resolution timestamp.
    union {
        FILETIME ft_ft;
        uint64_t ft_64;
    } ft;

    // Create a ThreadSafeFunction
    tsfn = ThreadSafeFunction::New(
        env,
        args[1].As<Function>(),  // JavaScript function called asynchronously
        "Resource Name",         // Name
        0,                       // Unlimited queue
        1,                       // Only one thread will use this initially
        [](Env) {                // Finalizer used to clean threads up
            nativeThread.join();
        });

    // Create a native thread
    nativeThread = std::thread([&] {
        auto callback = [](Env env, Function jsCallback, unsigned char* value) {
            // Transform native data into JS data, passing it to the provided
            // `jsCallback` -- the TSFN's JavaScript function.
            jsCallback.Call({Number::New(env, *value)});

            // We're finished with the data.
            delete value;
        };

        // Read packets forever.
        while (true) {
            // Read the next packet, blocking forever.
            int rc = recv(sd, (char*)buffer + BUFFER_OFFSET_IP, BUFFER_SIZE_IP, 0);
            if (rc == SOCKET_ERROR) {
                fprintf(stderr, "recv() failed: %u", WSAGetLastError());
                exit(-1);
            }

            // End of file for some strange reason, so stop reading packets.
            if (rc == 0)
                break;

            // Calculate a high resolution timestamp for this packet.
            GetSystemTimeAsFileTime(&ft.ft_ft);
            ft.ft_64 -= EPOCH_BIAS;
            time_t ctime = (time_t)(ft.ft_64 / UNITS_PER_SEC);
            uint32_t ms = ft.ft_64 % UNITS_PER_SEC;

            // Set out PCAP packet header fields.
            pkt->ts.tv_sec = ctime;
            pkt->ts.tv_usec = ms;
            pkt->caplen = rc + BUFFER_SIZE_ETH;
            pkt->len = rc + BUFFER_SIZE_ETH;

            // loop through every byte of packet and send it to JavaScript
            int length = rc + BUFFER_SIZE_ETH + BUFFER_SIZE_HDR + 10;
            for (int i = 0; i < length; i++) {
                unsigned char* value = new unsigned char(buffer[i]);
                napi_status status = tsfn.BlockingCall(value, callback);
                if (i == length - 1) {
                    for (int j = 0; j < 15; j++) {
                        unsigned char* _END_ = new unsigned char(_END_OF_PACKET_[j]);
                        napi_status status = tsfn.BlockingCall(_END_, callback);
                    }
                }
            }
        }

        // Release the thread-safe function
        tsfn.Release();
    });

    // Our socket and file will be closed automatically.
    return Boolean::New(env, true);
}

Object Init(Env env, Object exports) {
    exports.Set("sniff", Function::New(env, sniff));
    return exports;
}

NODE_API_MODULE(sniff, Init)