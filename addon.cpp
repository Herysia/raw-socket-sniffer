#include <node_object_wrap.h>
#include "uv.h"
#include <mstcpip.h>
#include <iostream>
#include <napi.h>

// Various sizes and offsets for our packet read buffer.
#define BUFFER_SIZE_PKT ((256 * 256) - 1)
#define BUFFER_SIZE_ETH 14
#define BUFFER_SIZE_IP (BUFFER_SIZE_PKT - BUFFER_SIZE_ETH)
#define BUFFER_OFFSET_IP BUFFER_SIZE_ETH

struct PacketEventData
{
    unsigned char *pkt_data;
    UINT copy_len;
};
class RawSocketCapture : public Napi::ObjectWrap<RawSocketCapture>
{
    SOCKET sd;
    FD_SET readSet;
    int port;

    unsigned char *buffer;
    UINT errorCode = 0;

    DWORD handle;
    struct sockaddr_in addr;
    int dwIoControlCode;

    Napi::ThreadSafeFunction tsEmit_;
    uv_async_t async;
    HANDLE wait;
    HANDLE recvEvent;

    WSAEVENT eventHandle;

    void close(const Napi::CallbackInfo &info)
    {
        if (sd != 0)
        {
            closesocket(sd);
            sd = -1;
        }
    }
    static void CALLBACK OnPacket(void *data, BOOLEAN didTimeout)
    {
        uv_async_t *async = (uv_async_t *)data;
        int r = uv_async_send(async);
    }
    static void cb_packets(uv_async_t *handle)
    {
        // std::cout << "cb_packets - we got an event, consume all data" << std::endl;
        RawSocketCapture *obj = (RawSocketCapture *)handle->data;
        /*
        int rc = select(0, &obj->readSet, NULL, NULL, NULL); // We get data

        if (rc == SOCKET_ERROR)
        {
            std::cout << WSAGetLastError() << std::endl;
            obj->tsEmit_.Release();
            //  TODO: emit close/error ?
            return;
        }
        */
        while (true)
        {
            int errorCode = handle_packet(handle); // consume all data
            if (errorCode == WSAEWOULDBLOCK)
            {
                break;
            }
            if (errorCode)
            {
                obj->tsEmit_.Release();
                //  TODO: emit close/error ?
                return;
            }
        }
        // std::cout << "done - out of data" << std::endl;
    }
    static int handle_packet(uv_async_t *handle)
    {
        int errorCode = 0;
        RawSocketCapture *obj = (RawSocketCapture *)handle->data;
        // unsigned char buffer[65536];
        unsigned char *buffer = obj->buffer;
        // We should have concurent calls anymore so we're fine
        //  TODO: we don't want to allocate
        //   Read the next packet, should not block as we checked for the event earlier
        int rc = recv(obj->sd, (char *)(buffer + BUFFER_OFFSET_IP), BUFFER_SIZE_IP, 0);
        if (rc == SOCKET_ERROR)
        {
            return WSAGetLastError();
        }
        if (rc == 0) // End of file for some strange reason, so stop reading packets.
        {
            errorCode = -1;
            return errorCode;
        }
        // filter port
        uint8_t ipHeaderLen = (buffer[BUFFER_OFFSET_IP] & 0x0f) * 4;
        if (rc < ipHeaderLen + 4)
        {
            return 0; // malformed data: silent (probably not TCP packet, not long enough to contain ports
        }
        uint8_t protocol = buffer[BUFFER_OFFSET_IP + 9];
        if (protocol != 6) // check for tcp
        {

            return 0; // ignore UDP (or any other if pkt is malformed)
        }
        // filter port
        uint16_t srcport = (buffer[BUFFER_OFFSET_IP + ipHeaderLen] << 8) | buffer[BUFFER_OFFSET_IP + ipHeaderLen + 1];
        uint16_t dstport = (buffer[BUFFER_OFFSET_IP + ipHeaderLen + 2] << 8) | buffer[BUFFER_OFFSET_IP + ipHeaderLen + 3];
        if (obj->port == 0 || srcport == obj->port || dstport == obj->port)
        {

            // std::cout << srcport << "->" << dstport << std::endl;
            //  Store for dispatch
            auto packetLen = rc + BUFFER_SIZE_ETH;
            // Build fake eth header
            // memset(buffer, 0, 14);
            // buffer[12] = 0x08;
            PacketEventData *eventData = new PacketEventData;
            // We save to a new buffer, as we will use a nonblocking emit, to keep this thread receiving packets
            unsigned char *pktbuff = (unsigned char *)malloc(packetLen);
            memcpy(pktbuff, buffer, packetLen);
            eventData->copy_len = packetLen;
            eventData->pkt_data = pktbuff;
            auto cb = [](Napi::Env env, Napi::Function jsCallback, PacketEventData *data)
            {
                jsCallback.Call({Napi::String::New(env, "data"), Napi::Buffer<unsigned char>::Copy(env, data->pkt_data, data->copy_len)});
                free(data->pkt_data);
            };
            obj->tsEmit_.BlockingCall(eventData, cb);
        }
        return 0;
    }

public:
    RawSocketCapture(const Napi::CallbackInfo &info) : Napi::ObjectWrap<RawSocketCapture>(info)
    {

        Napi::Env env = info.Env();
        if (!info.IsConstructCall())
        {
            Napi::Error::New(env, "Use `new` to create instances of this object, Usage: new RawSocket(ip, port)").ThrowAsJavaScriptException();
            return;
        }
        if (info.Length() < 2)
        {
            Napi::Error::New(env, "Not enough parameters, Usage: new RawSocket(ip, port)").ThrowAsJavaScriptException();
            return;
        }
        if (!info[0].IsString())
        {
            Napi::Error::New(env, "ip must be a string").ThrowAsJavaScriptException();
            return;
        }
        if (!info[1].IsNumber())
        {
            Napi::Error::New(env, "port must be a number").ThrowAsJavaScriptException();
            return;
        }
        std::string ip_address = info[0].As<Napi::String>().Utf8Value();
        // Captured IP packets sent and received by the network interface the
        // specified IP address is associated with.
        addr.sin_family = AF_INET;
        // addr.sin_addr.s_addr = inet_addr(argv[1]);
        addr.sin_addr.s_addr = inet_addr(ip_address.c_str());
        addr.sin_port = htons(0);
        port = info[1].As<Napi::Number>();
        wait = nullptr;
    }
    void Listen(const Napi::CallbackInfo &info)
    {
        Napi::Env env = info.Env();
        Napi::Function emit = info.This().As<Napi::Object>().Get("emit").As<Napi::Function>();
        Napi::Function bound = emit.Get("bind").As<Napi::Function>().Call(emit, {info.This()}).As<Napi::Function>();
        this->tsEmit_ = Napi::ThreadSafeFunction::New(
            bound.Env(),
            bound,    // JavaScript function called asynchronously
            "packet", // Name
            0,        // Unlimited queue
            1         // Only one thread will use this initially
        );
        // init buffer
        buffer = (unsigned char *)malloc(BUFFER_SIZE_PKT);
        memset(buffer, 0, BUFFER_SIZE_PKT);
        buffer[12] = 0x08;

        // Windows winsock requires this.
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        // Create a raw socket which supports IPv4 only.
        sd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (sd == INVALID_SOCKET)
        {
            Napi::Error::New(env, "socket() failed").ThrowAsJavaScriptException();
            return;
        }
        FD_ZERO(&this->readSet);
        FD_SET(sd, &this->readSet);

        // Bind the socket to the specified IP address.
        int rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
        if (rc == SOCKET_ERROR)
        {
            close(info);
            Napi::Error::New(env, "bind() failed").ThrowAsJavaScriptException();
            return;
        }
        // Give us ALL IPv4 packets sent and received to the specific IP address.
        dwIoControlCode = RCVALL_IPLEVEL;

        rc = WSAIoctl(sd, SIO_RCVALL, &dwIoControlCode, sizeof(dwIoControlCode), NULL, 0, &handle, NULL, NULL);
        if (rc == SOCKET_ERROR)
        {
            close(info);
            Napi::Error::New(env, "WSAIoctl() failed").ThrowAsJavaScriptException();
            return;
        }

        u_long mode = 1; // 1 to enable non-blocking socket
        ioctlsocket(sd, FIONBIO, &mode);

        int r = uv_async_init(uv_default_loop(),
                              &this->async,
                              (uv_async_cb)RawSocketCapture::cb_packets);
        eventHandle = WSACreateEvent();
        WSAEventSelect(sd, eventHandle, FD_READ);
        this->async.data = this;
        r = RegisterWaitForSingleObject(
            &this->wait,
            eventHandle,
            RawSocketCapture::OnPacket,
            &this->async,
            INFINITE,
            WT_EXECUTEINWAITTHREAD);
        if (!r)
        {
            char *errmsg = nullptr;
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          nullptr,
                          GetLastError(),
                          MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                          (LPTSTR)&errmsg,
                          0,
                          nullptr);
            Napi::TypeError::New(env, errmsg).ThrowAsJavaScriptException();
            return;
        }
    }
    static Napi::Function Init(Napi::Env env, Napi::Object exports)
    {

        Napi::Function func = DefineClass(
            env,
            "RawSocketCapture",
            {
                RawSocketCapture::InstanceMethod("listen", &RawSocketCapture::Listen),
            });
        exports.Set("RawSocketCapture", func);
    }
};
Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    RawSocketCapture::Init(env, exports);
    return exports;
}
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)