#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <winsock2.h>
#include <ws2tcpip.h>  // 包含 inet_ntop 函数声明

#include <QObject>
#include <pcap.h>

typedef struct ether_header {
    u_char  h_dest[6];    // 目的MAC地址
    u_char  h_source[6];  // 源MAC地址
    u_short h_proto;      // 上层协议类型
} ether_header;

// IP包头部结构定义
typedef struct ip_header {
    u_char  version_ihl;  // 版本号(4位) + 头部长度(4位)
    u_char  tos;          // 服务类型
    u_short total_len;    // 总长度
    u_short id;           // 标识
    u_short frag_off;     // 分片偏移
    u_char  ttl;          // 生存时间
    u_char  protocol;     // 上层协议
    u_short check;        // 校验和
    u_char  saddr[4];     // 源IP地址
    u_char  daddr[4];     // 目的IP地址
} ip_header;

// TCP段头部结构定义
typedef struct tcp_header {
    u_short src_port;     // 源端口
    u_short dest_port;    // 目的端口
    u_int   seq;          // 序列号
    u_int   ack;          // 确认号
    u_char  data_off;     // 数据偏移
    u_char  flags;        // 标志位
    u_short window;       // 窗口大小
    u_short check;        // 校验和
    u_short urgent_ptr;   // 紧急指针
} tcp_header;

// UDP段头部结构定义
typedef struct udp_header {
    u_short src_port;     // 源端口
    u_short dest_port;    // 目的端口
    u_short len;          // 长度
    u_short check;        // 校验和
} udp_header;

// 协议类型常量定义
#define ETH_P_IP   0x0800  // IP协议
#define ETH_P_ARP  0x0806  // ARP协议
#define IPPROTO_TCP 6      // TCP协议
#define IPPROTO_UDP 17     // UDP协议

// TCP标志位定义
#define TH_SYN 0x02        // SYN标志
#define TH_ACK 0x10        // ACK标志

// 存储数据包基本信息
struct PacketInfo {
    bool isTruncated;        //判断是否被截断
    int index;               // 序号
    QString timestamputc;    //utc时间戳
    QString timestamp;       // 时间戳
    QString srcMac;          // 源MAC
    QString dstMac;          // 目的MAC
    QString srcIp;           // 源IP
    QString dstIp;           // 目的IP
    QString protocol;        // 协议
    int length;              // 长度
    QString info;            // 摘要信息
    QString detail;          // 详细信息（分层解析）
};

class PacketParser : public QObject {
    Q_OBJECT
public:
    ~PacketParser();
    explicit PacketParser(QObject *parent = nullptr);
    bool openFile(const QString &filePath);  // 打开pcap文件
    void closeFile();                        // 关闭文件
    void parseAllPackets();                  // 解析所有数据包

signals:
    void packetParsed(const PacketInfo &info);  // 解析到一个数据包时触发
    void parseFinished();                       // 所有数据包解析完成

private:
    pcap_t *m_pcapHandle = nullptr;  // pcap句柄
    int m_packetIndex = 0;           // 数据包序号
};

#endif // PACKETPARSER_H
