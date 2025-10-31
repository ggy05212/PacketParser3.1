#include "packetparser.h"
#include <QDateTime>
#include <QStringList>
#include <QDebug>

PacketParser::PacketParser(QObject *parent) : QObject(parent) {
    // 初始化Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

PacketParser::~PacketParser() {
    // 清理Winsock
    WSACleanup();
    closeFile();
}

bool PacketParser::openFile(const QString &filePath) {
    closeFile();  // 先关闭已打开的文件
    char errbuf[PCAP_ERRBUF_SIZE];
    m_pcapHandle = pcap_open_offline(filePath.toUtf8().constData(), errbuf);
    if (!m_pcapHandle) {
        qWarning("无法打开pcap文件: %s", errbuf);
        return false;
    }
    m_packetIndex = 0;
    return true;
}

void PacketParser::closeFile() {
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
    }
}

void PacketParser::parseAllPackets() {
    if (!m_pcapHandle) return;

    struct pcap_pkthdr *header;  // 数据包头部（包含时间戳、长度等）
    const u_char *packet;        // 数据包内容
    int res;

    // 循环读取所有数据包
    while ((res = pcap_next_ex(m_pcapHandle, &header, &packet)) >= 0) {
        if (res == 0) continue;  // 读取超时（离线文件不会发生）

        m_packetIndex++;
        PacketInfo info;
        info.index = m_packetIndex;

        info.isTruncated = (header->caplen < header->len);  // 捕获长度 < 实际长度表示被截断


        // 1. 解析时间戳（秒.微秒）
        QDateTime time = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec);
        time = time.addMSecs(header->ts.tv_usec / 1000);  // 转换微秒到毫秒
        info.timestamp = time.toString("yyyy-MM-dd hh:mm:ss.zzz");

        // 解析时间戳（秒.微秒）并转换为UTC时间
        QDateTime timeutc = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec, Qt::UTC);
        timeutc = timeutc.addMSecs(header->ts.tv_usec / 1000);  // 转换微秒到毫秒
        info.timestamputc = timeutc.toString("yyyy-MM-dd hh:mm:ss.zzz");

        // 2. 解析以太网层（MAC地址）
        ether_header *eth = (ether_header *)packet;
        info.srcMac = QString("%1:%2:%3:%4:%5:%6")
                .arg((uchar)eth->h_source[0], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[1], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[2], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[3], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[4], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[5], 2, 16, QChar('0')).toUpper();

        info.dstMac = QString("%1:%2:%3:%4:%5:%6")
                .arg((uchar)eth->h_dest[0], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[1], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[2], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[3], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[4], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[5], 2, 16, QChar('0')).toUpper();

        info.length = header->len;
        info.detail = QString("以太网层: 源MAC=%1, 目的MAC=%2, 类型=0x%3\n")
                .arg(info.srcMac).arg(info.dstMac)
                .arg(ntohs(eth->h_proto), 4, 16, QChar('0')).toUpper();

        // 3. 解析网络层（IP协议）
        if (ntohs(eth->h_proto) == ETH_P_IP) {  // 确认是IP协议
            u_char *ipStart = (u_char *)(packet + sizeof(ether_header));
            ip_header *ip = (ip_header *)ipStart;

            // 检查是否为IPv4
            if ((ip->version_ihl & 0xF0) == 0x40) {  // IPv4 (版本号为4)
                // 转换IP地址格式
                char srcIpStr[INET_ADDRSTRLEN];
                char dstIpStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ip->saddr, srcIpStr, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, ip->daddr, dstIpStr, INET_ADDRSTRLEN);

                info.srcIp = QString(srcIpStr);
                info.dstIp = QString(dstIpStr);

                int ipHeaderLen = (ip->version_ihl & 0x0F) * 4;  // IP头部长度
                info.detail += QString("IP层: 源IP=%1, 目的IP=%2, 协议=%3, TTL=%4, 长度=%5\n")
                        .arg(info.srcIp).arg(info.dstIp)
                        .arg((int)ip->protocol).arg((int)ip->ttl)
                        .arg(ntohs(ip->total_len));

                // 4. 解析传输层（TCP/UDP）
                u_char *transportStart = ipStart + ipHeaderLen;

                if (ip->protocol == IPPROTO_TCP) {  // TCP协议
                    tcp_header *tcp = (tcp_header *)transportStart;
                    info.protocol = "TCP";

                    QString flags;
                    if (tcp->flags & TH_SYN) flags += "SYN ";
                    if (tcp->flags & TH_ACK) flags += "ACK ";

                    info.info = QString("源端口: %1, 目的端口: %2, 标志: %3")
                            .arg(ntohs(tcp->src_port))
                            .arg(ntohs(tcp->dest_port))
                            .arg(flags.trimmed());

                    info.detail += QString("TCP层: 源端口=%1, 目的端口=%2, 序列号=%3, 确认号=%4\n")
                            .arg(ntohs(tcp->src_port))
                            .arg(ntohs(tcp->dest_port))
                            .arg(ntohl(tcp->seq))
                            .arg(ntohl(tcp->ack));
                } else if (ip->protocol == IPPROTO_UDP) {  // UDP协议
                    udp_header *udp = (udp_header *)transportStart;
                    info.protocol = "UDP";
                    info.info = QString("源端口: %1, 目的端口: %2, 长度: %3")
                            .arg(ntohs(udp->src_port))
                            .arg(ntohs(udp->dest_port))
                            .arg(ntohs(udp->len));
                    info.detail += QString("UDP层: 源端口=%1, 目的端口=%2, 长度=%3\n")
                            .arg(ntohs(udp->src_port))
                            .arg(ntohs(udp->dest_port))
                            .arg(ntohs(udp->len));
                } else {
                    info.protocol = QString("IP（协议号：%1）").arg((int)ip->protocol);
                    info.info = QString("不支持的传输层协议: %1").arg((int)ip->protocol);
                }
            } else {
                info.protocol = "非IPv4";
                info.info = "不支持的IP版本";
            }
        } else {
            info.protocol = QString("以太网（类型：0x%1）").arg(ntohs(eth->h_proto), 4, 16, QChar('0')).toUpper();
            info.info = "非IP协议数据包";
        }

        // 在详细信息中添加截断提示
        if (info.isTruncated) {
            info.detail.prepend(QString("警告：数据包被截断（实际长度：%1，捕获长度：%2）\n")
                                .arg(header->len).arg(header->caplen));
        }

        emit packetParsed(info);  // 发送解析结果到UI
    }

    emit parseFinished();  // 解析完成
}
