#ifndef PACKETWIDGET_H
#define PACKETWIDGET_H

#include <QWidget>
#include "packetparser.h" // 包含数据包结构定义

namespace Ui {
class PacketWidget;
}

class PacketWidget : public QWidget {
    Q_OBJECT

public:
    explicit PacketWidget(QWidget *parent = nullptr);
    ~PacketWidget();

    // 清空显示内容
    void clear();
    void cleardetail();

public slots:
    // 接收并显示单个数据包
    void appendPacket(const PacketInfo &data);
    void onTableItemClicked(int row, int column);


private:
    Ui::PacketWidget *ui;
    QList<PacketInfo> m_packetList;
};

#endif // PACKETWIDGET_H
