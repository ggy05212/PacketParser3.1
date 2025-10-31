#ifndef PACKETWIDGET_H
#define PACKETWIDGET_H

#include <QWidget>
#include <QTreeWidgetItem>
#include "packetparser.h"

namespace Ui {
class PacketWidget;
}

class PacketWidget : public QWidget {
    Q_OBJECT

public:
    explicit PacketWidget(QWidget *parent = nullptr);
    ~PacketWidget();

    void clear();
    void cleardetail();

public slots:
    void appendPacket(const PacketInfo &data);
    void onTableItemClicked(int row, int column);

private:
    Ui::PacketWidget *ui;
    QList<PacketInfo> m_packetList;
    // 新增：将详细信息转换为树状结构
    void buildDetailTree(const PacketInfo &info);
};

#endif // PACKETWIDGET_H
