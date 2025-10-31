#include "packetwidget.h"
#include "ui_packetwidget.h"
#include <QTableWidgetItem>
PacketWidget::PacketWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketWidget) {
    ui->setupUi(this);

    // 初始化表格
    ui->tableWidget->setColumnCount(6);
    ui->tableWidget->setHorizontalHeaderLabels(
    {"序号", "时间戳", "源地址", "目的地址", "协议", "信息"});
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    connect(ui->tableWidget, &QTableWidget::itemClicked, this, [=](QTableWidgetItem *item) {
        if (item) {
            onTableItemClicked(item->row(), item->column());
        }
    });

    // 初始化树状结构
    ui->detailTree->setHeaderLabel("数据包详细信息");
    ui->detailTree->setColumnCount(2);
    ui->detailTree->setHeaderLabels({"字段", "值"});
}

PacketWidget::~PacketWidget() {
    delete ui;
}

void PacketWidget::cleardetail() {
    ui->tableWidget->setRowCount(0);
    m_packetList.clear();
    ui->detailTree->clear(); // 清空树状结构
}

void PacketWidget::clear() {
    ui->tableWidget->setRowCount(0);
}

void PacketWidget::appendPacket(const PacketInfo &data) {
    // 表格添加逻辑不变
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(data.index)));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(data.timestamp));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(data.srcIp.isEmpty() ? data.srcMac : data.srcIp));
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem(data.dstIp.isEmpty() ? data.dstMac : data.dstIp));
    ui->tableWidget->setItem(row, 4, new QTableWidgetItem(data.protocol));
    ui->tableWidget->setItem(row, 5, new QTableWidgetItem(data.info));
    m_packetList.append(data);
}

// 构建树状结构
void PacketWidget::buildDetailTree(const PacketInfo &info) {
    ui->detailTree->clear();

    // 基本信息节点
    QTreeWidgetItem *baseItem = new QTreeWidgetItem({"基本信息"});
    baseItem->addChild(new QTreeWidgetItem({"序号", QString::number(info.index)}));
   baseItem->addChild(new QTreeWidgetItem({"Arrival Time(UTC)", info.timestamputc}));
    baseItem->addChild(new QTreeWidgetItem({"Arrival Time(CTS)", info.timestamp}));
    baseItem->addChild(new QTreeWidgetItem({"总长度", QString::number(info.length)}));
    ui->detailTree->addTopLevelItem(baseItem);



    // 以太网层节点
    QTreeWidgetItem *ethItem = new QTreeWidgetItem({"以太网层"});
    ethItem->addChild(new QTreeWidgetItem({"源MAC", info.srcMac}));
    ethItem->addChild(new QTreeWidgetItem({"目的MAC", info.dstMac}));
    ui->detailTree->addTopLevelItem(ethItem);

    // IP层节点（如果有IP信息）
    if (!info.srcIp.isEmpty()) {
        QTreeWidgetItem *ipItem = new QTreeWidgetItem({"IP层"});
        ipItem->addChild(new QTreeWidgetItem({"源IP", info.srcIp}));
        ipItem->addChild(new QTreeWidgetItem({"目的IP", info.dstIp}));
        ipItem->addChild(new QTreeWidgetItem({"协议", info.protocol}));
        ui->detailTree->addTopLevelItem(ipItem);
    }

    // 展开所有节点
    ui->detailTree->expandAll();
}

void PacketWidget::onTableItemClicked(int row, int column) {
    Q_UNUSED(column);
    if (row >= 0 && row < m_packetList.size()) {
        const PacketInfo &info = m_packetList[row];
        buildDetailTree(info); // 显示树状结构
    }
}
