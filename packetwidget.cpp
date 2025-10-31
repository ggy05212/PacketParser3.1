#include "packetwidget.h"
#include "ui_packetwidget.h"
#include <QTableWidgetItem>

PacketWidget::PacketWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketWidget) {
    ui->setupUi(this);

    // 初始化表格（与之前的表格结构一致）
    ui->tableWidget->setColumnCount(6);
    ui->tableWidget->setHorizontalHeaderLabels(
    {"序号", "时间戳", "源地址", "目的地址", "协议", "信息"});
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    connect(ui->tableWidget, &QTableWidget::itemClicked, this, [=](QTableWidgetItem *item) {
        if (item) {
            onTableItemClicked(item->row(), item->column());
        }
    });
    ui->detailText->setReadOnly(true);
}

PacketWidget::~PacketWidget() {
    delete ui;
}
//清理detail表格
void PacketWidget::cleardetail() {
    ui->tableWidget->setRowCount(0);
    m_packetList.clear(); // 清空存储的数据包列表
    ui->detailText->clear(); // 清空详细信息
}

void PacketWidget::clear() {
    ui->tableWidget->setRowCount(0); // 清空表格
}

void PacketWidget::appendPacket(const PacketInfo &data) {
    // 添加数据包到表格
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(data.index)));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(data.timestamp));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(data.srcIp.isEmpty() ? data.srcMac : data.srcIp));
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem(data.dstIp.isEmpty() ? data.dstMac : data.dstIp));
    ui->tableWidget->setItem(row, 4, new QTableWidgetItem(data.protocol));
    ui->tableWidget->setItem(row, 5, new QTableWidgetItem(data.info));
    // 存储数据包到列表，用于后续点击查询
    m_packetList.append(data);
}

// 处理表格点击事件，显示对应数据包的详细信息
void PacketWidget::onTableItemClicked(int row, int column) {
    Q_UNUSED(column);
    if (row >= 0 && row < m_packetList.size()) {
        // 获取当前行对应的数据包信息
        const PacketInfo &info = m_packetList[row];
        // 在detailTextEdit中显示详细信息
        ui->detailText->setText(info.detail);
    }
}
