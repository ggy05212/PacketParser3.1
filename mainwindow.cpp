#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      m_pcapHandler(new PacketParser(this)),
      m_packetWidget(new PacketWidget(this)) {
    ui->setupUi(this);
    setWindowTitle("PCAP 阅读器");

    // 将PacketWidget设置为主窗口的中心部件
    setCentralWidget(m_packetWidget);

    // 关联信号：解析器的数据包 → 显示Widget
    connect(m_pcapHandler, &PacketParser::packetParsed,
            m_packetWidget, &PacketWidget::appendPacket);
    // 关联菜单和解析完成信号
    connect(ui->actionOpen, &QAction::triggered, this, &MainWindow::onActionOpenFile);
//    connect(m_pcapHandler, &PacketParser::parseFinished, this, &MainWindow::onParseFinished);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onActionOpenFile() {
    // 选择文件
    QString filePath = QFileDialog::getOpenFileName(
        this, "选择PCAP文件", "", "PCAP Files (*.pcap *.pcapng)");
    if (filePath.isEmpty()) return;

    // 清空之前的显示
    m_packetWidget->clear();

    // 打开并解析文件
    if (m_pcapHandler->openFile(filePath)) {
        m_pcapHandler->parseAllPackets();
    } else {
        QMessageBox::critical(this, "错误", "无法打开PCAP文件！");
    }
}

//void MainWindow::onParseFinished() {
//    QMessageBox::information(this, "完成",
//        QString("解析完成，共 %1 个数据包").arg(m_packetWidget->findChild<QTableWidget*>()->rowCount()));
//}
