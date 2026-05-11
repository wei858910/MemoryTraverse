#include "mainwindow.h"
#include <QHeaderView>
#include <QMessageBox>
#include <tlhelp32.h>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTimer>

bool MemThread::readPtr(HANDLE hProc, ULONG64 addr, ULONG64 &out)
{
    SIZE_T read;
    return ReadProcessMemory(hProc, (LPCVOID)addr, &out, 8, &read) && read == 8;
}

MemThread::MemThread(DWORD pid, ULONG64 baseAddr, QList<ULONG64> staticOffsets,
                     QList<QPair<int, QPair<int, int>>> traverseList,
                     QString finalOffsetStr,
                     bool hideInvalid,
                     QObject *parent)
    : QThread(parent),
      m_pid(pid),
      m_baseAddr(baseAddr),
      m_staticOffsets(staticOffsets),
      m_traverseList(traverseList),
      m_finalOffsetStr(finalOffsetStr),
      m_hideInvalid(hideInvalid)
{}

void MemThread::run()
{
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, m_pid);
    if (!hProc) { emit finishedSignal(); return; }

    ULONG64 basePtr;
    if (!readPtr(hProc, m_baseAddr, basePtr)) { CloseHandle(hProc); emit finishedSignal(); return; }

    QList<ULONG64> baseOffsets = m_staticOffsets;
    for (ULONG64 off : m_staticOffsets) {
        basePtr += off;
        ULONG64 next;
        if (!readPtr(hProc, basePtr, next)) { CloseHandle(hProc); emit finishedSignal(); return; }
        basePtr = next;
    }

    int total = 1;
    for (auto &p : m_traverseList) total *= p.second.second;
    emit progressUpdated(total, 0);

    QList<int> indexes;
    for (auto &p : m_traverseList) indexes << 0;
    int done = 0;

    while (true) {
        ULONG64 current = basePtr;
        QList<ULONG64> dynamicOffsets;

        for (int i = 0; i < m_traverseList.size(); ++i) {
            int start = m_traverseList[i].first;
            int step  = m_traverseList[i].second.first;
            int idx   = indexes[i];
            ULONG64 add = start + idx * step;

            dynamicOffsets << add;
            current += add;

            if (i != m_traverseList.size() - 1) {
                ULONG64 next;
                if (!readPtr(hProc, current, next)) break;
                current = next;
            }
        }

        BYTE buf[32] = {0};
        SIZE_T read;
        bool valid = ReadProcessMemory(hProc, (LPCVOID)current, buf, 32, &read) && read > 0;

        if (m_hideInvalid && !valid) {
            emit progressUpdated(total, ++done);
            int pos = indexes.size() - 1;
            while (pos >= 0) {
                indexes[pos]++;
                if (indexes[pos] < m_traverseList[pos].second.second) break;
                indexes[pos] = 0; pos--;
            }
            if (pos < 0) break;
            continue;
        }

        QStringList fullOffsetList;
        fullOffsetList << QString("0x%1").arg(m_baseAddr, 0, 16);
        for (auto o : baseOffsets) fullOffsetList << QString("0x%1").arg(o, 0, 16);
        for (auto o : dynamicOffsets) fullOffsetList << QString("0x%1").arg(o, 0, 16);

        QString fullAddr = QString("{%1} ==> 0x%2")
            .arg(fullOffsetList.join(", "))
            .arg(current, 0, 16);

        auto makeInt = [&](quint64 v, int width) -> QString {
            if (!valid) return "-";
            return QString("0x%1 | %2").arg(v, width, 16, QChar('0')).toUpper().arg(v);
        };
        auto makeFloat = [&](float v) -> QString {
            if (!valid) return "-";
            return QString("0x%1 | %2").arg(*(quint32*)&v, 8, 16, QChar('0')).toUpper().arg(v, 0, 'f', 2);
        };
        auto makeDouble = [&](double v) -> QString {
            if (!valid) return "-";
            return QString("0x%1 | %2").arg(*(quint64*)&v, 16, 16, QChar('0')).toUpper().arg(v, 0, 'f', 4);
        };

        QString b1 = makeInt(buf[0], 2);
        QString b2 = (valid && read >= 2) ? makeInt(*(quint16*)buf, 4) : "-";
        QString b4 = (valid && read >= 4) ? makeInt(*(quint32*)buf, 8) : "-";
        QString b8 = (valid && read >= 8) ? makeInt(*(quint64*)buf,16) : "-";
        QString f32 = (valid && read >= 4) ? makeFloat(*(float*)buf) : "-";
        QString f64 = (valid && read >= 8) ? makeDouble(*(double*)buf) : "-";
        QString ansi = valid ? QString::fromLocal8Bit((char*)buf, qMin((int)read,20)).remove('\0') : "-";
        QString unicode = (valid && read>=2) ? QString::fromWCharArray((wchar_t*)buf, qMin((int)read/2,10)).remove('\0') : "-";

        emit resultReady({ fullAddr, b1, b2, b4, b8, f32, f64, ansi, unicode });
        emit progressUpdated(total, ++done);

        int pos = indexes.size() - 1;
        while (pos >= 0) {
            indexes[pos]++;
            if (indexes[pos] < m_traverseList[pos].second.second) break;
            indexes[pos] = 0; pos--;
        }
        if (pos < 0) break;
    }
    CloseHandle(hProc);
    emit finishedSignal();
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), m_thread(nullptr)
{
    initUI();
    QTimer::singleShot(100, this, &MainWindow::refreshProcesses);
}

MainWindow::~MainWindow()
{
    if (m_thread) { m_thread->quit(); m_thread->wait(); delete m_thread; }
}

void MainWindow::initUI()
{
    setWindowTitle("内存遍历工具");
    setMinimumSize(1500, 800);

    QWidget *c = new QWidget(this); setCentralWidget(c);
    QVBoxLayout *mainLayout = new QVBoxLayout(c);

    QHBoxLayout *lay1 = new QHBoxLayout;
    lay1->addWidget(new QLabel("进程"));
    cboProcess = new QComboBox;
    lay1->addWidget(cboProcess, 1); // 水平拉伸
    QPushButton *btnRefresh = new QPushButton("刷新进程");
    lay1->addWidget(btnRefresh);
    mainLayout->addLayout(lay1);

    QHBoxLayout *lay2 = new QHBoxLayout;
    lay2->addWidget(new QLabel("表达式"));
    edtExpr = new QLineEdit;
    edtExpr->setPlaceholderText("[[[[[基址]+静态偏移]+${起始,步长,数量}]+${起始,步长,数量}]+...](支持多级偏移) 例:[[[[[[[1416D17D8]+38]+60]+3600]+18]+0]+${0,4,100}]");
    // edtExpr->setText("[[[[[[[[1416D17D8]+38]+60]+3600]+18]+0]+${60,4,100}]+${4,4,10}]");
    lay2->addWidget(edtExpr);
    btnTraverse = new QPushButton("开始遍历");
    lay2->addWidget(btnTraverse);
    chkHideInvalid = new QCheckBox("不显示无效内存");
    chkHideInvalid->setChecked(true);
    lay2->addWidget(chkHideInvalid);
    mainLayout->addLayout(lay2);

    QHBoxLayout *layFilter = new QHBoxLayout;
    layFilter->addWidget(new QLabel("类型"));
    cboFilterType = new QComboBox;
    cboFilterType->addItems({"单字节","双字节","整数型","长整型","单浮点","双浮点","ANSI文本型","UNICODE文本型"});
    layFilter->addWidget(cboFilterType);
    layFilter->addWidget(new QLabel("条件"));
    cboFilterCond = new QComboBox;
    cboFilterCond->addItems({"等于","两者之间","值大于...","值小于..."});
    layFilter->addWidget(cboFilterCond);
    edtFilterVal1.setPlaceholderText("值");
    edtFilterVal2.setPlaceholderText("区间");
    layFilter->addWidget(&edtFilterVal1);
    layFilter->addWidget(&edtFilterVal2);
    QPushButton *btnFilter = new QPushButton("筛选");
    QPushButton *btnReset = new QPushButton("重置");
    layFilter->addWidget(btnFilter);
    layFilter->addWidget(btnReset);
    mainLayout->addLayout(layFilter);

    progressBar = new QProgressBar;
    mainLayout->addWidget(progressBar);

    table = new QTableWidget;
    table->setColumnCount(9);
    table->setHorizontalHeaderLabels({"完整地址","1字节","2字节","4字节","8字节","float","double","ANSI","UNICODE"});

    table->horizontalHeader()->setSectionResizeMode(COL_FULL_ADDRESS, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(COL_1BYTE,      QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(COL_2BYTE,      QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(COL_4BYTE,      QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(COL_8BYTE,      QHeaderView::ResizeToContents);
    table->setColumnWidth(COL_FLOAT,  300);
    table->setColumnWidth(COL_DOUBLE, 400);
    table->horizontalHeader()->setSectionResizeMode(COL_FLOAT,  QHeaderView::Interactive);
    table->horizontalHeader()->setSectionResizeMode(COL_DOUBLE, QHeaderView::Interactive);
    table->horizontalHeader()->setSectionResizeMode(COL_ANSI,    QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(COL_UNICODE, QHeaderView::ResizeToContents);

    colorDelegate = new ColorDelegate(this);
    for(int i=1;i<=6;i++) table->setItemDelegateForColumn(i, colorDelegate);
    mainLayout->addWidget(table);

    connect(btnRefresh, &QPushButton::clicked, this, &MainWindow::refreshProcesses);
    connect(btnTraverse, &QPushButton::clicked, this, &MainWindow::startTraverse);
    connect(btnFilter, &QPushButton::clicked, this, &MainWindow::doFilter);
    connect(btnReset, &QPushButton::clicked, this, &MainWindow::resetFilter);

    statusBar = new QStatusBar(this);
    this->setStatusBar(statusBar);
}

bool MainWindow::parseExpression(const QString &expr,
                                 ULONG64 &baseAddr,
                                 QList<ULONG64> &staticOffsets,
                                 QList<QPair<int, QPair<int, int>>> &traverseList,
                                 QString &outFinalOffsetStr)
{
    QString s = expr;
    s.remove(" ").remove("[").remove("]");
    QStringList parts = s.split("+${");
    bool ok;

    QStringList addrParts = parts[0].split("+");
    baseAddr = addrParts[0].toULongLong(&ok, 16);
    if (!ok) return false;

    staticOffsets.clear();
    for(int i=1;i<addrParts.size();i++){
        ULONG64 o = addrParts[i].toULongLong(&ok,16);
        if(!ok) return false;
        staticOffsets << o;
    }

    traverseList.clear();
    for(int i=1;i<parts.size();i++){
        QString p = parts[i];
        int e = p.indexOf("}");
        if(e<0) return false;
        QStringList t = p.left(e).split(",");
        if(t.size() < 3) return false;

        int start = t[0].toInt(&ok, 16);
        int step  = t[1].toInt(&ok, 16);
        int count = t[2].toInt(&ok, 10);
        if(!ok || count < 1) return false;

        traverseList << qMakePair(start, qMakePair(step, count));
    }
    return true;
}

void MainWindow::refreshProcesses()
{
    cboProcess->clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if(Process32First(hSnap,&pe)){
        do{
            cboProcess->addItem(QString::fromWCharArray(pe.szExeFile));
        }while(Process32Next(hSnap,&pe));
    }
    CloseHandle(hSnap);
}

DWORD MainWindow::getPidByName(const QString &name)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if(Process32First(hSnap,&pe)){
        do{
            if(QString::fromWCharArray(pe.szExeFile).compare(name,Qt::CaseInsensitive)==0){
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        }while(Process32Next(hSnap,&pe));
    }
    CloseHandle(hSnap);
    return 0;
}

void MainWindow::startTraverse()
{
    if(cboProcess->currentText().isEmpty()){QMessageBox::warning(this,"","请选择进程");return;}
    if(m_thread && m_thread->isRunning()){QMessageBox::warning(this,"","正在运行");return;}

    DWORD pid = getPidByName(cboProcess->currentText());
    if(!pid){QMessageBox::warning(this,"","无法打开进程");return;}

    ULONG64 base;
    QList<ULONG64> staticOffs;
    QList<QPair<int, QPair<int, int>>> travList;
    QString finalStr;

    if(!parseExpression(edtExpr->text(), base, staticOffs, travList, finalStr)){
        QMessageBox::warning(this,"","表达式解析失败");return;
    }

    table->setRowCount(0);
    m_allResults.clear();
    btnTraverse->setEnabled(false);

    m_thread = new MemThread(pid, base, staticOffs, travList, finalStr, chkHideInvalid->isChecked(), this);
    connect(m_thread,&MemThread::resultReady,this,&MainWindow::onResultReady);
    connect(m_thread,&MemThread::progressUpdated,this,&MainWindow::onProgressUpdated);
    connect(m_thread,&MemThread::finishedSignal,this,&MainWindow::onThreadFinished);
    m_thread->start();
}

void MainWindow::onResultReady(const QStringList &d)
{
    m_allResults.append(d);
    int r = table->rowCount();
    table->insertRow(r);
    for(int i=0;i<d.size();i++) table->setItem(r,i,new QTableWidgetItem(d[i]));
}

void MainWindow::onProgressUpdated(int max, int cur)
{
    progressBar->setMaximum(max);
    progressBar->setValue(cur);
}

void MainWindow::onThreadFinished()
{
    btnTraverse->setEnabled(true);
    m_thread->deleteLater();
    m_thread = nullptr;

    // 播放提示音
    QString soundPath = qApp->applicationDirPath() + "/sound/notify.wav";
    QSound::play(soundPath);

    statusBar->showMessage(QString("遍历完成，共 %1 条数据").arg(m_allResults.size()));
}

bool MainWindow::matchRow(const QStringList &row)
{
    QString t = cboFilterType->currentText();
    QString c = cboFilterCond->currentText();
    QString v1 = edtFilterVal1.text().trimmed();
    QString v2 = edtFilterVal2.text().trimmed();
    if(v1.isEmpty() && c!="两者之间") return true;

    int col = -1;
    if(t=="单字节") col=1; else if(t=="双字节") col=2; else if(t=="整数型") col=3;
    else if(t=="长整型") col=4; else if(t=="单浮点") col=5; else if(t=="双浮点") col=6;
    else if(t=="ANSI文本型") col=7; else if(t=="UNICODE文本型") col=8;
    if(col<0 || col>=row.size()) return false;

    QString cell = row[col];
    if(t.contains("文本")){
        if(c=="等于") return cell==v1;
        if(c=="值大于...") return cell>v1;
        if(c=="值小于...") return cell<v1;
        if(c=="两者之间") return cell>=v1 && cell<=v2;
    }else{
        QString dec = cell.split(" | ").last().trimmed();
        bool ok; double val = dec.toDouble(&ok); if(!ok) return false;
        double a = v1.toDouble();
        if(c=="等于") return qAbs(val-a)<0.0001;
        if(c=="值大于...") return val>a;
        if(c=="值小于...") return val<a;
        if(c=="两者之间") return val>=a && val<=v2.toDouble();
    }
    return false;
}

void MainWindow::doFilter()
{
    if(m_allResults.isEmpty()){QMessageBox::warning(this,"","请先遍历");return;}
    table->setRowCount(0);
    for(auto& row : m_allResults){
        if(matchRow(row)){
            int r = table->rowCount(); table->insertRow(r);
            for(int i=0;i<row.size();i++) table->setItem(r,i,new QTableWidgetItem(row[i]));
        }
    }
}

void MainWindow::resetFilter()
{
    table->setRowCount(0);
    for(auto& row : m_allResults){
        int r = table->rowCount(); table->insertRow(r);
        for(int i=0;i<row.size();i++) table->setItem(r,i,new QTableWidgetItem(row[i]));
    }
    edtFilterVal1.clear(); edtFilterVal2.clear();
}
