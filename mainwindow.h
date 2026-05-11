#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QCheckBox>
#include <QThread>
#include <windows.h>
#include <QList>
#include <QPair>
#include <QVariant>
#include <QStyledItemDelegate>
#include <QPainter>
#include <QApplication>
#include <QStatusBar>
#include <QSound>

const int COL_FULL_ADDRESS     = 0;
const int COL_1BYTE            = 1;
const int COL_2BYTE            = 2;
const int COL_4BYTE            = 3;
const int COL_8BYTE            = 4;
const int COL_FLOAT            = 5;
const int COL_DOUBLE           = 6;
const int COL_ANSI             = 7;
const int COL_UNICODE          = 8;

class ColorDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit ColorDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->fillRect(option.rect, option.palette.base());
        int col = index.column();
        if (col < 1 || col > 6) { QStyledItemDelegate::paint(painter, option, index); return; }

        QString text = index.data(Qt::DisplayRole).toString();
        int splitPos = text.indexOf(" | ");
        if (splitPos <= 0) { QStyledItemDelegate::paint(painter, option, index); return; }

        QString hexPart = text.left(splitPos);
        QString restPart = text.mid(splitPos);
        painter->save();

        QRect rect = option.rect.adjusted(2, 0, -2, 0);
        painter->setPen(Qt::red);
        painter->drawText(rect, Qt::AlignLeft | Qt::AlignVCenter, hexPart);

        painter->setPen(Qt::black);
        int w = painter->fontMetrics().horizontalAdvance(hexPart);
        painter->drawText(rect.adjusted(w, 0, 0, 0), Qt::AlignLeft | Qt::AlignVCenter, restPart);

        painter->restore();
    }
};

class MemThread : public QThread
{
    Q_OBJECT
public:
    explicit MemThread(DWORD pid, ULONG64 baseAddr,
                       QList<ULONG64> staticOffsets,
                       QList<QPair<int, QPair<int, int>>> traverseList,
                       QString finalOffsetStr,
                       bool hideInvalid,
                       QObject *parent = nullptr);

    void run() override;

signals:
    void resultReady(const QStringList &rowData);
    void progressUpdated(int max, int current);
    void finishedSignal();

private:
    bool readPtr(HANDLE hProc, ULONG64 addr, ULONG64 &out);

    DWORD m_pid;
    ULONG64 m_baseAddr;
    QList<ULONG64> m_staticOffsets;
    QList<QPair<int, QPair<int, int>>> m_traverseList;
    QString m_finalOffsetStr;
    bool m_hideInvalid;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void refreshProcesses();
    void startTraverse();
    void onResultReady(const QStringList &rowData);
    void onProgressUpdated(int max, int cur);
    void onThreadFinished();
    void doFilter();
    void resetFilter();

private:
    void initUI();
    bool parseExpression(const QString &expr,
                         ULONG64 &baseAddr,
                         QList<ULONG64> &staticOffsets,
                         QList<QPair<int, QPair<int, int>>> &traverseList,
                         QString &outFinalOffsetStr);

    DWORD getPidByName(const QString &name);
    bool matchRow(const QStringList &rowData);

    QComboBox *cboProcess;
    QLineEdit *edtExpr;
    QPushButton *btnTraverse;
    QCheckBox *chkHideInvalid;
    QProgressBar *progressBar;
    QTableWidget *table;
    MemThread *m_thread;
    ColorDelegate *colorDelegate;

    QComboBox *cboFilterType;
    QComboBox *cboFilterCond;
    QLineEdit edtFilterVal1;
    QLineEdit edtFilterVal2;
    QList<QStringList> m_allResults;
    QStatusBar *statusBar;
};

#endif // MAINWINDOW_H
