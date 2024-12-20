#include "../dns.hpp"

#include <QCoreApplication>
#include <QDebug>
#include <QNetworkProxy>
#include <QUdpSocket>

constexpr quint16 DNS_PORT = 53;
constexpr auto MAX_UDP_DNS_PACKET_SIZE = 512;
constexpr auto DNS_SERVER_IP = "8.8.8.8";
constexpr auto LOOKUP_DOMAIN = "www.google.com";

inline QByteArray vectorToQByteArray(const std::vector<std::byte> &data)
{
    return QByteArray(
        reinterpret_cast<const char *>(data.data()),
        static_cast<qsizetype>(data.size()));
}

inline std::vector<std::byte> QByteArrayToVector(const QByteArray &data)
{
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(data.data()),
        reinterpret_cast<const std::byte *>(data.data() + data.size()));
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QNetworkProxyFactory::setUseSystemConfiguration(false);

    dns::DnsHeaderVars headerVars;
    headerVars.xid = 0x1234;
    headerVars.recursionDesired = 1;
    headerVars.opcode = 0;
    headerVars.isResponse = 0;
    headerVars.responseCode = 0;
    headerVars.checkingDisabled = 0;
    headerVars.authenticatedData = 0;
    headerVars.reserved = 0;
    headerVars.recursionAvailable = 0;
    headerVars.truncation = 0;
    headerVars.authoritative = 0;

    dns::DnsQuestion question;
    question.name = LOOKUP_DOMAIN;
    question.type = dns::RecordType::A;
    question.cls = dns::RecordClass::INTERNET;

    dns::DnsMessage message;
    message.dnsHead = headerVars;
    message.questions.push_back(question);

    const auto packet = dns::Build(message);
    if (packet.empty())
    {
        qWarning() << "Failed to build DNS packet";
        return -1;
    }
    // std::vector<std::byte> to QByteArray
    QByteArray packetData(vectorToQByteArray(packet));
    qDebug() << "Sending DNS packet" << packetData.toHex();

    QUdpSocket udpSocket;
    auto slotsFunction{
        [&udpSocket]()
        {
            while (udpSocket.hasPendingDatagrams())
            {
                QByteArray data;
                data.resize(udpSocket.pendingDatagramSize());
                QHostAddress sender;
                quint16 senderPort;
                udpSocket.readDatagram(data.data(), data.size(), &sender, &senderPort);
                qDebug() << QStringLiteral("Received data from ").append(sender.toString()).append(QStringLiteral(":")).append(QString::number(senderPort));
                qDebug() << data.toHex();

                // QByteArray to std::vector<std::byte>
                std::vector<std::byte> responseData(QByteArrayToVector(data));

                // to const uint8_t * and size
                const auto *responsePtr = reinterpret_cast<const uint8_t *>(responseData.data());
                const auto responseSize = responseData.size();

                // parse DNS response
                auto response = dns::Parse(responsePtr, responseSize);
                if (!response)
                {
                    qWarning() << "Failed to parse DNS response";
                    return;
                }
                qDebug() << "Parsed DNS response";

                // print answers
                for (const auto &answer : response->answers)
                {
                    qDebug() << "Answer:" << QString::fromStdString(answer.name) << answer.ttl;
                    if (auto a = std::get_if<dns::AData>(&answer.value))
                    {
                        qDebug() << "A:" << QHostAddress{ *a };
                    }
                }
            } }
    };
    QObject::connect(&udpSocket, &QUdpSocket::readyRead, slotsFunction);
    udpSocket.connectToHost(DNS_SERVER_IP, DNS_PORT);
    if (!udpSocket.waitForConnected())
    {
        qWarning() << "Failed to connect to DNS server";
        return -1;
    }
    udpSocket.write(packetData);

    return a.exec();
}
