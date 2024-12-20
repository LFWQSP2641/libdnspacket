#include "../dns.hpp"

#include <QCoreApplication>
#include <QDebug>
#include <QNetworkProxy>
#include <QUdpSocket>

constexpr quint16 DNS_PORT = 53;
constexpr auto MAX_UDP_DNS_PACKET_SIZE = 512;
constexpr auto DNS_SERVER_IP = "8.8.8.8";
constexpr auto LOOKUP_DOMAIN = "aliyun.com";

constexpr dns::RecordType recordType = dns::RecordType::AAAA;
constexpr dns::RecordClass recordClass = dns::RecordClass::INTERNET;

template <typename T,
          typename = std::enable_if_t<std::is_same_v<typename T::value_type, std::byte>>>
inline QByteArray vectorToQByteArray(const T &data)
{
    return QByteArray(
        reinterpret_cast<const char *>(data.data()),
        static_cast<qsizetype>(data.size() * sizeof(std::byte)));
}

inline std::vector<std::byte> QByteArrayToVector(const QByteArray &data)
{
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(data.data()),
        reinterpret_cast<const std::byte *>(data.data() + data.size()));
}

// ipv6 ( std::array<std::byte, 16> ) to QHostAddress
inline QHostAddress vectorToQHostAddress(const std::array<std::byte, 16> &data)
{
    // to Q_IPV6ADDR
    Q_IPV6ADDR ipv6;
    for (int i = 0; i < 16; ++i)
    {
        ipv6[i] = static_cast<quint8>(data[i]);
    }
    return QHostAddress(ipv6);
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
    question.type = recordType;
    question.cls = recordClass;

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

                std::vector<dns::DnsAnswer> answers;

                answers = response->answers;
                answers.insert(answers.end(), response->authorityAnswers.begin(), response->authorityAnswers.end());
                answers.insert(answers.end(), response->additionalAnswers.begin(), response->additionalAnswers.end());

                // print answers
                for (const auto &answer : answers)
                {
                    qDebug() << "Answer:" << QString::fromStdString(answer.name) << answer.ttl;
                    if (auto a = std::get_if<dns::AData>(&answer.value))
                    {
                        qDebug() << "A:" << QHostAddress{ *a };
                    }
                    else if (auto aaaa = std::get_if<dns::AAAAData>(&answer.value))
                    {
                        qDebug() << "AAAA:" << vectorToQHostAddress(*aaaa);
                    }
                    else if (auto mx = std::get_if<dns::MXData>(&answer.value))
                    {
                        qDebug() << "MX:" << mx->exchange;
                    }
                    else if (auto ptr = std::get_if<dns::PTRData>(&answer.value))
                    {
                        qDebug() << "PTR:" << QString::fromStdString(*ptr);
                    }
                    else if (auto txt = std::get_if<dns::TXTData>(&answer.value))
                    {
                        qDebug() << "TXT:" << txt->txt;
                    }
                    else if (auto soa = std::get_if<dns::SOAData>(&answer.value))
                    {
                        qDebug() << "SOA:" << soa->primaryServer << soa->administrator << soa->serialNo << soa->refresh << soa->retry << soa->expire << soa->defaultTtl;
                    }
                    else
                    {
                        qDebug() << "Unknown record type";
                    }
                }
            }
        }
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
