from confluent_kafka import Consumer, KafkaException, KafkaError
from dns_pb2 import DNS, DnsMssgType, DnsRrType
import os

def consume_and_test():
    consumer = Consumer({
        'bootstrap.servers': os.environ.get('KAFKA_BROKER'),
        'group.id': 'dns_consumer_group',
        'auto.offset.reset': 'earliest'
    })
    consumer.subscribe(['dns_packets'])

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            else:
                print("Kafka error:", msg.error())
                break
        try:
            dns_message = DNS()
            dns_message.ParseFromString(msg.value())
            print("Received DNS message:", dns_message)

            assert dns_message is not None, "Failed to parse DNS message from Protobuf"

            assert dns_message.HasField("mssg_type"), "Missing mssg_type field"
            assert dns_message.HasField("connection"), "Missing connection field"
            assert len(dns_message.questions) > 0 or len(dns_message.rrs) > 0, "No questions or resource records found"

            assert dns_message.mssg_type in [DnsMssgType.DNS_QUERY, DnsMssgType.DNS_RESPONSE], "Invalid mssg_type"

            for question in dns_message.questions:
                assert question.type in [DnsRrType.DNS_RR_A, DnsRrType.DNS_RR_AAAA, DnsRrType.DNS_RR_MX, DnsRrType.DNS_RR_NS, DnsRrType.DNS_RR_PTR], \
                    f"Invalid DNS query type: {question.type}"
                assert len(question.name) > 0, "DNS query name is empty"

            for rr in dns_message.rrs:
                assert rr.type in [DnsRrType.DNS_RR_A, DnsRrType.DNS_RR_AAAA, DnsRrType.DNS_RR_MX, DnsRrType.DNS_RR_NS, DnsRrType.DNS_RR_PTR], \
                    f"Invalid DNS resource record type: {rr.type}"
                assert len(rr.name) > 0, "DNS resource record name is empty"
                if rr.type == DnsRrType.DNS_RR_A or rr.type == DnsRrType.DNS_RR_AAAA:
                    assert rr.HasField("a_data") or rr.HasField("aaaa_data"), "A/AAAA data missing"
                elif rr.type == DnsRrType.DNS_RR_MX:
                    assert rr.HasField("mx_data"), "MX data missing"
                elif rr.type == DnsRrType.DNS_RR_NS:
                    assert rr.HasField("ns_data"), "NS data missing"
                elif rr.type == DnsRrType.DNS_RR_PTR:
                    assert rr.HasField("ptr_data"), "PTR data missing"

        except AssertionError as e:
            print("Test failed:", e)
        except Exception as e:
            print("Exception while parsing or testing message:", e)
            print("Raw message:", msg.value())
        finally:
            continue

    consumer.close()

if __name__ == "__main__":
    consume_and_test()
