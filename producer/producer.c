#include <librdkafka/rdkafka.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h> 
#include <netinet/udp.h>  
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <resolv.h> 
#include "dns.pb-c.h"
#include <stdbool.h>

#define BUFFER_SIZE 1024
#define KAFKA_BROKER "kafka:9092"
#define KAFKA_TOPIC "dns_packets"

// Function to query A and AAAA records
int get_a_and_aaaa_records(App__DNS *dns_message, const char *hostname) {
    struct addrinfo hints, *res, *p;
    char ip_str[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        perror("getaddrinfo error");
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        App__DnsRr *rr = malloc(sizeof(App__DnsRr));
        app__dns_rr__init(rr);

        rr->name.data = (uint8_t *)strdup(hostname);
        rr->name.len = strlen(hostname);
        rr->class_ = APP__DNS_CLASS__DNS_CLASS_IN;
        rr->ttl = 3600;

        if (p->ai_family == AF_INET) {
            rr->type = APP__DNS_RR_TYPE__DNS_RR_A;
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, sizeof ip_str);
            rr->rr_data_case = APP__DNS_RR__RR_DATA_A_DATA;
            rr->a_data = malloc(sizeof(App__DnsRrTypeAData));
            app__dns_rr_type_adata__init(rr->a_data);
            rr->a_data->address.data = (uint8_t *)strdup(ip_str);
            rr->a_data->address.len = strlen(ip_str);
        } else if (p->ai_family == AF_INET6) {
            rr->type = APP__DNS_RR_TYPE__DNS_RR_AAAA;
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, sizeof ip_str);
            rr->rr_data_case = APP__DNS_RR__RR_DATA_AAAA_DATA;
            rr->aaaa_data = malloc(sizeof(App__DnsRrTypeAAAAData));
            app__dns_rr_type_aaaadata__init(rr->aaaa_data);
            rr->aaaa_data->address.data = (uint8_t *)strdup(ip_str);
            rr->aaaa_data->address.len = strlen(ip_str);
        }

        dns_message->rrs = realloc(dns_message->rrs, sizeof(App__DnsRr *) * (dns_message->n_rrs + 1));
        dns_message->rrs[dns_message->n_rrs++] = rr;
    }

    freeaddrinfo(res);
    return 0;
}

// Function to query MX, NS, and PTR records
int query_mx_ns(App__DNS *dns_message, const char *hostname, int query_type) {
    unsigned char buf[BUFFER_SIZE];
    int len = res_query(hostname, C_IN, query_type, buf, sizeof(buf));
    
    if (len < 0) {
        fprintf(stderr, "res_query failed for %s: %s\n",
                query_type == T_MX ? "MX" : "NS", hstrerror(h_errno));
        return 1;
    }

    ns_msg msg;
    ns_rr rr;
    if (ns_initparse(buf, len, &msg) < 0) {
        perror("ns_initparse failed");
        return 1;
    }

    int count = ns_msg_count(msg, ns_s_an);
    for (int i = 0; i < count; i++) {
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            continue;
        }

        App__DnsRr *resource_record = malloc(sizeof(App__DnsRr));
        app__dns_rr__init(resource_record);
        resource_record->name.data = (uint8_t *)strdup(hostname);
        resource_record->name.len = strlen(hostname);
        resource_record->class_ = APP__DNS_CLASS__DNS_CLASS_IN;
        resource_record->ttl = ns_rr_ttl(rr);

        switch (query_type) {
            case ns_t_mx:
                resource_record->type = APP__DNS_RR_TYPE__DNS_RR_MX;
                resource_record->rr_data_case = APP__DNS_RR__RR_DATA_MX_DATA;
                resource_record->mx_data = malloc(sizeof(App__DnsRrTypeMxData));
                app__dns_rr_type_mx_data__init(resource_record->mx_data);
                resource_record->mx_data->preference = ns_get16(ns_rr_rdata(rr));
                resource_record->mx_data->mail_exchange.data = (uint8_t *)strdup((char *)ns_rr_rdata(rr) + 2);
                resource_record->mx_data->mail_exchange.len = strlen((char *)ns_rr_rdata(rr) + 2);
                break;
            case ns_t_ns:
                resource_record->type = APP__DNS_RR_TYPE__DNS_RR_NS;
                resource_record->rr_data_case = APP__DNS_RR__RR_DATA_NS_DATA;
                resource_record->ns_data = malloc(sizeof(App__DnsRrTypeNsData));
                app__dns_rr_type_ns_data__init(resource_record->ns_data);
                resource_record->ns_data->name_server.data = (uint8_t *)strdup((char *)ns_rr_rdata(rr));
                resource_record->ns_data->name_server.len = strlen((char *)ns_rr_rdata(rr));
                break;
            default:
                free(resource_record);
                continue;
        }

        dns_message->rrs = realloc(dns_message->rrs, sizeof(App__DnsRr *) * (dns_message->n_rrs + 1));
        dns_message->rrs[dns_message->n_rrs++] = resource_record;
    }
    return 0;
}

int query_ptr(App__DNS *dns_message, const char *hostname) {
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        perror("getaddrinfo error");
        return 1;
    }

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        App__DnsRr *rr = malloc(sizeof(App__DnsRr));
        app__dns_rr__init(rr);

        rr->name.data = (uint8_t *)strdup(hostname);
        rr->name.len = strlen(hostname);
        rr->class_ = APP__DNS_CLASS__DNS_CLASS_IN;
        rr->ttl = 3600;

        dns_message->rrs = realloc(dns_message->rrs, sizeof(App__DnsRr *) * (dns_message->n_rrs + 1));
        dns_message->rrs[dns_message->n_rrs++] = rr;
    }

    freeaddrinfo(res);
    return 0;
}

bool is_ip(const char *hostname) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;

    return getaddrinfo(hostname, NULL, &hints, &res) == 0;
}

// Main function to perform all queries and populate DNS message
int populate_all_dns_records(App__DNS *dns_message, const char *hostname) {
    app__dns__init(dns_message);
    dns_message->mssg_type = APP__DNS_MSSG_TYPE__DNS_QUERY;

    if (get_a_and_aaaa_records(dns_message, hostname) != 0)
        return 1;

    if (!is_ip(hostname)) {
        if (query_ptr(dns_message, hostname) != 0)
            return 1;
        return 0;
    }
    if (query_mx_ns(dns_message, hostname, ns_t_mx) != 0)
        return 1;

    if (query_mx_ns(dns_message, hostname, ns_t_ns) != 0)
        return 1;

    return 0;
}

void send_dns_message_to_kafka(App__DNS *dns_message) {
    rd_kafka_t *rk;
    rd_kafka_conf_t *conf;
    rd_kafka_topic_t *rkt;
    char errstr[512];

    conf = rd_kafka_conf_new();
    if (rd_kafka_conf_set(conf, "bootstrap.servers", KAFKA_BROKER, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        fprintf(stderr, "%% Failed to configure Kafka: %s\n", errstr);
        return;
    }

    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk) {
        fprintf(stderr, "%% Failed to create Kafka producer: %s\n", errstr);
        return;
    }

    rkt = rd_kafka_topic_new(rk, KAFKA_TOPIC, NULL);

    size_t message_len = app__dns__get_packed_size(dns_message);
    uint8_t *buffer = malloc(message_len);
    app__dns__pack(dns_message, buffer);

    if (rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, buffer, message_len, NULL, 0, NULL) == -1) {
        fprintf(stderr, "%% Failed to send message to Kafka: %s\n", rd_kafka_err2str(rd_kafka_last_error()));
    } else {
        fprintf(stderr, "%% Message sent to Kafka topic 'dns_packets'\n");
    }

    rd_kafka_flush(rk, 10000);
    free(buffer);
    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
}


int main(int ac, char **av) {
    App__DNS dns_message;
    if (ac < 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", av[0]);
        return 1;
    }

    if (populate_all_dns_records(&dns_message, av[1]) != 0)
        return 1;
    
    if (ac == 3) {
        int num = atoi(av[2]);
        for (int i = 0; i < num; i++) {
            send_dns_message_to_kafka(&dns_message);
        }
    }
    send_dns_message_to_kafka(&dns_message);

    return 0;
}

