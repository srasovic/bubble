
all: bubble
bubble.o:      ops/bubble.c
	gcc -fPIC -g -c ops/bubble.c -lnet -lpcap -lpthread
arp_fuzzer.o: fuzzers/arp_fuzzer.c
	gcc -fPIC -g -c fuzzers/arp_fuzzer.c -lnet -lpcap
ip_fuzzer.o: fuzzers/ip_fuzzer.c
	gcc -fPIC -g -c fuzzers/ip_fuzzer.c -lnet -lpcap
ipv6_fuzzer.o: fuzzers/ipv6_fuzzer.c
	gcc -fPIC -g -c fuzzers/ipv6_fuzzer.c -lnet -lpcap
bgp_fuzzer.o: fuzzers/bgp_fuzzer.c
	gcc -fPIC -g -c fuzzers/bgp_fuzzer.c -lnet -lpcap
msdp_fuzzer.o: fuzzers/msdp_fuzzer.c
	gcc -fPIC -g -c fuzzers/msdp_fuzzer.c -lnet -lpcap
ike_fuzzer.o: fuzzers/ike_fuzzer.c
	gcc -fPIC -g -c fuzzers/ike_fuzzer.c -lnet -lpcap
dhcpv4_fuzzer.o: fuzzers/dhcpv4_fuzzer.c
	gcc -fPIC -g -c fuzzers/dhcpv4_fuzzer.c -lnet -lpcap
dns_fuzzer.o: fuzzers/dns_fuzzer.c
	gcc -fPIC -g -c fuzzers/dns_fuzzer.c -lnet -lpcap
auxiliary.o: ops/auxiliary.c
	gcc -fPIC -g -c ops/auxiliary.c -lnet -lpcap -ldumbnet
l2_l4_packet_parser.o:    ops/l2_l4_packet_parser.c
	gcc -fPIC -g -c ops/l2_l4_packet_parser.c
build_session_ike.o:    session/build_session_ike.c
	gcc -fPIC -g -c session/build_session_ike.c -lnet -lpcap
build_session_bgp.o:    session/build_session_bgp.c
	gcc -fPIC -g -c session/build_session_bgp.c -lnet -lpcap
build_session_dhcpv4.o:    session/build_session_dhcpv4.c
	gcc -fPIC -g -c session/build_session_dhcpv4.c -lnet -lpcap
build_session_dns.o:    session/build_session_dns.c
	gcc -fPIC -g -c session/build_session_dns.c -lnet -lpcap
build_session_msdp.o:    session/build_session_msdp.c
	gcc -fPIC -g -c session/build_session_msdp.c -lnet -lpcap
build_pack_arp.o:    single/build_pack_arp.c
	gcc -fPIC -g -c single/build_pack_arp.c -lnet -lpcap
build_pack_ipv4.o:    single/build_pack_ipv4.c
	gcc -fPIC -g -c single/build_pack_ipv4.c -lnet -lpcap
build_pack_ipv6.o:    single/build_pack_ipv6.c
	gcc -fPIC -g -c single/build_pack_ipv6.c -lnet -lpcap
build_pack.o:    single/build_pack.c
	gcc -fPIC -g -c single/build_pack.c -lnet -lpcap
build_session.o:    session/build_session.c
	gcc -fPIC -g -c session/build_session.c -lnet -lpcap
ping_to_uut.o: ops/ping_to_uut.c
	gcc -fPIC -g -c ops/ping_to_uut.c
ping6_to_uut.o: ops/ping6_to_uut.c
	gcc -fPIC -g -c ops/ping6_to_uut.c
db_connectivity.o: ops/db_connectivity.c
	gcc -fPIC -g -c ops/db_connectivity.c -lpq
send_from_db.o: ops/send_from_db.c
	gcc -fPIC -g -c ops/send_from_db.c -lpq
tcp_socket_operation.o: ops/tcp_socket_operation.c
	gcc -fPIC -g -c ops/tcp_socket_operation.c -lpq
udp_socket_operation.o: ops/udp_socket_operation.c
	gcc -fPIC -g -c ops/udp_socket_operation.c -lpq
io_socket_bgp.o:      ops/io_socket_bgp.c
	gcc -fPIC -g -c ops/io_socket_bgp.c
read_sample_from_db.o: ops/read_sample_from_db.c
	gcc -fPIC -g -c ops/read_sample_from_db.c -lpq
instrumentation.o: ops/instrumentation.c
	gcc -fPIC -g -c ops/instrumentation.c -lpthread -lssh


bubble: bubble.o ping_to_uut.o ping6_to_uut.o build_pack_arp.o build_session_ike.o build_session_bgp.o build_session_dhcpv4.o build_session_dns.o build_session_msdp.o build_pack_ipv4.o build_pack_ipv6.o build_pack.o build_session.o arp_fuzzer.o ip_fuzzer.o ipv6_fuzzer.o bgp_fuzzer.o msdp_fuzzer.o ike_fuzzer.o dhcpv4_fuzzer.o dns_fuzzer.o auxiliary.o l2_l4_packet_parser.o send_from_db.o tcp_socket_operation.o udp_socket_operation.o io_socket_bgp.o read_sample_from_db.o db_connectivity.o instrumentation.o
bubble: bubble.o ping_to_uut.o ping6_to_uut.o build_pack_arp.o build_session_ike.o build_session_bgp.o build_session_dhcpv4.o build_session_dns.o build_session_msdp.o build_pack_ipv4.o build_pack_ipv6.o build_pack.o build_session.o arp_fuzzer.o ip_fuzzer.o ipv6_fuzzer.o bgp_fuzzer.o msdp_fuzzer.o ike_fuzzer.o dhcpv4_fuzzer.o dns_fuzzer.o auxiliary.o l2_l4_packet_parser.o send_from_db.o tcp_socket_operation.o udp_socket_operation.o io_socket_bgp.o read_sample_from_db.o db_connectivity.o instrumentation.o
	gcc -g -o bubble *.o -lnet -lpcap -ldumbnet -lpq -lpthread -lssh
	sudo mv bubble /usr/bin/

clean:
	rm -f *.o;rm -f *.gch
