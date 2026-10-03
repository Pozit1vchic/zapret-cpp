// Flow table and TCP stream reassembly.
#include <string>
#include <vector>

#include "test_util.hpp"
#include "zc/flow.hpp"

using namespace zctest;

namespace {

zc::FlowKey make_key(std::uint16_t sport = 50000, std::uint16_t dport = 443,
                     std::uint8_t proto = zc::kProtoTcp, std::uint8_t last_octet = 2) {
    zc::FlowKey key;
    key.source = zc::IpAddress::parse("10.0.0." + std::to_string(last_octet));
    key.destination = zc::IpAddress::parse("93.184.216.34");
    key.source_port = sport;
    key.destination_port = dport;
    key.protocol = proto;
    return key;
}

void check_identity() {
    const zc::FlowKey a = make_key();
    zc::FlowKey b = a;
    ZC_CHECK(a == b);
    ZC_CHECK(zc::FlowKeyHash{}(a) == zc::FlowKeyHash{}(b));

    // Every component of the key must matter.
    b.source_port = 50001;
    ZC_CHECK(!(a == b));
    b = a; b.destination_port = 8443;
    ZC_CHECK(!(a == b));
    b = a; b.protocol = zc::kProtoUdp;
    ZC_CHECK(!(a == b));
    b = a; b.destination = zc::IpAddress::parse("93.184.216.35");
    ZC_CHECK(!(a == b));
    b = a; b.source = zc::IpAddress::parse("10.0.0.3");
    ZC_CHECK(!(a == b));
    // A different IPv6 source must not collide with the IPv4 one.
    b = a; b.source = zc::IpAddress::parse("2001:db8::1");
    ZC_CHECK(!(a == b));
    ZC_CHECK(!a.to_string().empty());

    // High bytes of an IPv6 address participate in the hash and equality.
    zc::FlowKey v6a;
    v6a.source = zc::IpAddress::parse("2001:db8::1");
    zc::FlowKey v6b = v6a;
    ZC_CHECK(v6a == v6b);
    v6b.source.bytes[0] = 0x20;
    v6b.source.bytes[1] = 0x02;
    ZC_CHECK(!(v6a == v6b));
}

void check_one_shot() {
    zc::FlowTable flows(16, 60000, 0);
    const auto key = make_key();
    bool created = false;
    auto first = flows.touch(key, 1000, created);
    ZC_CHECK(created);
    ZC_CHECK(first != nullptr);
    ZC_CHECK(!first->desynced);

    auto second = flows.touch(key, 1001, created);
    ZC_CHECK(!created);
    ZC_CHECK(second.get() == first.get());  // the same entry, not a copy
    ZC_CHECK_EQ(flows.size(), 1u);
    ZC_CHECK(flows.stats().reused >= 1);
}

void check_capacity_is_bounded() {
    zc::FlowTable flows(8, 60000, 0);
    for (std::uint16_t port = 1; port <= 200; ++port) {
        bool created = false;
        flows.touch(make_key(port), 1000 + port, created);
        ZC_CHECK_MSG(flows.size() <= 8, "size " + std::to_string(flows.size()) +
                                           " must stay within capacity");
    }
    ZC_CHECK(flows.stats().evicted > 0);
    ZC_CHECK(flows.stats().peak <= 8);
}

void check_expiry() {
    zc::FlowTable flows(64, 1000, 0);
    bool created = false;
    flows.touch(make_key(1), 1000, created);
    flows.touch(make_key(2), 1000, created);
    ZC_CHECK_EQ(flows.size(), 2u);
    // Not yet expired.
    flows.prune(1500);
    ZC_CHECK_EQ(flows.size(), 2u);
    // Past the TTL.
    flows.prune(3000);
    ZC_CHECK_EQ(flows.size(), 0u);
    ZC_CHECK(flows.stats().expired >= 2);
}

void check_eviction_keeps_recent_flows() {
    zc::FlowTable flows(4, 100000, 0);
    bool created = false;
    flows.touch(make_key(1), 1000, created);
    flows.touch(make_key(2), 2000, created);
    flows.touch(make_key(3), 3000, created);
    flows.touch(make_key(4), 4000, created);
    // Refreshing flow 4 makes it the most recent.
    flows.touch(make_key(4), 5000, created);
    // Adding a fifth flow must evict the least recently seen (flow 1), not flush all.
    flows.touch(make_key(5), 6000, created);
    flows.touch(make_key(2), 7000, created);
    ZC_CHECK_EQ(flows.size(), 4u);
    bool again = false;
    flows.touch(make_key(2), 7001, again);
    ZC_CHECK(!again);  // flow 2 survived
}

void check_forget() {
    zc::FlowTable flows(16, 60000, 0);
    bool created = false;
    flows.touch(make_key(), 1000, created);
    flows.forget(make_key());
    ZC_CHECK_EQ(flows.size(), 0u);
    flows.touch(make_key(), 1001, created);
    ZC_CHECK(created);
    // Forgetting something absent is harmless.
    flows.forget(make_key(9999));
    ZC_CHECK_EQ(flows.size(), 1u);
    flows.clear();
    ZC_CHECK_EQ(flows.size(), 0u);
}

void check_zero_capacity() {
    zc::FlowTable flows(0, 1000, 0);
    bool created = false;
    const auto entry = flows.touch(make_key(), 1, created);
    ZC_CHECK(entry != nullptr);
    ZC_CHECK(flows.size() <= 1);
}

void check_tcp_stream() {
    zc::TcpStreamBuffer stream;
    stream.configure(64);
    const std::vector<std::uint8_t> a = {1, 2, 3, 4};
    const std::vector<std::uint8_t> b = {5, 6, 7, 8};

    ZC_CHECK(stream.push(1000, a));
    ZC_CHECK_EQ(stream.size(), 4u);
    ZC_CHECK_EQ(stream.next_sequence_for_test(), 1004u);

    // Contiguous continuation.
    ZC_CHECK(stream.push(1004, b));
    ZC_CHECK_EQ(stream.size(), 8u);
    const std::vector<std::uint8_t> expected = {1, 2, 3, 4, 5, 6, 7, 8};
    ZC_CHECK(std::vector<std::uint8_t>(stream.data().begin(), stream.data().end()) == expected);

    // A pure retransmission must not duplicate bytes.
    ZC_CHECK(!stream.push(1000, a));
    ZC_CHECK_EQ(stream.size(), 8u);

    // A partial overlap must contribute only the new bytes: a retransmission that starts
    // two bytes behind the stream pointer.
    ZC_CHECK(stream.push(1006, std::vector<std::uint8_t>{3, 4, 9, 9}));
    ZC_CHECK_EQ(stream.size(), 10u);
    ZC_CHECK_EQ(stream.data()[8], 9);
    ZC_CHECK_EQ(stream.data()[9], 9);

    // A retransmission entirely inside what we already have is dropped.
    ZC_CHECK(!stream.push(1004, std::vector<std::uint8_t>(4, 0xbb)));
    ZC_CHECK_EQ(stream.size(), 10u);

    // A gap is refused rather than buffered out of order.
    ZC_CHECK(!stream.push(5000, std::vector<std::uint8_t>{1, 2}));
    ZC_CHECK_EQ(stream.size(), 10u);

    // The buffer must stop at its budget.
    stream.reset();
    stream.configure(8);
    ZC_CHECK(stream.push(1, std::vector<std::uint8_t>(10, 0xaa)));
    ZC_CHECK(stream.size() <= 8);
    ZC_CHECK(stream.truncated());

    // A zero budget disables reassembly entirely.
    stream.reset();
    stream.configure(0);
    ZC_CHECK(!stream.push(1, a));
    ZC_CHECK_EQ(stream.size(), 0u);
}

void check_stream_budget_is_shared() {
    // The table divides its byte budget across flows, so no single flow can consume
    // everything.
    zc::FlowTable flows(64, 60000, 64 * 1024);
    bool created = false;
    for (std::uint16_t port = 1; port <= 32; ++port) {
        auto entry = flows.touch(make_key(port), 1000, created);
        for (int i = 0; i < 64; ++i) {
            entry->tcp_stream.push(static_cast<std::uint32_t>(i * 64),
                                   std::vector<std::uint8_t>(64, 0x41));
        }
    }
    ZC_CHECK(flows.stream_bytes() <= 64 * 1024);
    ZC_CHECK(flows.stream_bytes() > 0);
}

void check_shared_ptr_stays_valid() {
    // A handle obtained from the table must remain usable even after the entry is
    // evicted, which is what lets a second thread finish using a flow safely.
    zc::FlowTable flows(2, 100000, 0);
    bool created = false;
    auto held = flows.touch(make_key(1), 1000, created);
    held->desynced = true;
    flows.touch(make_key(2), 1001, created);
    flows.touch(make_key(3), 1002, created);
    ZC_CHECK(held->desynced);  // still valid, not dangling
    ZC_CHECK_EQ(held.use_count(), 1);
}

void run() {
    check_identity();
    check_one_shot();
    check_capacity_is_bounded();
    check_expiry();
    check_eviction_keeps_recent_flows();
    check_forget();
    check_zero_capacity();
    check_tcp_stream();
    check_stream_budget_is_shared();
    check_shared_ptr_stays_valid();
}

}  // namespace

ZC_TEST_MAIN("flow", run)
