// Flow tracking and TCP stream reassembly.
//
// Two responsibilities, both of which the old implementation got wrong or omitted:
//   * remember which flows have already been processed, so a one-shot desync strategy
//     is not applied again to a retransmitted ClientHello or request;
//   * accumulate the first bytes of a TCP flow so a ClientHello split across several
//     segments can be parsed once enough data has arrived, instead of guessing.
//
// Everything here is bounded. A flow entry costs a fixed amount of memory, the table
// itself is capped, and entries expire. The capture loop is single threaded, but the
// table stores `shared_ptr` entries and is internally synchronised so that adding a
// second capture thread later cannot silently corrupt it.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "zc/packet.hpp"
#include "zc/quic.hpp"

namespace zc {

// Identity of a bidirectional connection as seen by this machine. The protocol, both
// addresses and both ports are all required: reusing ephemeral source ports across
// destinations must not collide, and an IPv4 and an IPv6 flow to the same service must
// not share state.
struct FlowKey {
    IpAddress source{};
    IpAddress destination{};
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint8_t protocol = 0;

    [[nodiscard]] bool operator==(const FlowKey& o) const noexcept {
        return protocol == o.protocol && source_port == o.source_port &&
               destination_port == o.destination_port && source == o.source &&
               destination == o.destination;
    }
    [[nodiscard]] std::string to_string() const;
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept;
};

// Bounded, in-order reassembly of the beginning of a TCP stream.
class TcpStreamBuffer {
public:
    void configure(std::size_t max_bytes) noexcept { max_bytes_ = max_bytes; }
    void reset() noexcept;

    // Append payload that is contiguous with what we already have. Retransmissions and
    // out-of-order segments are ignored (never buffered) so the stream stays cheap and
    // cannot be reordered into something the peer never sent in that order.
    bool push(std::uint32_t sequence, std::span<const std::uint8_t> payload) noexcept;

    [[nodiscard]] std::span<const std::uint8_t> data() const noexcept {
        return {storage_.data(), storage_.size()};
    }
    [[nodiscard]] std::size_t size() const noexcept { return storage_.size(); }
    [[nodiscard]] std::size_t capacity() const noexcept { return max_bytes_; }
    [[nodiscard]] bool truncated() const noexcept { return truncated_; }
    [[nodiscard]] bool started() const noexcept { return started_; }
    // Next byte offset expected from the peer; exposed for tests and diagnostics.
    [[nodiscard]] std::uint32_t next_sequence_for_test() const noexcept {
        return next_sequence_;
    }

private:
    std::vector<std::uint8_t> storage_;
    std::size_t max_bytes_ = 0;
    std::uint32_t next_sequence_ = 0;
    bool started_ = false;
    bool truncated_ = false;
};

// Per-connection state. All members are cheap to copy; the two buffers are only
// populated for flows we actually care about.
struct FlowEntry {
    std::uint64_t created_ms = 0;
    std::uint64_t last_seen_ms = 0;

    bool desynced = false;          // the one-shot strategy has already been applied
    bool closed = false;            // FIN/RST observed
    bool classified = false;        // the hostname is known (or definitively absent)
    std::string host;               // empty when the hostname could not be determined

    std::uint64_t largest_quic_packet_number = 0;
    CryptoStream quic_crypto;
    TcpStreamBuffer tcp_stream;
};

struct FlowTableStats {
    std::uint64_t created = 0;
    std::uint64_t expired = 0;
    std::uint64_t evicted = 0;
    std::uint64_t reused = 0;   // hits on an entry that already existed
    std::size_t peak = 0;
};

class FlowTable {
public:
    FlowTable(std::size_t capacity, std::uint64_t ttl_ms, std::size_t stream_budget_bytes)
        : capacity_(capacity == 0 ? 1 : capacity),
          ttl_ms_(ttl_ms == 0 ? 1 : ttl_ms),
          stream_budget_(stream_budget_bytes) {}

    FlowTable(const FlowTable&) = delete;
    FlowTable& operator=(const FlowTable&) = delete;

    // Returns the entry for `key`, creating it when absent, and refreshes its timestamp.
    // The shared_ptr keeps the entry alive even if another thread evicts it meanwhile.
    // `created` reports whether this is the first sighting.
    std::shared_ptr<FlowEntry> touch(const FlowKey& key, std::uint64_t now_ms, bool& created);

    void forget(const FlowKey& key);
    void prune(std::uint64_t now_ms);
    void clear();

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] std::uint64_t ttl_ms() const noexcept { return ttl_ms_; }
    [[nodiscard]] FlowTableStats stats() const;
    // Total bytes currently held by TCP stream buffers, so the caller can prove the
    // budget is respected.
    [[nodiscard]] std::size_t stream_bytes() const;

private:
    void prune_locked(std::uint64_t now_ms);

    mutable std::mutex mutex_;
    std::size_t capacity_;
    std::uint64_t ttl_ms_;
    std::size_t stream_budget_;
    std::unordered_map<FlowKey, std::shared_ptr<FlowEntry>, FlowKeyHash> table_;
    FlowTableStats stats_;
};

}  // namespace zc
