#include "zc/flow.hpp"

#include <algorithm>
#include <utility>

namespace zc {

std::string FlowKey::to_string() const {
    return source.to_string() + ":" + std::to_string(source_port) + " -> " +
           destination.to_string() + ":" + std::to_string(destination_port) + " proto=" +
           std::to_string(static_cast<unsigned>(protocol));
}

std::size_t FlowKeyHash::operator()(const FlowKey& k) const noexcept {
    // FNV-1a over the canonical byte image. IPv4 addresses live in bytes[12..15] of the
    // same 16-byte array as IPv6, so hashing all 16 bytes covers both uniformly.
    std::uint64_t h = 1469598103934665603ull;
    auto mix = [&h](std::uint8_t b) {
        h ^= b;
        h *= 1099511628211ull;
    };
    for (std::uint8_t b : k.source.bytes) mix(b);
    for (std::uint8_t b : k.destination.bytes) mix(b);
    mix(static_cast<std::uint8_t>(k.source_port >> 8));
    mix(static_cast<std::uint8_t>(k.source_port & 0xffu));
    mix(static_cast<std::uint8_t>(k.destination_port >> 8));
    mix(static_cast<std::uint8_t>(k.destination_port & 0xffu));
    mix(k.protocol);
    return static_cast<std::size_t>(h);
}

// ---------------------------------------------------------------------------
// TcpStreamBuffer
// ---------------------------------------------------------------------------

void TcpStreamBuffer::reset() noexcept {
    storage_.clear();
    started_ = false;
    truncated_ = false;
    next_sequence_ = 0;
}

bool TcpStreamBuffer::push(std::uint32_t sequence,
                           std::span<const std::uint8_t> payload) noexcept {
    if (max_bytes_ == 0 || payload.empty()) return false;
    if (!started_) {
        // First data we see for this flow defines the stream origin.
        started_ = true;
        next_sequence_ = sequence;
    }
    // Retransmission or overlap: already have these bytes.
    if (static_cast<std::int32_t>(sequence - next_sequence_) <= 0) {
        const std::uint32_t behind = next_sequence_ - sequence;
        if (behind >= payload.size()) return false;
        // Partial overlap: skip the bytes we already hold.
        const auto skip = static_cast<std::size_t>(behind);
        sequence = next_sequence_;
        payload = payload.subspan(skip);
    } else {
        // A gap. We refuse to buffer holes rather than assembling a stream the peer
        // never sent contiguously; the caller simply keeps waiting for the real bytes.
        return false;
    }

    const std::size_t room = storage_.size() < max_bytes_
                                 ? max_bytes_ - storage_.size()
                                 : std::size_t{0};
    if (room == 0) {
        truncated_ = true;
        return false;
    }
    const std::size_t take = std::min(room, payload.size());
    storage_.insert(storage_.end(), payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(take));
    next_sequence_ += static_cast<std::uint32_t>(take);
    if (take < payload.size()) truncated_ = true;
    return take > 0;
}

// ---------------------------------------------------------------------------
// FlowTable
// ---------------------------------------------------------------------------

std::shared_ptr<FlowEntry> FlowTable::touch(const FlowKey& key, std::uint64_t now_ms,
                                            bool& created) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(key);
    if (it != table_.end()) {
        created = false;
        it->second->last_seen_ms = now_ms;
        ++stats_.reused;
        return it->second;
    }

    if (table_.size() >= capacity_) {
        // Expire first; only evict a live entry when expiry was not enough. Evicting
        // the least recently seen entry keeps the working set of active connections
        // instead of flushing the whole cache and re-desyncing everything.
        prune_locked(now_ms);
        if (table_.size() >= capacity_) {
            auto victim = table_.end();
            for (auto cur = table_.begin(); cur != table_.end(); ++cur) {
                if (victim == table_.end() || cur->second->last_seen_ms < victim->second->last_seen_ms) {
                    victim = cur;
                }
            }
            if (victim != table_.end()) {
                table_.erase(victim);
                ++stats_.evicted;
            }
        }
    }

    auto entry = std::make_shared<FlowEntry>();
    entry->created_ms = now_ms;
    entry->last_seen_ms = now_ms;
    // Give the reassembly buffer only a slice of the per-stream budget so one connection
    // cannot consume the whole table's memory.
    const std::size_t per_flow = stream_budget_ == 0 ? 0 : std::max<std::size_t>(1024, stream_budget_ / 64);
    entry->tcp_stream.configure(per_flow);
    table_.emplace(key, entry);
    created = true;
    ++stats_.created;
    stats_.peak = std::max(stats_.peak, table_.size());
    return entry;
}

void FlowTable::prune_locked(std::uint64_t now_ms) {
    for (auto it = table_.begin(); it != table_.end();) {
        // Tolerate a clock that appears to move backwards (monotonic time is expected,
        // but tests may feed synthetic values starting near zero).
        const bool expired = now_ms >= it->second->last_seen_ms &&
                             now_ms - it->second->last_seen_ms > ttl_ms_;
        if (expired) {
            it = table_.erase(it);
            ++stats_.expired;
        } else {
            ++it;
        }
    }
}

void FlowTable::prune(std::uint64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    prune_locked(now_ms);
}

void FlowTable::forget(const FlowKey& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    table_.erase(key);
}

void FlowTable::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    table_.clear();
}

std::size_t FlowTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}

FlowTableStats FlowTable::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    FlowTableStats s = stats_;
    s.peak = std::max(s.peak, table_.size());
    return s;
}

std::size_t FlowTable::stream_bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t total = 0;
    for (const auto& [key, entry] : table_) {
        (void)key;
        total += entry->tcp_stream.size();
    }
    return total;
}

}  // namespace zc
