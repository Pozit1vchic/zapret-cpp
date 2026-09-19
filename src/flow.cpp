#include "flow.hpp"

namespace zc {

namespace {
constexpr std::uint64_t FLOW_TTL_MS = 10 * 60 * 1000ull;
}

bool FlowCache::seen_and_mark(const FlowKey& k, std::uint64_t now_ms) {
    auto it = table_.find(k);
    if (it != table_.end()) {
        it->second = now_ms;
        return true;
    }
    if (table_.size() >= capacity_) {
        prune(now_ms);
    }
    table_[k] = now_ms;
    return false;
}

void FlowCache::prune(std::uint64_t now_ms) {
    for (auto it = table_.begin(); it != table_.end();) {
        if (now_ms - it->second > FLOW_TTL_MS) {
            it = table_.erase(it);
        } else {
            ++it;
        }
    }
    if (table_.size() >= capacity_) {
        table_.clear();
    }
}

}
