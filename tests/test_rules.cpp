// Rule engine: parsing, validation, indexing and matching.
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "test_util.hpp"
#include "zc/rules.hpp"

using namespace zctest;

namespace {

zc::RuleSet load(std::string_view text, std::vector<zc::ConfigProblem>* problems = nullptr) {
    zc::RuleSet rules;
    std::vector<zc::ConfigProblem> local;
    if (!rules.load_text(text, "test", local)) {
        if (problems != nullptr) *problems = local;
        return rules;
    }
    if (problems != nullptr) *problems = local;
    return rules;
}

bool rejects(std::string_view text, std::string& message) {
    std::vector<zc::ConfigProblem> problems;
    const zc::RuleSet rules = load(text, &problems);
    if (!problems.empty()) {
        message = problems.front().to_string();
        return true;
    }
    message.clear();
    return false;
}

void check_strategy_names() {
    zc::Strategy strategy{};
    for (const char* name : {"pass", "split", "disorder", "multisplit", "multidisorder",
                             "fake", "fake-split", "fake-disorder", "fake-multidisorder",
                             "fake-auto", "quic-fake"}) {
        ZC_CHECK_MSG(zc::parse_strategy(name, strategy), name);
    }
    ZC_CHECK(!zc::parse_strategy("nonsense", strategy));
    ZC_CHECK(!zc::parse_strategy("", strategy));
    // The name round-trips.
    for (zc::Strategy s : {zc::Strategy::split, zc::Strategy::fake_auto,
                           zc::Strategy::quic_fake}) {
        zc::Strategy parsed{};
        ZC_CHECK(zc::parse_strategy(zc::strategy_name(s), parsed));
        ZC_CHECK(parsed == s);
    }
    ZC_CHECK(zc::strategy_uses_fake(zc::Strategy::fake_auto));
    ZC_CHECK(!zc::strategy_uses_fake(zc::Strategy::split));
    ZC_CHECK(zc::strategy_splits(zc::Strategy::multidisorder));
    ZC_CHECK(!zc::strategy_splits(zc::Strategy::fake));
}

void check_suffix_matching() {
    const auto rules = load("example.com fake\n"
                            "=exact.example split\n"
                            "*.wild.example disorder\n");
    const zc::IpAddress dest = zc::IpAddress::parse("93.184.216.34");
    auto find = [&](std::string_view host) {
        return rules.match(host, dest, 443, zc::kProtoTcp);
    };

    const zc::Rule* base = find("example.com");
    ZC_REQUIRE(base != nullptr);
    ZC_CHECK(base->strategy == zc::Strategy::fake);

    // Subdomains inherit the suffix rule.
    const zc::Rule* sub = find("cdn.example.com");
    ZC_REQUIRE(sub != nullptr);
    ZC_CHECK(sub->strategy == zc::Strategy::fake);

    // A label boundary is required.
    ZC_CHECK(find("notexample.com") == nullptr);
    ZC_CHECK(find("example.com.evil.net") == nullptr);

    // "=" restricts to the exact host.
    ZC_CHECK(find("exact.example") != nullptr);
    ZC_CHECK(find("sub.exact.example") == nullptr);

    // "*." restricts to subdomains.
    ZC_CHECK(find("a.wild.example") != nullptr);
    ZC_CHECK(find("b.a.wild.example") != nullptr);
    ZC_CHECK(find("wild.example") == nullptr);
}

void check_longest_suffix_wins() {
    const auto rules = load("example.com fake\n"
                            "video.example.com split\n"
                            "a.video.example.com disorder\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.2.3.4");
    const zc::Rule* r = rules.match("x.a.video.example.com", dest, 443, zc::kProtoTcp);
    ZC_REQUIRE(r != nullptr);
    ZC_CHECK(r->strategy == zc::Strategy::disorder);
    r = rules.match("x.video.example.com", dest, 443, zc::kProtoTcp);
    ZC_REQUIRE(r != nullptr);
    ZC_CHECK(r->strategy == zc::Strategy::split);
    r = rules.match("example.com", dest, 443, zc::kProtoTcp);
    ZC_REQUIRE(r != nullptr);
    ZC_CHECK(r->strategy == zc::Strategy::fake);
}

void check_priority_wins() {
    const auto rules = load("example.com fake\n"
                            "video.example.com split priority=10\n"
                            "a.video.example.com disorder priority=5\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.2.3.4");
    // The highest priority wins even though it is the shorter suffix.
    const zc::Rule* r = rules.match("x.a.video.example.com", dest, 443, zc::kProtoTcp);
    ZC_REQUIRE(r != nullptr);
    ZC_CHECK(r->strategy == zc::Strategy::split);
}

void check_pass_action() {
    const auto rules = load("example.com pass\n"
                            "video.example.com fake\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.2.3.4");
    const zc::Rule* r = rules.match("example.com", dest, 443, zc::kProtoTcp);
    ZC_REQUIRE(r != nullptr);
    ZC_CHECK(r->strategy == zc::Strategy::pass);
    const zc::Rule* r2 = rules.match("video.example.com", dest, 443, zc::kProtoTcp);
    ZC_REQUIRE(r2 != nullptr);
    ZC_CHECK(r2->strategy == zc::Strategy::fake);
}

void check_address_matchers() {
    const auto rules = load("cidr:10.0.0.0/8 fake\n"
                            "ip:203.0.113.7 split\n"
                            "cidr:2001:db8::/32 disorder\n");
    ZC_CHECK(rules.match("", zc::IpAddress::parse("10.1.2.3"), 443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("", zc::IpAddress::parse("203.0.113.7"), 443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("", zc::IpAddress::parse("2001:db8::1"), 443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("", zc::IpAddress::parse("8.8.8.8"), 443, zc::kProtoTcp) == nullptr);
    ZC_CHECK(rules.match("", zc::IpAddress::parse("2001:db9::1"), 443, zc::kProtoTcp) == nullptr);
    // A v4 rule must not match a v6 address with the same bytes.
    ZC_CHECK(rules.match("", zc::IpAddress::parse("::a00:1"), 443, zc::kProtoTcp) == nullptr);
}

void check_port_and_protocol_matchers() {
    const auto rules = load("port:8443 fake\n"
                            "proto:udp disorder\n");
    ZC_CHECK(rules.match("", zc::IpAddress::parse("1.1.1.1"), 8443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("", zc::IpAddress::parse("1.1.1.1"), 443, zc::kProtoTcp) == nullptr);
    const zc::Rule* udp = rules.match("", zc::IpAddress::parse("1.1.1.1"), 443, zc::kProtoUdp);
    ZC_REQUIRE(udp != nullptr);
    ZC_CHECK(udp->strategy == zc::Strategy::disorder);
}

void check_conjunction() {
    // All matchers on one line must hold.
    const auto rules = load("example.com port:8443 fake\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.1.1.1");
    ZC_CHECK(rules.match("example.com", dest, 8443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("example.com", dest, 443, zc::kProtoTcp) == nullptr);
    ZC_CHECK(rules.match("other.example", dest, 8443, zc::kProtoTcp) == nullptr);
}

void check_host_rule_needs_a_host() {
    const auto rules = load("example.com fake\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.1.1.1");
    // No hostname available: a hostname rule must not fire.
    ZC_CHECK(rules.match("", dest, 443, zc::kProtoTcp) == nullptr);
}

void check_options() {
    const auto rules = load("example.com fake-auto ttl=7 repeats=4 segs=6 badseq=1 "
                            "badsum=1 rnd=1 sni=www.example.net priority=3 name=custom\n");
    const zc::Rule& rule = rules.rules().front();
    ZC_REQUIRE(rule.overrides.fake_ttl.has_value());
    ZC_CHECK_EQ(*rule.overrides.fake_ttl, 7);
    ZC_REQUIRE(rule.overrides.repeats.has_value());
    ZC_CHECK_EQ(*rule.overrides.repeats, 4);
    ZC_REQUIRE(rule.overrides.segments.has_value());
    ZC_CHECK_EQ(*rule.overrides.segments, 6);
    ZC_REQUIRE(rule.overrides.fooling_badseq.has_value());
    ZC_CHECK(*rule.overrides.fooling_badseq);
    ZC_REQUIRE(rule.overrides.fooling_badsum.has_value());
    ZC_CHECK(*rule.overrides.fooling_badsum);
    ZC_REQUIRE(rule.overrides.randomize_random.has_value());
    ZC_CHECK(*rule.overrides.randomize_random);
    ZC_REQUIRE(rule.overrides.fake_sni.has_value());
    ZC_CHECK_EQ(*rule.overrides.fake_sni, std::string("www.example.net"));
    ZC_CHECK_EQ(rule.priority, 3);
    ZC_CHECK_EQ(rule.name, std::string("custom"));
}

void check_validation() {
    std::string message;
    ZC_CHECK(rejects("example.com\n", message));                       // no action
    ZC_CHECK(rejects("example.com not-a-strategy\n", message));
    ZC_CHECK(rejects("fake\n", message));                              // no matcher
    ZC_CHECK(rejects("cidr:10.0.0.0/33 fake\n", message));            // bad prefix
    ZC_CHECK(rejects("cidr:2001:db8::/129 fake\n", message));
    ZC_CHECK(rejects("ip:not-an-address fake\n", message));
    ZC_CHECK(rejects("port:0 fake\n", message));
    ZC_CHECK(rejects("port:70000 fake\n", message));
    ZC_CHECK(rejects("proto:sctp fake\n", message));
    ZC_CHECK(rejects("example.com fake ttl=999\n", message));
    ZC_CHECK(rejects("example.com fake repeats=0\n", message));
    ZC_CHECK(rejects("example.com fake segs=99\n", message));
    ZC_CHECK(rejects("example.com fake badseq=maybe\n", message));
    ZC_CHECK(rejects("example.com fake sni=bad host\n", message));
    ZC_CHECK(rejects("example.com fake unknown=1\n", message));
    ZC_CHECK(rejects("example.com fake stray\n", message));
    ZC_CHECK(rejects("-bad-.example fake\n", message));

    // Valid configurations must load cleanly.
    ZC_CHECK(!rejects("# only a comment\n", message));
    ZC_CHECK(!rejects("; also a comment\n", message));
    ZC_CHECK(!rejects("\n\n   \n", message));
    ZC_CHECK(!rejects("example.com fake # trailing comment\n", message));
    ZC_CHECK(!rejects("example.com fake ; another comment\n", message));
    ZC_CHECK(!rejects("example.com pass\n", message));
    ZC_CHECK(!rejects("proto:tcp port:443 example.com fake\n", message));
}

void check_matcher_form_forms() {
    const auto rules = load("=exact.example fake\n"
                            ".dotted.example split\n"
                            "*.starred.example disorder\n"
                            "bare.example quic-fake\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.1.1.1");
    auto f = [&](std::string_view h) { return rules.match(h, dest, 443, zc::kProtoTcp); };

    ZC_CHECK(f("exact.example") != nullptr);
    ZC_CHECK(f("sub.exact.example") == nullptr);

    ZC_CHECK(f("dotted.example") == nullptr);
    const zc::Rule* dotted = f("a.dotted.example");
    ZC_REQUIRE(dotted != nullptr);
    ZC_CHECK(dotted->strategy == zc::Strategy::split);

    const zc::Rule* starred = f("a.starred.example");
    ZC_REQUIRE(starred != nullptr);
    ZC_CHECK(starred->strategy == zc::Strategy::disorder);

    const zc::Rule* bare = f("anything.bare.example");
    ZC_REQUIRE(bare != nullptr);
    ZC_CHECK(bare->strategy == zc::Strategy::quic_fake);
}

void check_case_insensitive_domains() {
    const auto rules = load("ExAmPlE.CoM fake\n");
    const zc::IpAddress dest = zc::IpAddress::parse("1.1.1.1");
    ZC_CHECK(rules.match("WWW.EXAMPLE.COM", dest, 443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("www.example.com.", dest, 443, zc::kProtoTcp) != nullptr);
}

void check_excludes() {
    const auto path = std::filesystem::temp_directory_path() / "zc_exclude_test.txt";
    {
        std::ofstream out(path);
        out << "# comment\n";
        out << "banking.example\n";
        out << "0.0.0.0 ads.example\n";
        out << "||tracker.example^\n";
        out << "*.cdn.example\n";
        out << "\n";
    }
    zc::RuleSet rules;
    std::vector<zc::ConfigProblem> problems;
    ZC_REQUIRE(rules.load_exclude_file(path, problems));
    ZC_CHECK(problems.empty());

    ZC_CHECK(rules.excluded("banking.example"));
    ZC_CHECK(rules.excluded("login.banking.example"));
    ZC_CHECK(!rules.excluded("notbanking.example"));
    ZC_CHECK(rules.excluded("ads.example"));
    ZC_CHECK(rules.excluded("tracker.example"));
    ZC_CHECK(rules.excluded("x.cdn.example"));
    ZC_CHECK(!rules.excluded("cdn.example"));
    ZC_CHECK(!rules.excluded("example.org"));
    ZC_CHECK(!rules.excluded(""));

    // Missing file is an error.
    zc::RuleSet missing;
    std::vector<zc::ConfigProblem> missing_problems;
    ZC_CHECK(!missing.load_exclude_file(std::filesystem::temp_directory_path() / "nope.txt",
                                        missing_problems));
    ZC_CHECK(!missing_problems.empty());

    std::filesystem::remove(path);
}

void check_address_exclusions() {
    zc::RuleSet rules;
    // Local and special-purpose destinations must never be desynchronized, whatever the
    // rules say.
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("127.0.0.1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("10.0.0.1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("192.168.1.1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("172.16.0.1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("169.254.1.1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("224.0.0.1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("0.0.0.0")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("::1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("fe80::1")));
    ZC_CHECK(rules.excluded(zc::IpAddress::parse("fc00::1")));
    ZC_CHECK(!rules.excluded(zc::IpAddress::parse("93.184.216.34")));
    ZC_CHECK(!rules.excluded(zc::IpAddress::parse("2606:4700::1111")));
}

void check_include() {
    const auto dir = std::filesystem::temp_directory_path() / "zc_include_test";
    std::filesystem::create_directories(dir);
    const auto inner = dir / "inner.txt";
    {
        std::ofstream out(inner);
        out << "included.example split\n";
    }
    const auto outer = dir / "outer.txt";
    {
        std::ofstream out(outer);
        out << "include inner.txt\n";
        out << "outer.example fake\n";
    }
    zc::RuleSet rules;
    std::vector<zc::ConfigProblem> problems;
    ZC_CHECK_MSG(rules.load_file(outer, problems), problems.empty() ? "" : problems[0].to_string());
    ZC_CHECK_EQ(rules.rules().size(), 2u);

    const zc::IpAddress dest = zc::IpAddress::parse("1.1.1.1");
    ZC_CHECK(rules.match("x.included.example", dest, 443, zc::kProtoTcp) != nullptr);
    ZC_CHECK(rules.match("x.outer.example", dest, 443, zc::kProtoTcp) != nullptr);

    // A missing include is an error, not a silent skip.
    const auto broken = dir / "broken.txt";
    {
        std::ofstream out(broken);
        out << "include does-not-exist.txt\n";
    }
    zc::RuleSet broken_rules;
    std::vector<zc::ConfigProblem> broken_problems;
    ZC_CHECK(!broken_rules.load_file(broken, broken_problems));
    ZC_CHECK(!broken_problems.empty());

    std::filesystem::remove_all(dir);
}

void check_deep_nesting_is_bounded() {
    const auto dir = std::filesystem::temp_directory_path() / "zc_nest_test";
    std::filesystem::create_directories(dir);
    // A cycle must terminate instead of recursing until the stack overflows.
    {
        std::ofstream a(dir / "a.txt");
        a << "include b.txt\n";
        std::ofstream b(dir / "b.txt");
        b << "include a.txt\n";
    }
    zc::RuleSet rules;
    std::vector<zc::ConfigProblem> problems;
    const bool loaded = rules.load_file(dir / "a.txt", problems);
    ZC_CHECK_MSG(!loaded, "an include cycle must be reported, not followed forever");
    std::filesystem::remove_all(dir);
}

void check_many_rules() {
    std::string text;
    for (int i = 0; i < 2000; ++i) {
        text += "host" + std::to_string(i) + ".example split\n";
    }
    const auto rules = load(text);
    ZC_CHECK_EQ(rules.rules().size(), 2000u);
    const zc::IpAddress dest = zc::IpAddress::parse("1.1.1.1");
    for (int i : {0, 1, 999, 1999}) {
        const zc::Rule* r = rules.match("www.host" + std::to_string(i) + ".example", dest, 443,
                                       zc::kProtoTcp);
        ZC_CHECK_MSG(r != nullptr, "host" + std::to_string(i));
    }
    ZC_CHECK(rules.match("www.host2000.example", dest, 443, zc::kProtoTcp) == nullptr);
}

void run() {
    check_strategy_names();
    check_suffix_matching();
    check_longest_suffix_wins();
    check_priority_wins();
    check_pass_action();
    check_address_matchers();
    check_port_and_protocol_matchers();
    check_conjunction();
    check_host_rule_needs_a_host();
    check_options();
    check_validation();
    check_matcher_form_forms();
    check_case_insensitive_domains();
    check_excludes();
    check_address_exclusions();
    check_include();
    check_deep_nesting_is_bounded();
    check_many_rules();
}

}  // namespace

ZC_TEST_MAIN("rules", run)
