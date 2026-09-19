#include "services.hpp"

#include <algorithm>
#include <cctype>

namespace zc {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ends_with_domain(const std::string& host, const std::string& suffix) {
    if (suffix.empty() || host.size() < suffix.size()) {
        return false;
    }
    if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    if (host.size() == suffix.size()) {
        return true;
    }
    char before = host[host.size() - suffix.size() - 1];
    return before == '.';
}

}

const std::vector<Service>& services() {
    static const std::vector<Service> table = {
        // update services (real domains from Flowseal/zapret-discord-youtube lists)
        {"google",       {"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
                          "googlevideo.com", "ggpht.com", "google-analytics.com", "google.ru",
                          "googleadservices.com", "googleadawse.com"},       Strategy::FakeMultidisorder, -1, 3, true},
        {"google-play",  {"android.com", "play.google.com", "gvt1.com", "gvt2.com", "gvt3.com",
                          "gvt4.com", "gvt5.com", "gvt6.com", "gvt7.com", "gvt8.com"},
                                                                          Strategy::FakeMultidisorder, -1, 3, true},
        {"youtube",      {"youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com", "googlevideo.com",
                          "ytimg.com", "googleusercontent.com", "ytstatic"},   Strategy::FakeMultidisorder, -1, 3, true},
        {"discord",      {"discord.com", "discordapp.com", "discord.gg", "discordapp.net",
                          "discord.media", "discord.co", "discord.gift", "discord.new",
                          "discordmerch.com", "discordstatus.com"},           Strategy::FakeAuto,        -1, 2, true},
        {"discord-cdn",  {"discord-attachments-uploads-prd.storage.googleapis.com", "discordcdn.com",
                          "cdn.discordapp.com", "discord.media"},              Strategy::Disorder,        -1, 5, true},
        {"instagram",    {"instagram.com", "cdninstagram.com", "fbcdn.net"},   Strategy::FakeMultidisorder, -1, 3, true},
        {"facebook",     {"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com"}, Strategy::FakeMultidisorder, -1, 3, true},
        {"twitter",      {"twitter.com", "x.com", "twimg.com", "t.co"},        Strategy::FakeMultidisorder, -1, 3, true},
        {"telegram",     {"telegram.org", "t.me", "telegram.me", "telesco.pe", "telegram.dog"},
                                                                          Strategy::Disorder,        -1, 5, true},
        {"whatsapp",     {"whatsapp.com", "whatsapp.net"},                     Strategy::FakeMultidisorder, -1, 3, true},
        {"reddit",       {"reddit.com", "redd.it", "redditmedia.com"},         Strategy::FakeMultidisorder, -1, 3, true},
        {"wikipedia",    {"wikipedia.org", "wikimedia.org"},                   Strategy::FakeMultidisorder, -1, 3, true},
        {"github",       {"github.com", "githubusercontent.com", "githubassets.com"}, Strategy::FakeMultidisorder, -1, 3, true},
        {"openai",       {"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
                          "openai.org", "sora.com"},                            Strategy::FakeMultidisorder, -1, 3, true},
        {"anthropic",    {"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
                          "anthropic-cdn.com", "claude.dev"},                  Strategy::Disorder,        -1, 1, false},
        {"gemini",       {"gemini.google.com", "bard.google.com", "aistudio.google.com",
                          "makersuite.google.com", "deepmind.com", "deepmind.google"},
                                                                          Strategy::Disorder,        -1, 1, false},
        {"copilot",      {"copilot.microsoft.com", "bing.com", "bingapis.com",
                          "microsoft365.com", "githubcopilot.com"},            Strategy::Disorder,        -1, 1, false},
        {"groq",         {"groq.com", "console.groq.com"},                      Strategy::Disorder,        -1, 1, false},
        {"perplexity",   {"perplexity.ai", "pplx.ai"},                          Strategy::Disorder,        -1, 1, false},
        {"xai",          {"x.ai", "grok.com", "api.x.ai"},                      Strategy::Disorder,        -1, 1, false},
        {"mistral",      {"mistral.ai", "mistral.com", "mistralcdn.com"},       Strategy::Disorder,        -1, 1, false},
        {"huggingface",  {"huggingface.co", "hf.co", "hf.space"},               Strategy::Disorder,        -1, 1, false},
        {"cohere",       {"cohere.ai", "cohere.com"},                           Strategy::Disorder,        -1, 1, false},
        {"deepseek",     {"deepseek.com", "deepseek.ai"},                       Strategy::Disorder,        -1, 1, false},
        {"midjourney",   {"midjourney.com"},                                    Strategy::FakeMultidisorder, -1, 3, true},
        {"elevenlabs",   {"elevenlabs.io", "elevenlabs.com"},                   Strategy::FakeMultidisorder, -1, 3, true},
        {"character-ai", {"character.ai"},                                      Strategy::FakeMultidisorder, -1, 3, true},
        {"poe",          {"poe.com", "quora.com"},                              Strategy::FakeMultidisorder, -1, 3, true},
        {"spotify",      {"spotify.com", "scdn.co"},                           Strategy::FakeMultidisorder, -1, 3, true},
        {"netflix",      {"netflix.com", "nflxvideo.net", "nflximg.net"},      Strategy::FakeMultidisorder, -1, 3, true},
        {"twitch",       {"twitch.tv", "ttvnw.net", "jtvnw.net"},              Strategy::FakeMultidisorder, -1, 3, true},
        {"roblox",       {"roblox.com", "rbxcdn.com", "rbx.com"},              Strategy::FakeMultidisorder, -1, 3, true},
        {"cloudflare",   {"cloudflare.com", "cloudflare-dns.com", "cloudflare-ech.com", "cdnjs.cloudflare.com",
                          "cloudflareclient.com", "one.one.one.one"},          Strategy::FakeMultidisorder, -1, 3, true},
        {"cloudfront",   {"cloudfront.net", "cloudfront.com"},                 Strategy::FakeMultidisorder, -1, 3, true},
        {"discord-addons", {"7tv.app", "7tv.io", "betterttv.net", "frankerfacez.com", "ffzap.com",
                          "discordactivities.com", "discordsays.com"},         Strategy::Disorder,        -1, 5, true},
        {"discord-live", {"live-video.net", "dis.gd"},                          Strategy::Disorder,        -1, 5, true},
    };
    return table;
}

bool matches_service(const std::string& sni, const Service& s) {
    std::string host = lower(sni);
    for (const char* suf : s.suffixes) {
        if (suf == nullptr) {
            break;
        }
        if (ends_with_domain(host, suf)) {
            return true;
        }
    }
    return false;
}

const Service* find_service(const std::string& sni) {
    for (const Service& s : services()) {
        if (matches_service(sni, s)) {
            return &s;
        }
    }
    return nullptr;
}

void apply_service(const Service& s, Config& cfg) {
    cfg.strategy = s.strategy;
    cfg.split_pos = s.split_pos;
    cfg.repeats = s.repeats;
    cfg.fooling_badseq = s.fooling_badseq;
}

}
