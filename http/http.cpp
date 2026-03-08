#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "http/http.hpp"
#include "vault/vault.hpp"
#include "auth/auth.hpp"

#include <crystals/base64.hpp>
#include <crystals/tray.hpp>

#include <nlohmann/json.hpp>

#include <httplib.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace sarek {
namespace {

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

static std::string jerr(const std::string& msg) {
    return json{{"error", msg}}.dump();
}

static std::string jok(const std::string& msg = "ok") {
    return json{{"status", msg}}.dump();
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

// Extract raw token bytes from "Authorization: Bearer <base64>" header.
static std::vector<uint8_t> extract_bearer(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end())
        throw std::runtime_error("Missing Authorization header");
    const std::string& hdr = it->second;
    if (hdr.size() < 7 || hdr.substr(0, 7) != "Bearer ")
        throw std::runtime_error("Authorization must be 'Bearer <token>'");
    return base64_decode(hdr.substr(7));
}

// Validate Bearer token; on failure sets res to 401 and returns nullopt.
static std::optional<TokenClaims> try_auth(
        const httplib::Request& req, httplib::Response& res,
        const Tray& tok_tray) {
    try {
        auto wire = extract_bearer(req);
        return validate_token(wire, tok_tray);
    } catch (const std::exception& e) {
        res.status = 401;
        res.set_content(jerr(e.what()), "application/json");
        return std::nullopt;
    }
}

// Does this token have wildcard admin access?
static bool is_admin(const TokenClaims& c) {
    for (const auto& a : c.assertions)
        if (a == "/*") return true;
    return false;
}

// Does a slc: assertion or /* cover the given path?
static bool scope_allows(const TokenClaims& c, const std::string& path) {
    for (const auto& a : c.assertions) {
        if (a == "/*") return true;
        if (a.size() > 4 && a.substr(0, 4) == "slc:") {
            std::string scope = a.substr(4);
            if (!scope.empty() && scope.back() == '*') {
                std::string pfx = scope.substr(0, scope.size() - 1);
                if (path.size() >= pfx.size() && path.substr(0, pfx.size()) == pfx)
                    return true;
            } else {
                if (path == scope) return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tray type string → TrayType enum
// ---------------------------------------------------------------------------

static TrayType tray_type_from_str(const std::string& s) {
    if (s == "level0")  return TrayType::Level0;
    if (s == "level1")  return TrayType::Level1;
    if (s == "level2")  return TrayType::Level2;
    if (s == "level3")  return TrayType::Level3;
    if (s == "level5")  return TrayType::Level5;
    throw std::invalid_argument("unknown tray type '" + s + "'; "
        "valid: level0 level1 level2 level3 level5");
}

// ---------------------------------------------------------------------------
// Tray info JSON (no secret keys)
// ---------------------------------------------------------------------------

static json tray_to_json(const Tray& t) {
    json slots = json::array();
    for (const auto& s : t.slots) {
        slots.push_back({
            {"alg",    s.alg_name},
            {"pk_b64", base64_encode(s.pk.data(), s.pk.size())},
            {"has_sk", !s.sk.empty()}
        });
    }
    return {
        {"id",      t.id},
        {"alias",   t.alias},
        {"type",    t.type_str},
        {"created", t.created},
        {"expires", t.expires},
        {"slots",   slots}
    };
}

// ---------------------------------------------------------------------------
// Random user_id helper (avoid 0 and collision with user DB)
// ---------------------------------------------------------------------------

static uint64_t generate_user_id(SarekEnv& /*env*/) {
    for (int i = 0; i < 16; ++i) {
        uint64_t id = 0;
        if (RAND_bytes(reinterpret_cast<uint8_t*>(&id), 8) != 1)
            throw std::runtime_error("RAND_bytes failed");
        if (id == 0) continue;
        // Check uniqueness: scan would be expensive; use a well-spaced random ID
        // (collision probability negligible for uint64 space).
        return id;
    }
    throw std::runtime_error("generate_user_id: failed");
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

static void register_routes(
        httplib::Server& svr,
        SarekEnv& env,
        const SarekConfig& cfg,
        const Tray& tok_tray,
        LruCache<uint64_t, std::vector<uint8_t>>& data_cache) {

    (void)cfg; // reserved for future rate-limit / policy use

    // ── POST /login ─────────────────────────────────────────────────────────
    svr.Post("/login", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string username = body.at("username").get<std::string>();
            std::string password = body.at("password").get<std::string>();

            auto user_opt = authenticate_user(env, username, password);
            if (!user_opt) {
                res.status = 401;
                res.set_content(jerr("invalid password"), "application/json");
                return;
            }

            auto wire  = issue_token(*user_opt, tok_tray);
            std::string token_b64 = base64_encode(wire.data(), wire.size());

            res.set_content(json{{"token", token_b64}, {"username", username}}.dump(),
                            "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── DELETE /logout ───────────────────────────────────────────────────────
    // Stateless: server has no session state; client deletes its token file.
    svr.Delete("/logout", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        res.set_content(jok("logged out"), "application/json");
    });

    // ── POST /users  (admin only) ────────────────────────────────────────────
    svr.Post("/users", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        if (!is_admin(*claims)) {
            res.status = 403;
            res.set_content(jerr("admin required"), "application/json");
            return;
        }
        try {
            auto body     = json::parse(req.body);
            std::string username = body.at("username").get<std::string>();
            std::string password = body.at("password").get<std::string>();

            std::vector<std::string> assertions;
            assertions.push_back("usr:" + username);
            if (body.contains("assertions")) {
                for (const auto& a : body.at("assertions"))
                    assertions.push_back(a.get<std::string>());
            }

            uint64_t uid = generate_user_id(env);
            create_user(env, username, password, 0, assertions, uid);

            res.set_content(
                json{{"username", username}, {"user_id", uid}}.dump(),
                "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── POST /trays ──────────────────────────────────────────────────────────
    svr.Post("/trays", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            auto body  = json::parse(req.body);
            std::string alias  = body.at("alias").get<std::string>();
            std::string type_s = body.at("type").get<std::string>();

            TrayType tt   = tray_type_from_str(type_s);
            Tray     tray = make_tray(tt, alias);

            // owner is the requesting user (find their user_id via load_user)
            auto user_opt = load_user(env, claims->username);
            if (!user_opt) throw std::runtime_error("current user not found in DB");

            store_tray(env, tray, user_opt->user_id);

            res.set_content(tray_to_json(tray).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /trays ───────────────────────────────────────────────────────────
    svr.Get("/trays", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            auto user_opt = load_user(env, claims->username);
            if (!user_opt) throw std::runtime_error("current user not found in DB");

            auto aliases = list_trays_for_user(env, user_opt->user_id);
            json arr = json::array();
            for (const auto& a : aliases) arr.push_back(a);
            res.set_content(json{{"trays", arr}}.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /trays/:alias ────────────────────────────────────────────────────
    svr.Get(R"(/trays/([^/]+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            std::string alias = req.matches[1].str();
            Tray t = load_tray_by_alias(env, alias);
            res.set_content(tray_to_json(t).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 404;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /secrets/:path/meta ──────────────────────────────────────────────
    // (registered before /secrets/:path to win regex priority)
    svr.Get(R"(/secrets/(.+)/meta)", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        std::string path = "/" + req.matches[1].str();
        if (!scope_allows(*claims, path)) {
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        try {
            MetadataRecord m = read_metadata(env, path);
            json o = {
                {"object_id", m.object_id},
                {"created",   m.created},
                {"size",      m.size},
                {"mimetype",  m.mimetype},
                {"tray_id",   m.tray_id}
            };
            if (!m.link_path.empty())
                o["link_path"] = m.link_path;
            res.set_content(o.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 404;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── POST /secrets/:path ──────────────────────────────────────────────────
    svr.Post(R"(/secrets/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        std::string path = "/" + req.matches[1].str();
        if (!scope_allows(*claims, path)) {
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        try {
            // Tray alias comes from query param "tray"; defaults to "system-token"
            std::string tray_alias = req.has_param("tray")
                ? req.get_param_value("tray")
                : "system-token";

            Tray tray    = load_tray_by_alias(env, tray_alias);
            std::string mimetype = req.get_header_value("Content-Type");
            if (mimetype.empty()) mimetype = "application/octet-stream";

            std::vector<uint8_t> body(req.body.begin(), req.body.end());
            create_secret(env, path, body, tray, mimetype);

            res.status = 201;
            res.set_content(jok("created"), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /secrets/:path ───────────────────────────────────────────────────
    svr.Get(R"(/secrets/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        std::string path = "/" + req.matches[1].str();
        if (!scope_allows(*claims, path)) {
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        try {
            // Get mimetype first for the Content-Type header
            MetadataRecord meta = read_metadata(env, path);
            // (meta may be a link; read_secret follows chain)
            auto plaintext = read_secret(env, path, &data_cache);

            std::string ct = meta.link_path.empty()
                ? meta.mimetype
                : "application/octet-stream";
            res.set_content(
                std::string(plaintext.begin(), plaintext.end()), ct);
        } catch (const std::exception& e) {
            res.status = 404;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /secrets ─────────────────────────────────────────────────────────
    svr.Get("/secrets", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            std::string prefix = req.has_param("prefix")
                ? req.get_param_value("prefix")
                : "";

            // Scope filter: non-admin users see only paths they can access
            auto all = list_secrets(env, prefix);
            json arr = json::array();
            for (const auto& p : all)
                if (scope_allows(*claims, p))
                    arr.push_back(p);
            res.set_content(json{{"secrets", arr}}.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── POST /links ──────────────────────────────────────────────────────────
    svr.Post("/links", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            auto body = json::parse(req.body);
            std::string target = body.at("target").get<std::string>();
            std::string link   = body.at("link").get<std::string>();

            if (!scope_allows(*claims, link) || !scope_allows(*claims, target)) {
                res.status = 403;
                res.set_content(jerr("access denied"), "application/json");
                return;
            }

            create_link(env, target, link);
            res.status = 201;
            res.set_content(jok("created"), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── Health check ─────────────────────────────────────────────────────────
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(jok("healthy"), "application/json");
    });
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// run_server
// ---------------------------------------------------------------------------

void run_server(SarekEnv&          env,
                const SarekConfig& cfg,
                const std::string& cert_path,
                const std::string& key_path) {
    // Load system-token tray (unencrypted Level2, used to validate Bearer tokens)
    Tray tok_tray = load_tray_by_alias(env, "system-token");

    // Shared data cache
    LruCache<uint64_t, std::vector<uint8_t>> data_cache(1024, cfg.cache_ttl_secs);

    if (!cert_path.empty() && !key_path.empty()) {
        // HTTPS path: capture by value for the setup callback
        std::string cp = cert_path;
        std::string kp = key_path;

        httplib::SSLServer svr(
            [cp, kp](httplib::tls::ctx_t raw_ctx) -> bool {
                SSL_CTX* ctx = static_cast<SSL_CTX*>(raw_ctx);
                if (SSL_CTX_use_certificate_file(ctx, cp.c_str(), SSL_FILETYPE_PEM) != 1)
                    return false;
                if (SSL_CTX_use_PrivateKey_file(ctx, kp.c_str(), SSL_FILETYPE_PEM) != 1)
                    return false;
                // Prefer post-quantum hybrid KEM group; fall back to X25519 on older OpenSSL
                SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519");
                return true;
            });

        register_routes(svr, env, cfg, tok_tray, data_cache);
        svr.listen("0.0.0.0", cfg.http_port);
    } else {
        // Plain HTTP (development / test only)
        httplib::Server svr;
        register_routes(svr, env, cfg, tok_tray, data_cache);
        svr.listen("0.0.0.0", cfg.http_port);
    }
}

} // namespace sarek
