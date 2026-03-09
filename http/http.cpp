#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "http/http.hpp"
#include "vault/vault.hpp"
#include "auth/auth.hpp"
#include "bootstrap/user_record.hpp"
#include "log/log.hpp"

#include <crystals/base64.hpp>
#include <crystals/tray.hpp>

#include <nlohmann/json.hpp>

#include <httplib.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <atomic>
#include <ctime>
#include <unistd.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;

// Active server instance; set by run_server(), read by request_shutdown().
static std::atomic<httplib::Server*> g_active_svr{nullptr};

namespace sarek {

void request_shutdown() {
    static const char msg[] = "sarek: signal received — shutting down\n";
    (void)write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    httplib::Server* svr = g_active_svr.load(std::memory_order_acquire);
    if (svr) svr->stop();
}

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
        auto log = get_logger();
        try {
            auto body = json::parse(req.body);
            std::string username = body.at("username").get<std::string>();
            std::string password = body.at("password").get<std::string>();

            auto user_opt = authenticate_user(env, username, password);
            if (!user_opt) {
                log->warn("[cmd=login] REJECTED user={} addr={}", username, req.remote_addr);
                res.status = 401;
                res.set_content(jerr("invalid password"), "application/json");
                return;
            }

            auto wire  = issue_token(*user_opt, tok_tray);
            std::string token_b64 = base64_encode(wire.data(), wire.size());

            log->info("[cmd=login] user={} addr={}", username, req.remote_addr);

            res.set_content(json{{"token", token_b64}, {"username", username}}.dump(),
                            "application/json");
        } catch (const std::exception& e) {
            log->error("[cmd=login] error={} addr={}", e.what(), req.remote_addr);
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── DELETE /logout ───────────────────────────────────────────────────────
    // Stateless: server has no session state; client deletes its token file.
    svr.Delete("/logout", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        get_logger()->info("[cmd=logout] user={} addr={}", claims->username, req.remote_addr);
        res.set_content(jok("logged out"), "application/json");
    });

    // ── POST /users/invite  (admin only) ─────────────────────────────────────
    // Creates a user with no password and returns a signed token for the new user.
    svr.Post("/users/invite", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        if (!is_admin(*claims)) {
            get_logger()->warn("[cmd=newuser] admin required user={} addr={}",
                               claims->username, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("admin required"), "application/json");
            return;
        }
        try {
            auto body = json::parse(req.body);
            std::string username = body.at("username").get<std::string>();

            std::vector<std::string> assertions;
            assertions.push_back("usr:" + username);
            if (body.contains("assertions")) {
                for (const auto& a : body.at("assertions"))
                    assertions.push_back(a.get<std::string>());
            }

            uint64_t uid = generate_user_id(env);
            // Empty password → "none" sentinel stored (via create_user in vault)
            create_user(env, username, "", 0, assertions, uid);

            // Load the new record and issue a token for it
            auto user_opt = load_user(env, username);
            if (!user_opt) throw std::runtime_error("failed to load newly created user");

            auto wire = issue_token(*user_opt, tok_tray);
            std::string token_b64 = base64_encode(wire.data(), wire.size());

            get_logger()->info("[cmd=newuser] by={} new_user={} addr={}",
                               claims->username, username, req.remote_addr);

            res.set_content(
                json{{"token", token_b64}, {"username", username}}.dump(),
                "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── POST /users/password  (authenticated user, sets own password) ─────────
    svr.Post("/users/password", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            auto body = json::parse(req.body);
            std::string new_password = body.at("password").get<std::string>();
            if (new_password.empty())
                throw std::invalid_argument("password must not be empty");

            update_user_password(env, claims->username, new_password);
            get_logger()->info("[cmd=changepass] by={} target={} addr={}",
                               claims->username, claims->username, req.remote_addr);
            res.set_content(jok(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /users ───────────────────────────────────────────────────────────
    svr.Get("/users", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        get_logger()->info("[cmd=listusers] by={} addr={}", claims->username, req.remote_addr);
        try {
            auto all = list_users(env);
            bool admin = is_admin(*claims);

            auto user_to_json = [](const std::string& uname, const UserRecord& r) -> json {
                return {
                    {"username",   uname},
                    {"user_id",    r.user_id},
                    {"admin",      bool(r.flags & kUserFlagAdmin)},
                    {"locked",     bool(r.flags & kUserFlagLocked)},
                    {"assertions", r.assertions}
                };
            };

            json arr = json::array();
            if (admin) {
                for (const auto& [uname, rec] : all)
                    arr.push_back(user_to_json(uname, rec));
            } else {
                for (const auto& [uname, rec] : all) {
                    if (uname == claims->username)
                        arr.push_back(user_to_json(uname, rec));
                    else
                        arr.push_back(json{{"username", uname}});
                }
            }
            res.set_content(json{{"users", arr}}.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── POST /users/:username/password ───────────────────────────────────────
    svr.Post(R"(/users/([^/]+)/password)", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        std::string username = req.matches[1].str();
        if (claims->username != username && !is_admin(*claims)) {
            get_logger()->warn("[cmd=changepass] DENIED user={} target={} addr={}",
                               claims->username, username, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        try {
            auto body = json::parse(req.body);
            std::string new_password = body.at("password").get<std::string>();
            if (new_password.empty())
                throw std::invalid_argument("password must not be empty");
            update_user_password(env, username, new_password);
            get_logger()->info("[cmd=changepass] by={} target={} addr={}",
                               claims->username, username, req.remote_addr);
            res.set_content(jok(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── DELETE /users/:username  (admin only) ────────────────────────────────
    svr.Delete(R"(/users/([^/]+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        if (!is_admin(*claims)) {
            get_logger()->warn("[cmd=deluser] admin required user={} addr={}",
                               claims->username, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("admin required"), "application/json");
            return;
        }
        std::string username = req.matches[1].str();
        if (username == claims->username) {
            res.status = 400;
            res.set_content(jerr("cannot delete own account"), "application/json");
            return;
        }
        set_request_user(claims->username);
        try {
            auto target_opt = load_user(env, username);
            if (!target_opt) {
                res.status = 404;
                res.set_content(jerr("user not found"), "application/json");
                clear_request_user();
                return;
            }
            if (target_opt->flags & kUserFlagAdmin) {
                res.status = 400;
                res.set_content(jerr("cannot delete admin account"), "application/json");
                clear_request_user();
                return;
            }
            auto result = delete_user(env, username);
            get_logger()->warn("[cmd=deluser] by={} target={} trays={} secrets={} addr={}",
                               claims->username, username,
                               result.trays_deleted, result.secrets_deleted, req.remote_addr);
            res.set_content(
                json{{"deleted",  username},
                     {"trays",    result.trays_deleted},
                     {"secrets",  result.secrets_deleted}}.dump(),
                "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
        clear_request_user();
    });

    // ── DELETE /admin/flush  (admin only) ────────────────────────────────────
    svr.Delete("/admin/flush", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        if (!is_admin(*claims)) {
            get_logger()->warn("[cmd=flush] admin required user={} addr={}",
                               claims->username, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("admin required"), "application/json");
            return;
        }
        if (!req.has_param("confirm") || req.get_param_value("confirm") != "flush") {
            res.status = 400;
            res.set_content(
                jerr("add query param ?confirm=flush to proceed"),
                "application/json");
            return;
        }
        get_logger()->warn("[cmd=flush] ALL DATABASES FLUSHED by={} addr={}",
                           claims->username, req.remote_addr);
        env.tray().truncate();
        env.tray_alias().truncate();
        env.user().truncate();
        env.data().truncate();
        env.metadata().truncate();
        env.path().truncate();
        res.set_content(
            json{{"status",  "flushed"},
                 {"message", "All databases cleared. Restart server to re-bootstrap."}}.dump(),
            "application/json");
        request_shutdown();
    });

    // ── POST /users  (admin only) ────────────────────────────────────────────
    svr.Post("/users", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        if (!is_admin(*claims)) {
            get_logger()->warn("[cmd=createuser] admin required user={} addr={}",
                               claims->username, req.remote_addr);
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

            get_logger()->info("[cmd=createuser] by={} new_user={} addr={}",
                               claims->username, username, req.remote_addr);

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

            get_logger()->info("[cmd=keygen] user={} alias={} type={} addr={}",
                               claims->username, alias, type_s, req.remote_addr);

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
        get_logger()->info("[cmd=listtrays] user={} addr={}", claims->username, req.remote_addr);
        try {
            std::vector<std::string> aliases;
            if (is_admin(*claims)) {
                aliases = list_all_trays(env);
            } else {
                auto user_opt = load_user(env, claims->username);
                if (!user_opt) throw std::runtime_error("current user not found in DB");
                aliases = list_trays_for_user(env, user_opt->user_id);
            }
            json arr = json::array();
            for (const auto& a : aliases) arr.push_back(a);
            res.set_content(json{{"trays", arr}}.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /trays/:alias/export ─────────────────────────────────────────────
    // Returns tray JSON including sk_b64 for all slots. Owner or admin only.
    // Registered before /trays/:alias so it matches first.
    svr.Get(R"(/trays/([^/]+)/export)", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            std::string alias = req.matches[1].str();
            get_logger()->info("[cmd=exporttray] user={} alias={} addr={}",
                               claims->username, alias, req.remote_addr);
            Tray t = load_tray_by_alias(env, alias);

            // Ownership check: must be admin or own the tray
            if (!is_admin(*claims)) {
                auto user_opt = load_user(env, claims->username);
                if (!user_opt) throw std::runtime_error("current user not found in DB");
                auto owned = list_trays_for_user(env, user_opt->user_id);
                bool found = false;
                for (const auto& a : owned) if (a == alias) { found = true; break; }
                if (!found) {
                    get_logger()->warn("[cmd=exporttray] DENIED user={} alias={} addr={}",
                                       claims->username, alias, req.remote_addr);
                    res.status = 403;
                    res.set_content(jerr("access denied"), "application/json");
                    return;
                }
            }

            // Build response including secret key bytes
            json slots = json::array();
            for (const auto& s : t.slots) {
                json slot = {
                    {"alg",    s.alg_name},
                    {"pk_b64", base64_encode(s.pk.data(), s.pk.size())}
                };
                if (!s.sk.empty())
                    slot["sk_b64"] = base64_encode(s.sk.data(), s.sk.size());
                slots.push_back(slot);
            }
            json out = {
                {"id",      t.id},
                {"alias",   t.alias},
                {"type",    t.type_str},
                {"created", t.created},
                {"expires", t.expires},
                {"slots",   slots}
            };
            res.set_content(out.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 404;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── POST /trays/:alias/view  (admin only, decrypts PWENC tray) ───────────
    // Registered before GET /trays/:alias so the regex matches first.
    svr.Post(R"(/trays/([^/]+)/view)", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        if (!is_admin(*claims)) {
            get_logger()->warn("[cmd=viewtray] admin required user={} addr={}",
                               claims->username, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("admin required"), "application/json");
            return;
        }
        try {
            std::string alias = req.matches[1].str();
            auto body = json::parse(req.body);
            std::string password = body.at("password").get<std::string>();
            Tray t = load_tray_by_alias_pwenc(env, alias, password);
            res.set_content(tray_to_json(t).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
    });

    // ── GET /trays/:alias ────────────────────────────────────────────────────
    svr.Get(R"(/trays/([^/]+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            std::string alias = req.matches[1].str();
            get_logger()->info("[cmd=gettray] user={} alias={} addr={}",
                               claims->username, alias, req.remote_addr);
            // If PWENC-encrypted: admin gets a prompt indicator; non-admin gets 403.
            if (is_tray_encrypted(env, alias)) {
                if (!is_admin(*claims)) {
                    get_logger()->warn("[cmd=gettray] DENIED (encrypted) user={} alias={} addr={}",
                                       claims->username, alias, req.remote_addr);
                    res.status = 403;
                    res.set_content(jerr("access denied"), "application/json");
                } else {
                    res.set_content(
                        json{{"encrypted", true}, {"alias", alias}}.dump(),
                        "application/json");
                }
                return;
            }
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
            get_logger()->warn("[cmd=meta] DENIED user={} path={} addr={}",
                               claims->username, path, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        get_logger()->info("[cmd=meta] user={} path={} addr={}",
                           claims->username, path, req.remote_addr);
        set_request_user(claims->username);
        try {
            MetadataRecord m = read_metadata(env, path);
            json o = {
                {"object_id",  m.object_id},
                {"created",    m.created},
                {"size",       m.size},
                {"mimetype",   m.mimetype},
                {"tray_id",    m.tray_id},
                {"creator_id", m.creator_id}
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
            get_logger()->warn("[cmd=create] DENIED user={} path={} addr={}",
                               claims->username, path, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        set_request_user(claims->username);
        try {
            // Tray alias comes from query param "tray"; defaults to "system-token"
            std::string tray_alias = req.has_param("tray")
                ? req.get_param_value("tray")
                : "system-token";

            Tray tray    = load_tray_by_alias(env, tray_alias);
            std::string mimetype = req.get_header_value("Content-Type");
            if (mimetype.empty()) mimetype = "application/octet-stream";

            auto creator_opt = load_user(env, claims->username);
            uint64_t creator_id = creator_opt ? creator_opt->user_id : 0;

            std::vector<uint8_t> body_bytes(req.body.begin(), req.body.end());
            create_secret(env, path, body_bytes, tray, mimetype, creator_id);

            get_logger()->info("[cmd=create] user={} path={} size={} addr={}",
                               claims->username, path, req.body.size(), req.remote_addr);

            res.status = 201;
            res.set_content(jok("created"), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
        clear_request_user();
    });

    // ── GET /secrets/:path ───────────────────────────────────────────────────
    svr.Get(R"(/secrets/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        std::string path = "/" + req.matches[1].str();
        if (!scope_allows(*claims, path)) {
            get_logger()->warn("[cmd=read] DENIED user={} path={} addr={}",
                               claims->username, path, req.remote_addr);
            res.status = 403;
            res.set_content(jerr("access denied"), "application/json");
            return;
        }
        get_logger()->info("[cmd=read] user={} path={} addr={}",
                           claims->username, path, req.remote_addr);
        set_request_user(claims->username);
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
        clear_request_user();
    });

    // ── GET /secrets ─────────────────────────────────────────────────────────
    svr.Get("/secrets", [&](const httplib::Request& req, httplib::Response& res) {
        auto claims = try_auth(req, res, tok_tray);
        if (!claims) return;
        try {
            std::string prefix = req.has_param("prefix")
                ? req.get_param_value("prefix")
                : "";

            get_logger()->info("[cmd=secrets] user={} prefix={} addr={}",
                               claims->username, prefix, req.remote_addr);

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
        set_request_user(claims->username);
        try {
            auto body = json::parse(req.body);
            std::string target = body.at("target").get<std::string>();
            std::string link   = body.at("link").get<std::string>();

            if (!scope_allows(*claims, link) || !scope_allows(*claims, target)) {
                get_logger()->warn("[cmd=link] DENIED user={} target={} link={} addr={}",
                                   claims->username, target, link, req.remote_addr);
                res.status = 403;
                res.set_content(jerr("access denied"), "application/json");
                clear_request_user();
                return;
            }

            create_link(env, target, link);
            get_logger()->info("[cmd=link] user={} target={} link={} addr={}",
                               claims->username, target, link, req.remote_addr);
            res.status = 201;
            res.set_content(jok("created"), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(jerr(e.what()), "application/json");
        }
        clear_request_user();
    });

    // ── Health check ─────────────────────────────────────────────────────────
    svr.Get("/health", [](const httplib::Request& req, httplib::Response& res) {
        get_logger()->info("[cmd=health] addr={}", req.remote_addr);
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

        svr.set_trusted_proxies(cfg.trusted_proxies);
        register_routes(svr, env, cfg, tok_tray, data_cache);
        g_active_svr.store(&svr, std::memory_order_release);
        if (!svr.bind_to_port("0.0.0.0", cfg.http_port))
            throw std::runtime_error("failed to bind to port " + std::to_string(cfg.http_port));
        get_logger()->info("server started successfully on port {} (HTTPS)", cfg.http_port);
        svr.listen_after_bind();
        g_active_svr.store(nullptr, std::memory_order_release);
        get_logger()->info("signal received — shutting down");
    } else {
        // Plain HTTP (development / test only)
        httplib::Server svr;
        svr.set_trusted_proxies(cfg.trusted_proxies);
        register_routes(svr, env, cfg, tok_tray, data_cache);
        g_active_svr.store(&svr, std::memory_order_release);
        if (!svr.bind_to_port("0.0.0.0", cfg.http_port))
            throw std::runtime_error("failed to bind to port " + std::to_string(cfg.http_port));
        get_logger()->info("server started successfully on port {} (HTTP)", cfg.http_port);
        svr.listen_after_bind();
        g_active_svr.store(nullptr, std::memory_order_release);
        get_logger()->info("signal received — shutting down");
    }
}

} // namespace sarek
