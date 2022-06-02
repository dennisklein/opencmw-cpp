#ifndef OPENCMW_CPP_RESTCLIENT_HPP
#define OPENCMW_CPP_RESTCLIENT_HPP

#include <memory>
#include <ranges>

#include <ClientContext.hpp>
#include <MIME.hpp>
#include <opencmw.hpp>
#include <ThreadPool.hpp>

#include "RestDefaultClientCertificates.hpp"

#ifndef __EMSCRIPTEN__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <httplib.h>
#pragma GCC diagnostic pop
#else

#endif

namespace opencmw::client {

class DefaultContentTypeHeader {
    const MIME::MimeType &_mimeType;

public:
    DefaultContentTypeHeader(const MIME::MimeType &type) noexcept
        : _mimeType(FWD(type)){};
    DefaultContentTypeHeader(const std::string_view type_str) noexcept
        : _mimeType(FWD(MIME::getType(type_str))){};
    constexpr operator const MIME::MimeType() const noexcept { return _mimeType; };
};

class MinIoThreads {
    const int _minThreads = 1;

public:
    MinIoThreads() = default;
    MinIoThreads(int value) noexcept
        : _minThreads(value){};
    constexpr operator int() const noexcept { return _minThreads; };
};

class MaxIoThreads {
    const int _maxThreads = 10'000;

public:
    MaxIoThreads() = default;
    MaxIoThreads(int value) noexcept
        : _maxThreads(value){};
    constexpr operator int() const noexcept { return _maxThreads; };
};

struct ClientCertificates {
    const std::string _certificates;

    ClientCertificates() = default;
    ClientCertificates(const char *X509_ca_bundle) noexcept
        : _certificates(X509_ca_bundle){};
    ClientCertificates(const std::string &X509_ca_bundle) noexcept
        : _certificates(X509_ca_bundle){};
    constexpr operator std::string() const noexcept { return _certificates; };
};

namespace detail {
template<bool exactMatch, typename RequiredType, typename Item>
constexpr auto find_type_helper(Item &item) {
    if constexpr (std::is_same_v<Item, RequiredType>) {
        return std::tuple<RequiredType>(item);
    } else if constexpr (std::is_convertible_v<Item, RequiredType> && !exactMatch) {
        return std::tuple<RequiredType>(RequiredType(item));
    } else {
        return std::tuple<>();
    }
}

template<bool exactMatch = false, typename RequiredType, typename Func, typename... Items>
    requires std::is_invocable_r_v<RequiredType, Func>
constexpr RequiredType find_type(Func defaultGenerator, Items... args) {
    auto ret = std::tuple_cat(find_type_helper<exactMatch, RequiredType>(args)...);
    if constexpr (std::tuple_size_v<decltype(ret)> == 0) {
        return defaultGenerator();
    } else {
        return std::get<0>(ret);
    }
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
int readCertificateBundleFromBuffer(X509_STORE &cert_store, const std::string_view &X509_ca_bundle) {
    BIO *cbio = BIO_new_mem_buf(X509_ca_bundle.data(), static_cast<int>(X509_ca_bundle.size()));
    if (!cbio) {
        return -1;
    }
    STACK_OF(X509_INFO) *inf = PEM_X509_INFO_read_bio(cbio, nullptr, nullptr, nullptr);

    if (!inf) {
        BIO_free(cbio); // cleanup
        return -1;
    }
    // iterate over all entries from the pem file, add them to the x509_store one by one
    int count = 0;
    for (int i = 0; i < sk_X509_INFO_num(inf); i++) {
        X509_INFO *itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            X509_STORE_add_cert(&cert_store, itmp->x509);
            count++;
        }
        if (itmp->crl) {
            X509_STORE_add_crl(&cert_store, itmp->crl);
            count++;
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);
    return count;
}

X509_STORE *createCertificateStore(const std::string_view &X509_ca_bundle) {
    X509_STORE *cert_store    = X509_STORE_new();
    const auto  nCertificates = detail::readCertificateBundleFromBuffer(*cert_store, X509_ca_bundle);
    if (nCertificates <= 0) {
        X509_STORE_free(cert_store);
        throw std::invalid_argument(fmt::format("failed to read certificate bundle from buffer:\n#---start---\n{}\n#---end---\n", X509_ca_bundle));
    }
    return cert_store;
}

X509 *readServerCertificateFromFile(const std::string_view &X509_ca_bundle) {
    BIO *certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, X509_ca_bundle.data(), static_cast<int>(X509_ca_bundle.size()));
    X509 *certX509 = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    if (certX509) {
        return certX509;
    }
    X509_free(certX509);
    throw std::invalid_argument(fmt::format("failed to read certificate from buffer:\n#---start---\n{}\n#---end---\n", X509_ca_bundle));
}

EVP_PKEY *readServerPrivateKeyFromFile(const std::string_view &X509_private_key) {
    BIO *certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, X509_private_key.data(), static_cast<int>(X509_private_key.size()));
    EVP_PKEY *privateKeyX509 = PEM_read_bio_PrivateKey(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    if (privateKeyX509) {
        return privateKeyX509;
    }
    EVP_PKEY_free(privateKeyX509);
    throw std::invalid_argument(fmt::format("failed to read private key from buffer"));
}

#endif

} // namespace detail

class RestClient : public ClientBase {
    constexpr static const char  *ACCEPT_HEADER = "accept";
    static const httplib::Headers EVT_STREAM_HEADERS;
    using ThreadPoolType = std::shared_ptr<BasicThreadPool<IO_BOUND>>;

    std::string                            _name;
    MIME::MimeType                         _mimeType;
    const int                              _minIoThreads;
    const int                              _maxIoThreads;
    ThreadPoolType                         _thread_pool;
    std::string                            _caCertificate;

    std::mutex                             _subscriptionLock;
    std::map<URI<STRICT>, httplib::Client> _subscription1;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    X509_STORE                               *_client_cert_store = nullptr;
    std::map<URI<STRICT>, httplib::SSLClient> _subscription2;
#endif

public:
    static bool CHECK_CERTIFICATES;
    template<typename... Args>
    explicit(false) RestClient(Args... initArgs)
        : _name(detail::find_type<false, std::string>([] { return "RestClient"; }, initArgs...)), //
        _mimeType(detail::find_type<true, DefaultContentTypeHeader>([this] { return MIME::JSON; }, initArgs...))
        , _minIoThreads(detail::find_type<true, MinIoThreads>([] { return MinIoThreads(); }, initArgs...))
        , _maxIoThreads(detail::find_type<true, MaxIoThreads>([] { return MaxIoThreads(); }, initArgs...))
        , _thread_pool(detail::find_type<true, ThreadPoolType>([this] { return std::make_shared<BasicThreadPool<IO_BOUND>>(_name, _minIoThreads, _maxIoThreads); }, initArgs...))
        , _caCertificate(detail::find_type<true, ClientCertificates>([] { return rest::DefaultCertificate().get(); }, initArgs...)) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (_client_cert_store != nullptr) {
            X509_STORE_free(_client_cert_store);
        }
        _client_cert_store = detail::createCertificateStore(_caCertificate);
#endif
    }
    ~RestClient() override { RestClient::stop(); };

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    std::vector<std::string> protocols() noexcept override { return { "http", "https" }; }
#else
    std::vector<std::string> protocols() noexcept override { return { "http" }; }
#endif
    void                         stop() noexcept override { stopAllSubscriptions(); };
    [[nodiscard]] std::string    name() const noexcept { return _name; }
    [[nodiscard]] ThreadPoolType threadPool() const noexcept { return _thread_pool; }
    [[nodiscard]] MIME::MimeType defaultMimeType() const noexcept { return _mimeType; }
    [[nodiscard]] std::string    clientCertificate() const noexcept { return _caCertificate; }

    void                         request(Command &cmd) override {
        switch (cmd.type) {
        case Command::Type::Get:
        case Command::Type::Set:
            _thread_pool->execute([this, cmd = std::move(cmd)]() mutable { executeCommand(std::move(cmd)); });
            return;
        case Command::Type::Subscribe:
            _thread_pool->execute([this, cmd = std::move(cmd)]() mutable { startSubscription(std::move(cmd)); });
            return;
        case Command::Type::Unsubscribe: // deregister existing subscription URI is key
            _thread_pool->execute([this, cmd = std::move(cmd)]() mutable { stopSubscription(cmd); });
            return;
        default:
            throw std::invalid_argument("command type is undefined");
        }
    }

private:
    httplib::Headers getPreferredContentTypeHeader(const URI<STRICT> &uri) const {
        auto       mimeType     = _mimeType.typeName().data();
        const auto acceptHeader = uri.queryParamMap().find(ACCEPT_HEADER);
        if (acceptHeader != uri.queryParamMap().end() && acceptHeader->second) {
            mimeType = acceptHeader->second->c_str();
        }
        const httplib::Headers headers = { { ACCEPT_HEADER, mimeType } };
        return headers;
    }

    void executeCommand(Command &&cmd) const {
        std::cout << "RestClient::request(" << (cmd.uri->str) << ")" << std::endl;
        auto preferredHeader = getPreferredContentTypeHeader(*cmd.uri);
        auto callback        = [&cmd, &preferredHeader]<typename ClientType>(ClientType &client) {
            if (const httplib::Result &result = client.Get(cmd.uri->path()->data(), preferredHeader)) {
                if (cmd.callback) {
                    std::vector<std::byte> ldata;
                    ldata.reserve(result->body.size());
                    std::memcpy(ldata.data(), result->body.c_str(), result->body.size());
                    cmd.callback(RawMessage{ .id = 0, .context = "TestContext", .endpoint = std::move(cmd.uri), .data = std::move(ldata) });
                }
            } else {
                const std::string errorStr = fmt::format("{}", result.error());
                throw std::runtime_error(fmt::format("GET request failed for: '{}' - {} - CHECK_CERTIFICATES: {}", cmd.uri->str, errorStr, CHECK_CERTIFICATES));
            }
        };

        if (start_with_case_ignore(*cmd.uri->scheme(), "https")) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            httplib::SSLClient client(cmd.uri->hostName().value(), cmd.uri->port() ? cmd.uri->port().value() : 443);
            client.set_ca_cert_store(_client_cert_store);
            client.enable_server_certificate_verification(CHECK_CERTIFICATES);
            callback(client);
#else
            throw std::invalid_argument("https is not supported");
#endif
        } else if (start_with_case_ignore(*cmd.uri->scheme(), "http")) {
            httplib::Client client(cmd.uri->hostName().value(), cmd.uri->port() ? cmd.uri->port().value() : 80);
            callback(client);
            return;
        } else {
            throw std::invalid_argument(fmt::format("unsupported protocol: '{}'", cmd.uri->scheme()));
        }
    }

    bool start_with_case_ignore(const std::string &a, const std::string &b) const {
        if (a.size() < b.size()) {
            return false;
        }
        for (size_t i = 0; i < b.size(); i++) {
            if (::tolower(a[i]) != ::tolower(b[i])) {
                return false;
            }
        }
        return true;
    }

    void startSubscription(Command &&cmd) {
        std::cout << "RestClient::startSubscription(" << (cmd.uri->str) << ")" << std::endl;
        std::scoped_lock lock(_subscriptionLock);
        if (start_with_case_ignore(*cmd.uri->scheme(), "http")) {
            auto it = _subscription1.find(*cmd.uri);
            if (it == _subscription1.end()) {
                auto      &client      = _subscription1.try_emplace(*cmd.uri, httplib::Client(cmd.uri->hostName().value(), cmd.uri->port().value())).first->second;
                auto       pollClient  = httplib::Client(cmd.uri->hostName().value(), cmd.uri->port().value());
                const auto pollHeaders = getPreferredContentTypeHeader(*cmd.uri);
                if (const httplib::Result &sseResult = client.Get(cmd.uri->path()->data(), EVT_STREAM_HEADERS, [&](const char *data, size_t data_length) {
                        if (const httplib::Result &result = pollClient.Get(cmd.uri->path()->data(), pollHeaders)) {
                            if (cmd.callback) {
                                std::vector<std::byte> ldata;
                                ldata.reserve(result->body.size());
                                std::memcpy(ldata.data(), result->body.c_str(), result->body.size());
                                cmd.callback(RawMessage{ .id = 0, .context = std::string(data, data_length), .endpoint = std::make_unique<URI<STRICT>>(*cmd.uri), .data = std::move(ldata) });
                            }
                        } else {
                            std::cout << "SSE-GET request failed: " << result.error() << std::endl;
                            // return error message to client
                            // std::cout << "meta info: " <<  res.value().version << std::endl;
                        }
                        return true;
                    })) {
                    std::cerr << fmt::format("RestClient::startSubscription({}) get returned ", cmd.uri->str) << std::endl;
                } else {
                    std::cerr << fmt::format("RestClient::startSubscription({}) get failed ", cmd.uri->str) << std::endl;
                }
            }
        } else if (start_with_case_ignore(*cmd.uri->scheme(), "https")) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            auto it = _subscription2.find(*cmd.uri);
            if (it == _subscription2.end()) {
                //                auto& client = _subscription2.emplace(*cmd.uri, httplib::SSLClient(cmd.uri->hostName().value(), cmd.uri->port().value())).first->second;
                //                client.is_socket_open();
            }
#else
            throw std::runtime_error("https is not supported - enable CPPHTTPLIB_OPENSSL_SUPPORT");
#endif
        } else {
            throw std::invalid_argument(fmt::format("unsupported scheme '{}' for requested subscription '{}'", cmd.uri->scheme(), cmd.uri->str));
        }
    }

    void stopSubscription(const Command &cmd) {
        // stop subscription that matches URI
        std::scoped_lock lock(_subscriptionLock);
        if (start_with_case_ignore(*cmd.uri->scheme(), "http")) {
            auto it = _subscription1.find(*cmd.uri);
            if (it != _subscription1.end()) {
                it->second.stop();
                _subscription1.erase(it);
                return;
            }
        } else if (start_with_case_ignore(*cmd.uri->scheme(), "https")) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            auto it = _subscription2.find(*cmd.uri);
            if (it != _subscription2.end()) {
                it->second.stop();
                _subscription2.erase(it);
                return;
            }
#else
            throw std::runtime_error("https is not supported - enable CPPHTTPLIB_OPENSSL_SUPPORT");
#endif
        } else {
            throw std::invalid_argument(fmt::format("unsupported scheme '{}' for requested subscription '{}'", cmd.uri->scheme(), cmd.uri->str));
        }
    }

    void stopAllSubscriptions() noexcept {
        std::scoped_lock lock(_subscriptionLock);
        std::ranges::for_each(_subscription1, [](auto &pair) { pair.second.stop(); });
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        std::ranges::for_each(_subscription2, [](auto &pair) { pair.second.stop(); });
#endif
    }
};
inline bool                   RestClient::CHECK_CERTIFICATES = true;
inline const httplib::Headers RestClient::EVT_STREAM_HEADERS = { { ACCEPT_HEADER, MIME::EVENT_STREAM.typeName().data() } };

} // namespace opencmw::client

#endif // OPENCMW_CPP_RESTCLIENT_HPP
