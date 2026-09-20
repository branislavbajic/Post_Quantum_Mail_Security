#include <emscripten/bind.h>
#include <liboqs-cpp/oqs_cpp.hpp>

using namespace emscripten;

/*

    Podsetnik:

        - Klase oqs::KeyEncapsulation i oqs::Signature, interno rade sa oqs::bytes tipom koji predstavlja raw binary data,
          a u suštini je samo alijas za std::vector<uint_8>, pa je preporučeno da se isti prilikom korišćenja konvertuje u
          taj tip, jer se on kasnije lako pretvara u Uint8Array koji koristi JavaScript.

        - Registrovavenjm std::vector<uint8_t> u EMSCRIPTEN_BINDINGS, uz proizvoljno ime tipa, kreiramo wrapper klasu zadatog
          naziva sa .size(), .get(i), .push_back(x) metodama, pomoću kojih JavaScript interaguje sa podacima ovog tipa.

          Embind automatski razrešava samo primitive (numbers, bool, std::string), dok za klase, kontejnere i slično je
          potrebna ovakva registracija da bih JavaScript kod uopšte mogao da im pristupa (uvek preko Modul.zadato_ime).

*/

class Kyber {

    public:
        explicit Kyber(const std::string& alg_name) : kyber(alg_name) {}

        Kyber(const std::string& alg_name, const std::vector<uint8_t>& secret_key)
            : kyber(alg_name, oqs::bytes(secret_key.begin(), secret_key.end())) {}

        std::vector<uint8_t> generateKeyPair() {
            auto public_key = kyber.generate_keypair();
            return std::vector<uint8_t>(public_key.begin(), public_key.end());
        }

        std::vector<uint8_t> exportSecretKey() {
            auto private_key = kyber.export_secret_key();
            return std::vector<uint8_t>(private_key.begin(), private_key.end());
        }

    private:
        oqs::KeyEncapsulation kyber; // objekat klase iz 'oqs' namespace-a za ML-KEM
};

class Dilithium {

    public:
        explicit Dilithium(const std::string& alg_name) : dilithium(alg_name) {}

        Dilithium(const std::string& alg_name, const std::vector<uint8_t>& secret_key)
            : dilithium(alg_name, oqs::bytes(secret_key.begin(), secret_key.end())) {}

        std::vector<uint8_t> generateKeyPair() {
            auto public_key = dilithium.generate_keypair();
            return std::vector<uint8_t>(public_key.begin(), public_key.end());
        }

        std::vector<uint8_t> exportSecretKey() {
            auto private_key = dilithium.export_secret_key();
            return std::vector<uint8_t>(private_key.begin(), private_key.end());
        }

    private:
        oqs::Signature dilithium; // objekat klase iz 'oqs' namespace-a za ML-DSA

};

EMSCRIPTEN_BINDINGS(oqs_module) {
    register_vector<uint8_t>("ByteVector");

    class_<Kyber>("Kyber")
        .constructor<std::string>()
        .constructor<std::string, std::vector<uint8_t>>()
        .function("generateKeyPair", &Kyber::generateKeyPair)
        .function("exportSecretKey", &Kyber::exportSecretKey);

    class_<Dilithium>("Dilithium")
        .constructor<std::string>()
        .constructor<std::string, std::vector<uint8_t>>()
        .function("generateKeyPair", &Dilithium::generateKeyPair)
        .function("exportSecretKey", &Dilithium::exportSecretKey);

}