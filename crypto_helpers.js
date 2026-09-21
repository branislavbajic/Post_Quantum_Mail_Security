const PBKDF2_ITERATIONS = 600000;
const ARMOR_HEADER = "-----BEGIN PQC MESSAGE-----";
const ARMOR_FOOTER = "-----END PQC MESSAGE-----";

/*

    Podsetnik:

        - Kada se radi sa binarnim podacima koji predstavlja sliku (PNG/JPEG), kompresovanu datoteku, ili enkriptovane
          podatke (kao u našem slučaju std::vector<uint8_t>), nije bezbedno da se oni direkno kopiraju u JSON, telo
          mejla ili URL-ove (na primer, 0x00 se često tumači kao EOL, Ox22 kao ", pa to može napraviti haos) i onda
          je neophodno da se prebace u siguran Base64 format (skup od tačno 64 bezbedna ASCII karaktera).

        - U našem slučaju, metodi klasa iz main.cpp vraćaju Module.ByteVector (u suštini std::vector<uint8_t>), pa to
          moramo prevesti u Uint8Array koji JavaScript razume (.vecToUint8()).

          Zatim, kada te podatke čuvamo u JSON formatu, moraju se prebaciti u Base64 (.bytesToBase64()).

          Kada se obrće postupak (treba da radimo sa sačuvanim podacima), koristimo .base64ToBytes() i .uint8ToVector()

*/

function bytesToBase64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

function vecToUint8(vec) {
    const arr = new Uint8Array(vec.size());
    for (let i = 0; i < vec.size(); i++) arr[i] = vec.get(i);
    vec.delete();
    return arr;
}

function uint8ToVector(bytes) {
    const vec = new Module.ByteVector();
    for (let i = 0; i < bytes.length; i++) vec.push_back(bytes[i]);
    return vec;
}

function parsePublicKeyPem(pem_text) {
    const kem_match = pem_text.match(
        /-----BEGIN PQC PUBLIC KEY \(ML-KEM-768\)-----([\s\S]*?)-----END PQC PUBLIC KEY \(ML-KEM-768\)-----/
    );
    const dsa_match = pem_text.match(
        /-----BEGIN PQC PUBLIC KEY \(ML-DSA-65\)-----([\s\S]*?)-----END PQC PUBLIC KEY \(ML-DSA-65\)-----/
    );
    if (!kem_match || !dsa_match) return null;
    return {
        kem_public: kem_match[1].replace(/\s+/g, ""),
        dsa_public: dsa_match[1].replace(/\s+/g, ""),
    };
}


async function deriveMasterKey(master_password, salt_bytes) {

    /*
        Da bi koristio .deriveKey(), input mora da bude u specificnom CryptoKey formatu, pa prvo od master lozinke
        mora da se napravi takav objekat uz pomoć .importKey() funkcije (ulaz je raw data odnosno nije neki specifičan
        format i može se kasnije koristiti samo za ono u "keyUsages" listi, odnosno samo za deriveKey)
     */

    const password_key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(master_password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    /*
        "extractable: false" znači da će JavaScript engine obezbediti da se sadržaj može samo koristiti za zadate
        operacije (encrypt i decrypt), dok će bilo kakav pokušaj čitanja rezultovati greškom
    */
    return crypto.subtle.deriveKey(
        {
            name : "PBKDF2",
            salt : salt_bytes,
            iterations : PBKDF2_ITERATIONS,
            hash : "SHA-256"
        },
        password_key,
        {
            "name" : "AES-GCM",
            length : 256
        },
        false,
        ["encrypt", "decrypt"]
    );

}

async function aesEncrypt(key, plaintext_bytes) {

    // AES-u treba inicijalizacioni vektor (IV)
    const iv = randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt(
        { name : "AES-GCM",
            iv
        },
        key,
        plaintext_bytes
    );
    return {
        iv : bytesToBase64(iv),
        ct : bytesToBase64(new Uint8Array(ciphertext))
    };

}

async function aesDecrypt(key, ivB64, ctB64) {
    const iv = base64ToBytes(ivB64);
    const ct = base64ToBytes(ctB64);
    const plaintext = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        ct
    );

    return new Uint8Array(plaintext);
}

async function deriveSessionKey(shared_secret_bytes) {

    const hkdf_key = await crypto.subtle.importKey(
        "raw",
        shared_secret_bytes,
        "HKDF",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: new TextEncoder().encode("pqc-security-session-key-v1"),
        },
        hkdf_key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

}

function createArmor(envelope_object) {
    const json = JSON.stringify(envelope_object);
    const b64 = btoa(json);
    const wrapped = b64.match(/.{1,64}/g).join("\n");
    return `${ARMOR_HEADER}\n${wrapped}\n${ARMOR_FOOTER}`;
}