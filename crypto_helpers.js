const PBKDF2_ITERATIONS = 600000;

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

async function deriveMasterKey(master_password, salt_bytes) {

    const password_key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(master_password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

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