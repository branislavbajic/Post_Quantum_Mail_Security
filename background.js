// Algoritmi

const KEM_ALG = "ML-KEM-768";
const DSA_ALG = "ML-DSA-65";

// Master password
let master_key = null;

// Provera da li je WASM učitan

var is_wasm_ready = false;
var Module = {
    onRuntimeInitialized: function () {
        is_wasm_ready = true;
        console.log("PQC Security: WASM runtime ready");
    }
}

function whenWasmReady() {
    if (is_wasm_ready) return Promise.resolve();
    return new Promise((resolve) => {
        const check = () => (is_wasm_ready ? resolve() : setTimeout(check, 20));
        check();
    });
}

// Helper funkcije

async function getMyKeys() {
    const { my_keys } = await messenger.storage.local.get("my_keys");

    return my_keys || null;
}

async function unlock(master_password) {

    const my_keys = await getMyKeys();

    if (!my_keys) {
        return {
            success : false,
            error : "No keys have been generated yet."
        }
    }

    const salt = base64ToBytes(my_keys.salt);
    const key = await deriveMasterKey(master_password, salt);

    try {
        await aesDecrypt(key, my_keys.kem_encrypted_pk.iv, my_keys.kem_encrypted_pk.ct);
    }
    catch (e) {
        return {
            success : false,
            error : "Incorrect master password."
        };
    }

    master_password = key;
    return {
        success : true
    }

}

// Funkcije za svaki tip zahteva

async function getStatus() {

    const my_keys = await getMyKeys();

    return {
        has_keys : !!my_keys,
        is_unlocked : master_key !== null
    }

}

async function generateKeys(master_password) {

    if (!master_password || master_password.length < 5) {
        return {
            success : false,
            error : "Master password must be at least 5 characters long."
        };
    }

    const my_keys = await getMyKeys();

    if (my_keys) {
        return {
            success : false,
            error : "Keys already exist. Delete them first if you want to regenerate."
        };
    }

    await whenWasmReady();

    const kyber = new Module.Kyber(KEM_ALG);
    const kem_public = kyber.generateKeyPair();
    const kem_private = kyber.exportSecretKey();
    kyber.delete();

    const dilithium = new Module.Dilithium(DSA_ALG);
    const dsa_public = dilithium.generateKeyPair();
    const dsa_private = dilithium.exportSecretKey();
    dilithium.delete();

    const salt = randomBytes(16);
    const key = await deriveMasterKey(master_password, salt);

    const kem_encrypted_pk = await aesEncrypt(key, vecToUint8(kem_private));
    const dsa_encrypted_pk = await aesEncrypt(key, vecToUint8(dsa_private));

    const record = {
        salt : bytesToBase64(salt),
        kem_public : bytesToBase64(vecToUint8(kem_public)),
        kem_encrypted_pk,
        dsa_public : bytesToBase64(vecToUint8(dsa_public)),
        dsa_encrypted_pk
    };

    await messenger.storage.local.set(
        {
            "my_keys" : record
        }
    );

    master_password = key;

    return {
        success : true
    };

}

async function exportPublicKeys() {

    const my_keys = await getMyKeys();

    if (!my_keys) {
        return {
            success : false,
            error : "Keys are not yet generated!"
        }
    }

    const lines = [
        "-----BEGIN PQC PUBLIC KEY (ML-KEM-768)-----",
        my_keys.kem_public.match(/.{1,64}/g).join("\n"),
        "-----END PQC PUBLIC KEY (ML-KEM-768)-----",
        "-----BEGIN PQC PUBLIC KEY (ML-DSA-65)-----",
        my_keys.dsa_public.match(/.{1,64}/g).join("\n"),
        "-----END PQC PUBLIC KEY (ML-DSA-65)-----",
    ];
    const pem = lines.join("\n");

    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    try {
        await messenger.downloads.download({ url, filename: "pqc-public-keys.pem", saveAs: true });
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    } finally {
        setTimeout(() => URL.revokeObjectURL(url), 30000);
    }
}


async function deleteKeys(master_password) {

    const result = await unlock(master_password);
    if (!result.success) {
        return result;
    }

    await messenger.storage.local.remove("my_keys");
    master_key = null;

    return {
        success : true
    }

}

// main logic

browser.runtime.onMessage.addListener(
    (request, sender) => {

        switch (request.type) {

            case "get_status":
                return getStatus();
            case "generate_keys":
                return generateKeys(request.master_password);
            case "export_public_keys":
                return exportPublicKeys()
            case "delete_keys":
                return deleteKeys(request.master_password);
            default:
                return undefined;
        }

    }
)