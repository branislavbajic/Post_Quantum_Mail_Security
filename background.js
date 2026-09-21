// Algoritmi
const KEM_ALG = "ML-KEM-768";
const DSA_ALG = "ML-DSA-65";

const ENVELOPE_VERSION = 1;

// Master password
let master_key = null;

// For enable toggle persistance (tab_id --> boolean)
const compose_encrypt_state = new Map();

// ============== Provera da li je WASM učitan =========================================================================

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

// ================= Helper funkcije ===================================================================================

function isUnlocked() {
    return master_key !== null;
}

async function getMyKeys() {
    const { my_keys } = await messenger.storage.local.get("my_keys");

    return my_keys || null;
}

async function getContacts() {

    const { my_contacts } = await messenger.storage.local.get("my_contacts");
    return my_contacts || {};

}

// ComposeDetails recipient je "Name <email>" ili običan email
function extractRecipientEmail(entry) {
    if (typeof entry !== "string") return null;
    const match = entry.match(/<([^>]+)>/);
    return (match ? match[1] : entry).trim().toLowerCase();
}

async function buildEnvelope(recipient_email, plaintext) {

    if (!isUnlocked()) throw new Error("Locked. Unlock with your master password first.");

    const my_keys = await getMyKeys();
    const contacts = await getContacts();
    const contact = contacts[recipient_email.trim().toLowerCase()];

    await whenWasmReady();

    // Potpisivanje
    const dsa_private_key = await aesDecrypt(master_key, my_keys.dsa_encrypted_pk.iv, my_keys.dsa_encrypted_pk.ct);
    const dilithium = new Module.Dilithium(DSA_ALG, uint8ToVector(dsa_private_key));
    const signature = vecToUint8(dilithium.sign(uint8ToVector(new TextEncoder().encode(plaintext))));
    dilithium.delete();

    const inner_payload = JSON.stringify(
        {
            body : plaintext,
            sig : bytesToBase64(signature)
        }
    );

    // Enkapsulacija (razmena simetričnog ključa)
    const kyber = new Module.Kyber(KEM_ALG);
    const recipient_public_key = base64ToBytes(contact.kem_public);
    const encapsulated_result = kyber.encapsulate(uint8ToVector(recipient_public_key));
    const kem_ciphertext = vecToUint8(encapsulated_result.ciphertext);
    const shared_secret = vecToUint8(encapsulated_result.shared_secret);
    kyber.delete();

    const session_key = await deriveSessionKey(shared_secret);
    const {iv, ct} = await aesEncrypt(session_key, new TextEncoder().encode(inner_payload));

    return createArmor(
        {
            v: ENVELOPE_VERSION,
            alg: `${KEM_ALG}/${DSA_ALG}`,
            kem_ct: bytesToBase64(kem_ciphertext),
            iv,
            ct,
        }
    );

}

async function openEnvelope(ascii_armor, sender_mail) {

    const envelope = parseArmor(ascii_armor);
    if (!envelope) {
        return {
            protected : false
        }
    }

    if (!isUnlocked()) throw new Error("Locked. Unlock with your master password first.");

    const my_keys = await getMyKeys();

    await whenWasmReady();

    const kem_private_key = await aesDecrypt(master_key, my_keys.kem_encrypted_pk.iv, my_keys.kem_encrypted_pk.ct);
    const kyber = new Module.Kyber(KEM_ALG, uint8ToVector(kem_private_key));
    const shared_secret = vecToUint8(kyber.decapsulate(uint8ToVector(base64ToBytes(envelope.kem_ct))));
    kyber.delete();

    const session_key = await deriveSessionKey(shared_secret);
    const inner_payload = await aesDecrypt(session_key, envelope.iv, envelope.ct);
    const inner = JSON.parse(new TextDecoder().decode(inner_payload));

    const contacts = await getContacts();
    const contact = contacts[(sender_mail || "").trim().toLowerCase()];

    let verified = null;
    if (contact) {
        const dilithium = new Module.Dilithium(DSA_ALG);
        verified = dilithium.verify(
            uint8ToVector(new TextEncoder().encode(inner.body)),
            uint8ToVector(base64ToBytes(inner.sig)),
            uint8ToVector(base64ToBytes(contact.dsa_public))
        )
        dilithium.delete();
    }

    return {
        protected : true,
        body : inner.body,
        verified,
        sender_known : !!contact
    };
}

/*

    - MIME struktura mejla izgleda otprilike ovako:

        multipart/mixed (whole message)
            ├── multipart/alternative
            │   ├── text/plain   <- what we actually want
            │   └── text/html
            └── application/pdf  (an attachment, say)

    - Međutim, broj nivoa mora da varira pa se ovde koristi rekurzivna funkcija da nađe pod-objekat koji nam je potreban

*/

function findPlainTextPart(part) {
    if (part.contentType && part.contentType.startsWith("text/plain") && part.body) {
        return part.body;
    }
    for (const child of part.parts || []) {
        const found = findPlainTextPart(child);
        if (found) return found;
    }
    return null;
}

// ================== Funkcije za svaki tip zahteva ====================================================================

async function getStatus() {

    const my_keys = await getMyKeys();

    return {
        has_keys : !!my_keys,
        is_unlocked : isUnlocked()
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

    master_key = key;

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

    master_key = key;
    return {
        success : true
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

async function importContactKey(email, pem_text, label) {

    const parsed = parsePublicKeyPem(pem_text);

    if (!parsed) {
        return {
            success : false,
            error : "That file doesn't look like a PQC Security public key export."
        }
    }

    const email_key = email.trim().toLowerCase();
    const contacts = await getContacts();

    contacts[email_key] = {
        ...parsed,
        label: label || email,
        added_at: Date.now()
    };

    await messenger.storage.local.set(
        {
            my_contacts : contacts
        }
    );


    return {
        success : true
    };
}

async function listContacts() {
    const contacts = await getContacts();

    return Object.entries(contacts).map(([email, c]) => (
        {
            email,
            label: c.label
        }
    ));

}

async function removeContact(email) {

    const contacts = await getContacts();

    delete contacts[email.trim().toLowerCase()];

    await messenger.storage.local.set(
        {
            my_contacts : contacts
        }
    );

    return {
        success : true
    }

}

async function canEncrypt(email) {

    const contacts = await getContacts();

    return !!contacts[email.trim().toLowerCase()];

}

async function decryptMessage(message_id) {
    const full = await messenger.messages.getFull(message_id);
    const header_info = await messenger.messages.get(message_id);
    const plain_part = findPlainTextPart(full);

    if (!plain_part) {
        return {
            protected : false
        }
    }

    const from_email = (header_info.author.match(/<([^>]+)>/) || [, header_info.author])[1];

    try {
        return await openEnvelope(plain_part, from_email);
    }
    catch (e) {
        return {
            protected : true,
            error : e.message
        }
    }
}

// ==================== MAIN LOGIC =====================================================================================
browser.runtime.onMessage.addListener(
    (request, sender) => {

        switch (request.type) {

            case "get_status":
                return getStatus();
            case "generate_keys":
                return generateKeys(request.master_password);
            case "export_public_keys":
                return exportPublicKeys()
            case "unlock":
                return unlock(request.master_password);
            case "delete_keys":
                return deleteKeys(request.master_password);
            case "import_contact_key":
                return importContactKey(request.email, request.pem_text, request.label);
            case "list_contacts":
                return listContacts();
            case "remove_contact":
                return removeContact(request.email);
            case "can_encrypt":
                return canEncrypt(request.email);
            case "set_compose_encrypt_state":
                compose_encrypt_state.set(request.tab_id, request.enabled);
                messenger.composeAction.setBadgeText(
                    {
                        tabId : request.tab_id,
                        text: request.enabled ? "\u{1F512}" : "",
                    }
                );
                return Promise.resolve(
                    {
                        success : true
                    }
                );
            case "get_compose_encrypt_state":
                return Promise.resolve(!!compose_encrypt_state.get(request.tab_id));
            case "decrypt_message":
                return decryptMessage(request.message_id);
            default:
                return undefined;
        }

    }
);

// presretanje slanja poruke i enkriptovanje sadržaja ako je izabrana ta opcija
messenger.compose.onBeforeSend.addListener(async (tab, details) => {

    const pqc_enabled = compose_encrypt_state.get(tab.id);
    if (!pqc_enabled) return {};

    const recipients = [].concat(details.to || []);
    const recipient_email = extractRecipientEmail(recipients[0]);
    if (!recipient_email) {
        return {
            cancel : true
        };
    }

    const plaintext = details.plainTextBody || details.body || "";

    try {
        const ascii_armor = await buildEnvelope(recipient_email, plaintext);

        return {
            cancel : false,
            details: {
                isPlainText : true,
                plainTextBody : ascii_armor,
                body : ascii_armor
            }
        };
    }
    catch (e) {
        console.error("PQC Security: failed to protect outgoing message:", e);
        return {
            cancel: true
        };
    }

});

/*messenger.messageDisplay.onMessagesDisplayed.addListener((tab, messageList) => {
    const messages = (messageList && messageList.messages) || [];

    //console.log(messages[0].folder);
    const folderType = messages[0] && messages[0].folder && messages[0].folder.type;
    if (folderType === "sent") {
        messenger.messageDisplayAction.disable(tab.id);
    } else {
        messenger.messageDisplayAction.enable(tab.id);
    }
});*/

