const message_status = document.getElementById("pqc-msg-status");
const unlock_section = document.getElementById("pqc-unlock-section");
const body_section = document.getElementById("pqc-body-section");
const msg_body = document.getElementById("pqc-msg-body");

let current_message_id = null;

function setStatus(kind, text) {
    message_status.className = "pqc-status " + kind;
    message_status.textContent = text;
}

async function loadAndDecrypt() {

    const message_list = await messenger.messageDisplay.getDisplayedMessages();
    const displayed = (message_list && message_list.messages) || [];
    if (!displayed.length) {
        setStatus("neutral", "No message is currently displayed.");
        return;
    }

    current_message_id = displayed[0].id;

    const result = await messenger.runtime.sendMessage(
        {
            type : "decrypt_message",
            message_id : current_message_id
        }
    );

    if (!result.protected) {
        setStatus("neutral", "This message is not protected.");
        unlock_section.style.display = "none";
        body_section.style.display = "none";
        return;
    }

    if (result.error && result.error.startsWith("Locked")) {
        setStatus("warn", "This message is protected. Enter your master password to read it.");
        unlock_section.style.display = "block";
        body_section.style.display = "none";
        return;
    }

    if (result.error) {
        setStatus("warn", "This message looked protected but could not be decrypted: " + result.error);
        unlock_section.style.display = "none";
        body_section.style.display = "none";
        return;
    }

    unlock_section.style.display = "none";
    body_section.style.display = "block";
    msg_body.textContent = result.body;

    if (result.sender_known === false) {
        setStatus("warn", "Decrypted, but the sender's signing key is unknown - signature not verified.");
    } else if (result.verified) {
        setStatus("ok", "Decrypted. Signature verified.");
    } else {
        setStatus("warn", "Decrypted, but the signature did NOT verify. Treat this message with caution.");
    }

}

document.getElementById("pqc-unlock-btn").addEventListener("click", async () => {

    const error_message = document.getElementById("pqc-msg-error");
    error_message.textContent = "";

    const master_password = document.getElementById("pqc-msg-password").value;
    const result = await messenger.runtime.sendMessage(
        {
            type : "unlock",
            master_password
        }
    );
    if (!result.success) {
        error_message.textContent = result.error;
        return;
    }

    document.getElementById("pqc-msg-password").value = "";

    await loadAndDecrypt();
});

document.addEventListener("DOMContentLoaded", async () => {
    await loadAndDecrypt();
});