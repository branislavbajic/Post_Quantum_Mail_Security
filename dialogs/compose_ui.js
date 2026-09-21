const status = document.getElementById("pqc-compose-status");
const toggle = document.getElementById("pqc-encrypt-toggle");

function setStatus(kind, text) {
    status.className = "pqc-status " + kind;
    status.textContent = text;
}

function getRecipientEmail(entry) {
    if (typeof entry !== "string") return null; // contact/list reference - not handled here
    const match = entry.match(/<([^>]+)>/);
    return (match ? match[1] : entry).trim().toLowerCase();
}

function enableToggle(email, tab_id) {

    setStatus("ok", `Ready to protect this message for ${email}.`);
    toggle.disabled = false;

    messenger.runtime.sendMessage(
        {
            type : "get_compose_encrypt_state",
            tab_id
        }
    ).then(
        (currently_enabled) => {
            toggle.checked = currently_enabled;
        }
    );

    toggle.addEventListener("change", () => {
        messenger.runtime.sendMessage(
            {
                type : "set_compose_encrypt_state",
                tab_id,
                enabled : toggle.checked
            }
        );
    });
}

(async () => {

    const [tab] = await messenger.tabs.query(
        {
            active: true,
            currentWindow: true
        }
    );
    const details = await messenger.compose.getComposeDetails(tab.id);

    const to = details.to || [];
    const cc = details.cc || [];
    const bcc = details.bcc || [];

    if (to.length !== 1 || cc.length > 0 || bcc.length > 0) {
        setStatus("warn", "Only a single \"To\" recipient is supported for protected messages.");
        toggle.disabled = true;
        return;
    }

    const email = getRecipientEmail(to[0]);
    if (!email) {
        setStatus("warn", "Couldn't read a plain email address for this recipient.");
        return;
    }

    const status = await messenger.runtime.sendMessage(
        {
            type: "get_status"
        }
    );
    if (!status.has_keys) {
        setStatus("warn", "Generate your own keys first (toolbar icon) to send protected mail.");
        return;
    }

    const can_encrypt = await messenger.runtime.sendMessage(
        {
            type: "can_encrypt",
            email
        }
    );
    if (!can_encrypt) {
        setStatus("warn", `No stored public key for ${email}. Import one from Options first.`);
        return;
    }

    if (!status.is_unlocked) {
        setStatus("warn", `Unlock your keys to protect this message for ${email}.`);
        document.getElementById("pqc-compose-unlock").style.display = "block";

        document.getElementById("pqc-compose-unlock-btn").addEventListener("click", async () => {
            const error_message = document.getElementById("pqc-compose-error");
            error_message.textContent = "";

            const master_password = document.getElementById("pqc-compose-password").value;
            const result = await messenger.runtime.sendMessage(
                {
                    type: "unlock",
                    master_password
                }
            );

            if (!result.success) {
                error_message.textContent = result.error;
                return;
            }

            document.getElementById("pqc-compose-password").value = "";
            document.getElementById("pqc-compose-unlock").style.display = "none";
            enableToggle(email, tab.id);
        });
        return;
    }

    enableToggle(email, tab.id);
})();