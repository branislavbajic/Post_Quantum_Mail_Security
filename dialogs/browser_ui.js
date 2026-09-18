const heading = document.getElementById("pqc-heading-text");
const badge = document.getElementById("pqc-badge");
const subtitle = document.getElementById("pqc-subtitle");
const generateSection = document.getElementById("pqc-generate-section");
const protectedSection = document.getElementById("pqc-protected-section");
const error_message = document.getElementById("pqc-error");


async function refreshDisplay() {

    const status = await messenger.runtime.sendMessage(
        {
            type: "get_status"
        }
    );

    if (status.has_keys) {
        heading.textContent = "Thunderbird is protected";
        badge.textContent = "\u{1F512}";
        badge.classList.remove("locked");
        badge.classList.add("unlocked");
        subtitle.style.display = "none";
        generateSection.style.display = "none";
        protectedSection.style.display = "block";
    }
    else {
        heading.textContent = "Thunderbird is not protected";
        badge.textContent = "\u{1F513}";
        badge.classList.add("locked");
        badge.classList.remove("unlocked");
        subtitle.style.display = "block";
        generateSection.style.display = "block";
        protectedSection.style.display = "none";
    }

}
document.getElementById("pqc-generate-btn").addEventListener("click", async () => {

    error_message.textContent = "";
    const master_password = document.getElementById("pqc-password").value;

    const btn = document.getElementById("pqc-generate-btn");
    btn.disabled = true;
    btn.textContent = "Generating\u2026";

    try {
        const result = await messenger.runtime.sendMessage(
            {
                type: "generate_keys",
                master_password
            }
        )

        if (!result.success) {
            error_message.textContent = result.error;
        } else {
            await refreshDisplay();
        }
    } catch (e) {
        error_message.textContent = "Unexpected error: " + e.message + " (see background page console)";
    } finally {
        btn.disabled = false;
        btn.textContent = "Generate Keys";
    }
});

document.getElementById("pqc-export-btn").addEventListener("click", async () => {

    const result = await messenger.runtime.sendMessage(
        {
            type : "export_public_keys"
        }
    );

    if (!result.success) {
        error_message.textContent = result.error;
    }

});

// Čim se učita stranica uradi refresh
document.addEventListener("DOMContentLoaded", async () => {
    await refreshDisplay();
});