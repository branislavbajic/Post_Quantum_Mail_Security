async function refreshOwnStatus() {

    const status = await messenger.runtime.sendMessage(
        {
            type : "get_status"
        }
    );

    const my_keys_box = document.getElementById("pqc-own-status");
    my_keys_box.className = "pqc-status " + (status.has_keys ? "ok" : "neutral");
    my_keys_box.textContent = status.has_keys
        ? "You have an ML-KEM and ML-DSA key pair."
        : "No keys generated yet. Use the toolbar icon to generate a pair.";

}

document.getElementById("pqc-delete-btn").addEventListener("click", async () => {

    const error_message = document.getElementById("pqc-delete-error");
    error_message.textContent = "";

    const master_password = document.getElementById("pqc-delete-password").value;

    const result = await messenger.runtime.sendMessage(
        {
            type : "delete_keys",
            master_password
        }
    )

    if (!result.success) {
        error_message.textContent = result.error;
        return;
    }

    document.getElementById("pqc-delete-password").value = "";
    await refreshOwnStatus();

})

document.addEventListener("DOMContentLoaded", async () => {
    refreshOwnStatus();
});