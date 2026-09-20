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

});

/*

    Thunderbird čuva kontakte u formatu:

        BEGIN:VCARD
        VERSION:4.0
        FN:John Doe
        EMAIL;PREF=1:john@example.com
        END:VCARD

*/

function parseVCard(vcard) {
    if (!vcard) return null;
    const lines = vcard.split(/\r\n|\n|\r/);
    let email = null;
    let name = null;
    for (const line of lines) {
        const emailMatch = line.match(/^EMAIL[^:]*:(.+)$/i);
        if (emailMatch && !email) email = emailMatch[1].trim();
        const fnMatch = line.match(/^FN:(.+)$/i);
        if (fnMatch) name = fnMatch[1].trim();
    }
    return email ? { email, name: name || email } : null;
}

async function populateContactSelect() {

    const select = document.getElementById("pqc-contact-select");

    select.innerHTML = '<option value="">(choose a contact)</option>';

    try {
        const address_books = await messenger.addressBooks.list();
        for (const book of address_books) {
            const contacts = await messenger.addressBooks.contacts.list(book.id);
            for (const contact of contacts) {
                const parsed = parseVCard(contact.vCard);
                if (!parsed) continue;
                const opt = document.createElement("option");
                opt.value = parsed.email;
                opt.textContent = `${parsed.name} <${parsed.email}>`;
                select.appendChild(opt);
            }
        }
    }
    catch (e) {
        console.warn("Could not list address book contacts:", e);
    }

}

async function refreshContactsList() {

    const display_list = document.getElementById("pqc-contacts-list");
    const my_contacts = await messenger.runtime.sendMessage(
        {
            type : "list_contacts"
        }
    );

    display_list.innerHTML = "";
    if (!my_contacts.length) {
        display_list.innerHTML = "<li><span class=\"email\">No stored public keys yet.</span></li>";
        return;
    }

    for (const c of my_contacts) {
        const li = document.createElement("li");
        const span = document.createElement("span");
        span.innerHTML = `${c.label}<br><span class="email">${c.email}</span>`;
        li.appendChild(span);
        display_list.appendChild(li);
    }

}

document.getElementById("pqc-import-btn").addEventListener("click", async () => {

    const error_message = document.getElementById("pqc-import-error");
    error_message.textContent = "";

    const select = document.getElementById("pqc-contact-select");
    const manual_email = document.getElementById("pqc-manual-email").value.trim();

    if (select.value && manual_email) {
        error_message.textContent = "You can't both choose a contact and manually enter email";
        return;
    }

    const email = manual_email || select.value;
    const label = select.selectedOptions[0] && select.selectedOptions[0].value === email
        ? select.selectedOptions[0].textContent
        : email;

    const file_input = document.getElementById("pqc-pem-file");
    if (!email) {
        error_message.textContent = "Choose a contact or type an email address.";
        return;
    }
    if (!file_input.files.length) {
        error_message.textContent = "Choose a .pem file to import.";
        return;
    }

    const pem_text = await file_input.files[0].text();

    const result = await messenger.runtime.sendMessage(
        {
            type : "import_contact_key",
            email,
            pem_text,
            label
        }
    );

    debugger;
    if (!result.success) {
        error_message.textContent = result.error;
        return;
    }

    document.getElementById("pqc-manual-email").value = "";
    file_input.value = "";

    await refreshContactsList();

})



document.addEventListener("DOMContentLoaded", async () => {
    refreshOwnStatus();
    populateContactSelect();
    refreshContactsList();
});