function decodeBase64url(input) {
  const pad = '='.repeat((4 - input.length % 4) % 4);
  const base64 = (input + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function encodeBase64url(buffer) {
  let str = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}


document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('register-passkey');
    const errorElem = document.getElementById('passkey-error');
    if (!button) {
        return;
    }

    button.addEventListener('click', async () => {
        try {
            const optionsResp = await fetch(button.dataset.registerOptionsUrl, {
                credentials: 'same-origin',
            });
            if (!optionsResp.ok) {
                throw new Error('Failed to fetch registration options.');
            }

            const options = await optionsResp.json();
            options.challenge = decodeBase64url(options.challenge);
            options.user.id = decodeBase64url(options.user.id);
            options.excludeCredentials = (options.excludeCredentials || []).map(c => ({
                ...c,
                id: decodeBase64url(c.id),
            }));

            const cred = await navigator.credentials.create({ publicKey: options });

            const payload = {
                id: cred.id,
                rawId: encodeBase64url(cred.rawId),
                type: cred.type,
                response: {
                    attestationObject: encodeBase64url(cred.response.attestationObject),
                    clientDataJSON: encodeBase64url(cred.response.clientDataJSON),
                },
                clientExtensionResults: cred.getClientExtensionResults(),
            };

            const verifyResp = await fetch(button.dataset.registerVerifyUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': button.dataset.csrfToken,
                },
                body: JSON.stringify(payload),
            });

            const data = await verifyResp.json();
            if (!verifyResp.ok || !data.ok) {
                throw new Error(data.error || 'Registration failed');
            }

            window.location.reload();
        } catch (error) {
            if (errorElem) {
                errorElem.textContent = error.message;
            }
        }
    });
});