# PWVault Autofill extension

This unpacked Manifest V3 extension adds explicit, origin-matched autofill for
personal-vault login entries. It contacts the server directly and keeps the
login token and derived keys only in the popup's memory. Closing the popup
clears its session. Each password fill requires a user click; the extension
does not submit forms. PWVault account passkeys are managed in the web app and
act as a second login factor after the master password.

## Install for development

1. Open `chrome://extensions` (or the equivalent extensions page in a Chromium
   browser) and enable Developer mode.
2. Choose **Load unpacked** and select this `browser_extension` folder.
3. Start PWVault, open a normal HTTPS site with a saved matching login, and
   click the extension. For local development the server field defaults to
   `http://127.0.0.1:8012`.
4. Enter your PWVault email and master password. The browser asks for access to
   the server origin the first time. If 2FA is enabled, enter the code and
   unlock again.
5. Select a listed login to fill the visible form. Review the fields and submit
   the website yourself.

For a deployed server, enter its HTTPS origin (for example,
`https://vault.example.com`) in the server field. Grant only that origin. The
extension compares the page's exact scheme, hostname, and port to each saved
site; it does not use broad parent-domain matching. Site entries should contain
a URL such as `https://example.com`.

It does not autofill shared vaults or iframes. The app and extension each ship
a copy of `pwvault_server/static/crypto.js`; keep those copies in sync when
changing the web crypto format.
