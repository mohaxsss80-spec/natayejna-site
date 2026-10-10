# Account sign-in setup

The site has optional account registration and sign-in. Result searches remain public; an account is not required to search. New account registration requires an explicit acknowledgment that the email address will appear in the owner's protected dashboard. Users can revoke that consent from their account page; the address is then removed from the dashboard list.

- Passwords are hashed with Werkzeug's default scrypt password hash. The original password is never stored, shown in the owner dashboard, or included in account records returned to templates.
- Email/password registration requires consent to show the entered email address to the site owner. Users can revoke consent later from their account page. The owner dashboard lists only currently consented addresses; accounts that existed before consent was required are not automatically exposed.
- Google sign-in uses the OpenID Connect authorization-code flow and requests only `openid email`. The app checks Google's verified-email claim, stores the account email and Google subject, and does not store Google access or refresh tokens. Google's client secret stays in the hosting provider's environment variables.
- Create an OAuth 2.0 Web application client in Google Cloud Console. Add `https://mhazim929282.pythonanywhere.com/auth/google/callback` as an authorized redirect URI, then configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` in PythonAnywhere's environment/settings. Restart the web app after setting them. The redirect URI must match exactly.
- Email ownership is not verified by this feature. The dashboard labels addresses as user-entered, not verified.
- Account data is stored in SQLite. By default the database is data/accounts.sqlite3. Set AUTH_DATABASE_PATH to a private, persistent filesystem path before starting the app if the deployment's writable filesystem is temporary. Back up this file securely; it contains password hashes and account emails.
- The session cookie is Secure by default. Serve the app over HTTPS; for local HTTP development only, set SESSION_COOKIE_SECURE=false.
- Use a strong FLASK_SECRET_KEY and ADMIN_PASSWORD in the hosting provider's secret manager. Never commit them to Git.
