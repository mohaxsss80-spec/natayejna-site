# Account sign-in setup

The site has optional account registration and sign-in. Result searches remain public; an account is not required to search.

- Passwords are hashed with Werkzeug's default scrypt password hash. The original password is never stored, shown in the owner dashboard, or included in account records returned to templates.
- The email-sharing checkbox is optional and unchecked by default. Users can opt in or revoke consent later from their account page. The owner dashboard lists only currently opted-in addresses.
- Email ownership is not verified by this feature. The dashboard labels addresses as user-entered, not verified.
- Account data is stored in SQLite. By default the database is data/accounts.sqlite3. Set AUTH_DATABASE_PATH to a private, persistent filesystem path before starting the app if the deployment's writable filesystem is temporary. Back up this file securely; it contains password hashes and account emails.
- The session cookie is Secure by default. Serve the app over HTTPS; for local HTTP development only, set SESSION_COOKIE_SECURE=false.
- Use a strong FLASK_SECRET_KEY and ADMIN_PASSWORD in the hosting provider's secret manager. Never commit them to Git.
