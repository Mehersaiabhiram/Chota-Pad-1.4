Chota Pad Private & Secure File Manager

A sleek and modern private file manager built with Flask + Vanilla JavaScript. Users can create a secure vault using only a secret code, upload files, manage documents, edit code files, and access everything from a beautiful glassmorphism UI.

Inspired by minimal privacy-first platforms. No email. No signup. Just your code and your files.

. Features . Code-based secure login system . No email or username required . Upload, download, edit, and delete files . JWT authentication with session expiry . Beautiful responsive UI with glassmorphism effects . Supports PDFs, images, code files, markdown, and more. Live code editor inside browser . Fully responsive modern design . Password hashing for secure storage . Animated landing page with smooth transitions . Tech Stack Frontend HTML5 CSS3 Vanilla JavaScript Boxicons Google Fonts Backend Python Flask Flask-CORS JWT Authentication Werkzeug Security Project Structure project/ │ ├── app.py ├── codes.json ├── index.html ├── uploads/ │ └── user-files/ │ └── static/

Authentication Flow User enters a unique secret code First time → creates private vault Returning user → verifies hashed code JWT token generated for secure session Session expires automatically after 24 hours File Operations

Users can:

Upload files Download files Edit code files Save changes Delete files Organize private storage

All files are isolated per user vault.

UI Highlights Glassmorphism design Animated hero section Responsive sidebar dashboard Toast notifications Drag & drop uploads Built-in code editor Smooth modal transitions Security Features Password hashing using Werkzeug JWT token authentication Protected routes Isolated upload folders Filename sanitization Session expiration Preview Landing Page Modern animated hero section Privacy-focused messaging Dashboard Secure file manager Upload zones File categories Inline code editing Future Improvements Cloud deployment File encryption Folder nesting Shareable secure links Dark/Light theme toggle Database integration Multi-device sync Author

Developed by Mehersaiabhiram Patnala
