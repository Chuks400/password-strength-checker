# PassWatch - Password Strength Checker

A modern password strength checker with both a desktop GUI and a web interface (Flask). Check your password security, entropy, and whether it has been leaked in known data breaches (via HaveIBeenPwned API).

## Features
- **Password strength analysis** (length, character diversity, entropy)
- **HaveIBeenPwned leak check** (no password sent directly)
- **Desktop GUI** (Tkinter)
- **Web app** (Flask + Bootstrap)
- **Easy deployment** (Render, PythonAnywhere, etc.)

---

## Usage

### 1. Desktop GUI
```bash
python password_checker.py gui
```

### 2. Command-Line
```bash
python password_checker.py
```

### 3. Web App (Flask)
```bash
cd flask_app
python app.py
```
Then visit [http://localhost:5000](http://localhost:5000) in your browser.

---

## Deploying to Render (Free Hosting)
1. Push your code to GitHub.
2. Create a new **Web Service** at [render.com](https://render.com/).
3. Use these settings:
    - **Root Directory:** `flask_app`
    - **Start Command:** `gunicorn app:app`
    - **Python Version:** 3.x
4. After deployment, you'll get a public link to share your password checker!

---

## Requirements
- Python 3.7+
- See `requirements.txt`

---

## Security
- Passwords are checked locally for strength and entropy.
- HaveIBeenPwned API is used in a privacy-preserving way (k-anonymity, only hash prefix sent).
- **Never reuse passwords from real accounts for testing.**

---

## License
MIT

---

## Credits
- [Bootstrap](https://getbootstrap.com/) for UI styling
- [HaveIBeenPwned](https://haveibeenpwned.com/API/v3) for breach data

---

## Screenshots
![Web UI Screenshot](docs/screenshot_web.png)
![Desktop GUI Screenshot](docs/screenshot_gui.png)

---

## Author
[Your Name](https://github.com/yourusername)
