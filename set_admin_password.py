from getpass import getpass
from pathlib import Path


PASSWORD_FILE = Path(__file__).resolve().parent / "data" / "admin_password.txt"


def main():
    password = getpass("كلمة سر لوحة التحكم: ").strip()
    confirmation = getpass("أعد كتابة كلمة السر: ").strip()

    if not password:
        raise SystemExit("لم يتم حفظ كلمة سر فارغة.")
    if password != confirmation:
        raise SystemExit("كلمتا السر غير متطابقتين.")

    PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
    PASSWORD_FILE.write_text(password, encoding="utf-8")
    try:
        PASSWORD_FILE.chmod(0o600)
    except OSError:
        pass

    print("تم حفظ كلمة السر بأمان.")


if __name__ == "__main__":
    main()