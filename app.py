from flask import Flask, render_template, request
import unicodedata
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

def load_blacklist(path="blacklist.txt"):
    bad_password = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                password = line.strip().lower()
                if password:
                    bad_password.add(password)
    except FileNotFoundError:
        logging.warning(f"Blacklist file not found at {path}.")
    return bad_password

BLACKLIST = load_blacklist()

LEETSPEAK = str.maketrans(
    {
        "@": "a", "4": "a",
        "3": "e",
        "1": "i", "!": "i",
        "0": "o",
        "5": "s", "$": "s",
        "7": "t",
        "+": "t",
        "8": "b",
        "6": "g",
        "9": "g",
    }
)

def normalize(password: str) -> str:
    nfd = unicodedata.normalize("NFD", password)
    ascii_approx = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    return ascii_approx.lower().translate(LEETSPEAK)

def apply_pattern_penalties(password: str):
    count = 0
    warnings = []

    # 1) Repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            count += 1
            warnings.append("Avoid using repeated characters (e.g., 'aaa' / '111').")
            break

    # 2) Digits at the end
    if len(password) >= 6:
        count_end_digits = 0
        for character in reversed(password):
            if character.isdigit():
                count_end_digits += 1
            else:
                break
        if count_end_digits >= 2:
            count += 1
            warnings.append("Avoid ending with multiple digits (common predictable pattern).")

    # 3) Common sequences
    lower = password.lower()
    sequences = ["0123", "1234", "2345", "3456", "4567", "5678", "6789",
                 "abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij",
                 "qwerty", "asdf", "zxcv"]
    for seq in sequences:
        if seq in lower:
            count += 1
            warnings.append(f"Avoid using a common sequence ('{seq}').")
            break

    return count, warnings

# Evaluate password
def evaluate_password(password: str):
    """
    - +1 if length >= 12
    - +1 if has uppercase
    - +1 if has lowercase
    - +1 if has digit
    - +1 if has symbol
    Total score: 0 to 7
    """

    if not password:
        return 0, "Weak", ["Password cannot be empty."]

    if len(password) < 6:
        return 0, "Weak", ["Password is too short — use at least 6 characters."]
        
    score = 0
    feedback = []

    if password.lower() in BLACKLIST:
        feedback.append("This password is commonly used. Choose a different one.")
        return 0, "Weak", feedback

    if len(password) >= 20:
        score += 3  
    elif len(password) >= 16:
        score += 2
    elif len(password) >= 12:
        score += 1
    else:
        feedback.append("Use 12+ characters — longer is stronger.")

    if any(character.isupper() for character in password):
        score += 1
    else:
        feedback.append("Add an uppercase letter.")

    if any(character.islower() for character in password):
        score += 1
    else:
        feedback.append("Add a lowercase letter.")

    if any(character.isdigit() for character in password):
        score += 1
    else:
        feedback.append("Add a number.")

    symbols = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~"
    if any(character in symbols for character in password):
        score += 1
    else:
        feedback.append("Add a symbol (like ! or #).")

    count, pattern_warnings = apply_pattern_penalties(password)

    # Subtract pattern penalties
    score = max(0, score - count)

    feedback.extend(pattern_warnings)

    # Compute category
    if score <= 3:
        category = "Weak"
    elif score <= 5:
        category = "Okay"
        if len(password) < 16:
            feedback.append("Using 16+ characters would make this stronger.")
        elif len(password) < 20:
            feedback.append("You can try using a password with 20+ characters to reach strong.")
    else:
        category = "Strong"

    return score, category, feedback

@app.route("/", methods=["GET", "POST"])
def index():
    score = None
    category = None
    feedback = []

    if request.method == "POST":
        password = request.form.get("password", "")
        score, category, feedback = evaluate_password(password)

    return render_template("index.html", score=score, category=category, feedback=feedback)

if __name__ == "__main__":
    app.run(debug=False)