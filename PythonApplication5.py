import tkinter as tk
from tkinter import messagebox, filedialog
import os
import platform
import random
import string
import smtplib
import hashlib
import webbrowser
from email.message import EmailMessage
from tkinter import ttk
from datetime import datetime
from PIL import Image, ImageTk
import re
import threading
import requests
import time
import base64
from dotenv import load_dotenv

# Load environment variables
loaded = load_dotenv()
print(f".env loaded: {loaded}")
print(f".env exists: {os.path.exists('.env')}")
print(f"APP_PASSWORD: {os.getenv('APP_PASSWORD')}")
raw_password = os.getenv('APP_PASSWORD')
 
if raw_password is None:  
    raise ValueError("APP_PASSWORD is not set in the environment variables.")  
hashed_password = hashlib.sha256(raw_password.encode()).hexdigest()  

# Constants
REDIRECT_IP = "127.0.0.1"
LOG_FILE = "log.txt"
VT_API_KEY = "405850f124df365c7773987ef31d9d89781de3651c97675946e082c26c1b972a"
VT_HEADERS = {"x-apikey": VT_API_KEY}


# --- Utility Functions ---

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def validate_password(pw):
    return hash_password(pw) == hashed_password


def log_action(action):
    with open(LOG_FILE, "a") as log:
        log.write(f"[{datetime.now()}] {action}\n")

def generate_random_password(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def is_valid_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email)

def send_email(subject, body, to_email, attach_log=False):
    try:
        SENDER_EMAIL = os.getenv("SENDER_EMAIL")
        SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

        if not to_email or not is_valid_email(to_email):
            messagebox.showerror("Invalid Email", "Please enter a valid recipient email.")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S %p")
        full_body = f"{body}\n\nTimestamp: {timestamp}"

        msg = EmailMessage()
        msg.set_content(full_body)
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = to_email

        if attach_log and os.path.exists(LOG_FILE):
            with open(LOG_FILE, "rb") as f:
                log_data = f.read()
            msg.add_attachment(log_data, maintype="text", subtype="plain", filename="log.txt")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)

        log_action(f"Email sent to {to_email} with subject: {subject}")
        messagebox.showinfo("Email", "Email sent successfully!")

    except Exception as e:
        messagebox.showerror("Failed to send Email", str(e))

def get_hosts_path():
    os_name = platform.system()
    if os_name == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    elif os_name in ["Linux", "Darwin"]:
        return "/etc/hosts"
    else:
        raise Exception("Unsupported OS: " + os_name)

# --- VirusTotal Integration ---

def vt_id_from_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def vt_scan_url(url):
    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=VT_HEADERS, data={"url": url})
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        for _ in range(10):
            time.sleep(4)
            r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=VT_HEADERS)
            r.raise_for_status()
            result = r.json()["data"]
            if result["attributes"]["status"] == "completed":
                return result["attributes"]["stats"]
        return None
    except Exception as e:
        return {"error": str(e)}

def scan_and_display():
    url = website_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a website URL.")
        return
    threading.Thread(target=show_vt_result, args=(url,), daemon=True).start()

def show_vt_result(url):
    stats = vt_scan_url(url)
    if not stats:
        messagebox.showerror("VirusTotal", "No result returned from VirusTotal.")
        return
    elif "error" in stats:
        messagebox.showerror("VirusTotal Error", stats["error"])
        return

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    verdict = f"VirusTotal verdict for {url}\n"
    for key, val in stats.items():
        verdict += f"{key.capitalize():<12}: {val}\n"

    if malicious > 0 or suspicious > 0:
        verdict += "\n⚠️ Website flagged as potentially harmful.\nAutomatically blocking it..."
        log_action(f"Auto-blocked {url} based on VirusTotal scan")
        block_websites([url], "password")  # Auto-block with preset password
    else:
        verdict += "\n✅ Website appears clean."

    messagebox.showinfo("VirusTotal Result", verdict)

# --- Blocking Logic ---

def validate_password(pw):
    return hash_password(pw) == hashed_password

def block_websites(urls, pw_input):
    if not validate_password(pw_input):
        messagebox.showerror("Error", "Invalid Password")
        return

    try:
        hosts_path = get_hosts_path()
        with open(hosts_path, "a") as file:
            for url in urls:
                entry = f"{REDIRECT_IP} {url.strip()}\n"
                file.write(entry)
                log_action(f"Blocked: {url.strip()}")

        messagebox.showinfo("Success", "Websites Blocked Successfully.")
        refresh_blocked_list()

        subject = "Website Block Alert"
        body = f"The following websites have been BLOCKED:\n\n" + "\n".join(urls)
        send_email(subject, body, email_entry.get(), attach_log=True)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def unblock_websites(urls, pw_input):
    if not validate_password(pw_input):
        messagebox.showerror("Error", "Invalid Password")
        return

    try:
        hosts_path = get_hosts_path()
        with open(hosts_path, "r") as file:
            lines = file.readlines()

        new_lines = [line for line in lines if not any(url in line and REDIRECT_IP in line for url in urls)]

        with open(hosts_path, "w") as file:
            file.writelines(new_lines)

        for url in urls:
            log_action(f"Unblocked: {url.strip()}")

        messagebox.showinfo("Success", "Websites Unblocked Successfully.")
        refresh_blocked_list()

        subject = "Website Unblock Alert"
        body = f"The following websites have been UNBLOCKED:\n\n" + "\n".join(urls)
        send_email(subject, body, email_entry.get(), attach_log=True)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def get_blocked_sites():
    try:
        with open(get_hosts_path(), "r") as file:
            return [line.strip() for line in file.readlines() if line.startswith(REDIRECT_IP)]
    except:
        return []

def refresh_blocked_list():
    listbox.delete(0, tk.END)
    for site in get_blocked_sites():
        listbox.insert(tk.END, site)

# --- GUI Callbacks ---

def browse_file_block():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        block_websites(urls, password_entry.get())

def browse_file_unblock():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        unblock_websites(urls, password_entry.get())

def submit_single_url_block():
    block_websites([website_entry.get()], password_entry.get())

def submit_single_url_unblock():
    unblock_websites([website_entry.get()], password_entry.get())

def open_website():
    url = website_entry.get()
    if url and not url.startswith("http"):
        url = "http://" + url
    if url:
        webbrowser.open(url)
    else:
        messagebox.showwarning("Input Error", "Please enter a website URL.")

def generate_and_insert_password():
    pw = generate_random_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, pw)
    app.clipboard_clear()
    app.clipboard_append(pw)
    messagebox.showinfo("Password", f"Copied to clipboard:\n{pw}")

def create_info_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Project Information</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f7f7f7; padding: 30px; color: #333; }
            h1, h2 { color: #2c3e50; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
            th { background-color: #e8e8e8; }
            .logo-container { text-align: center; margin-bottom: 20px; }
            .logo-container img { max-width: 200px; height: auto; }
        </style>
    </head>
    <body>
        <div class="logo-container">
            <img src="E:\logo.png" alt="Company Logo">
        </div>

        <h1>Project Information</h1>
        <p>This project was developed by <strong>Barathan R</strong>, <strong>Kumaresh Karthic KR</strong>, and <strong>Vadivel Kumaran N</strong> during the Cyber Security Internship.
        This project is designed to secure organizations in the real world from cyber frauds performed by hackers.</p>
        
        <h2>Project Details</h2>
        <table>
            <tr><th>Name</th><td>Blocking Malicious Websites</td></tr>
            <tr><th>Description</th><td>Firewall application to block malicious domains</td></tr>
            <tr><th>Start Date</th><td>08-JUNE-2025</td></tr>
            <tr><th>End Date</th><td>12-JUNE-2025</td></tr>
            <tr><th>Status</th><td>Completed</td></tr>
        </table>

        <h2>Developer Info</h2>
        <table>
            <tr><th>Name</th><th>ID</th><th>Email</th></tr>
            <tr><td>Barathan R</td><td>ST#IS7273</td><td>barathan713@gmail.com</td></tr>
            <tr><td>Kumaresh Karthic KR</td><td>ST#IS7271</td><td>karthickumares@gmail.com</td></tr>
            <tr><td>Vadivel Kumaran N</td><td>ST#IS7274</td><td>Vikasvarun2805@gmail.com</td></tr>
        </table>

        <h2>Company Info</h2>
        <table>
            <tr><th>Company</th><td>Supraja Technologies</td></tr>
            <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
        </table>
    </body>
    </html>
    """

    with open("info_page.html", "w", encoding="utf-8") as f:
        f.write(html_content)

def show_info_page():
    create_info_page()
    webbrowser.open("info_page.html")

# --- GUI Setup ---

app = tk.Tk()
app.title("Block Malicious Website")
app.geometry("800x800")

# Load Image
try:
    image = Image.open("E:/image.png")
    image = image.resize((400, 300))
    photo = ImageTk.PhotoImage(image)
    image_label = tk.Label(app, image=photo)
    image_label.image = photo
    image_label.pack(pady=10)
except Exception as e:
    messagebox.showerror("Image Error", str(e))

tk.Label(app, text="Enter Website:").pack()
website_entry = tk.Entry(app, width=60)
website_entry.pack()

tk.Label(app, text="Enter Password:").pack()
password_entry = tk.Entry(app, width=60, show="*")
password_entry.insert(0, "password")  # Auto-fill for auto blocking
password_entry.pack()

tk.Label(app, text="Enter Email:").pack()
email_entry = tk.Entry(app, width=60)
email_entry.insert(0, "youremail@example.com")
email_entry.pack()

tk.Button(app, text="Block URL", command=submit_single_url_block).pack(pady=5)
tk.Button(app, text="Unblock URL", command=submit_single_url_unblock).pack(pady=5)
tk.Button(app, text="Upload URL List to Block", command=browse_file_block).pack(pady=5)
tk.Button(app, text="Upload URL List to Unblock", command=browse_file_unblock).pack(pady=5)
tk.Button(app, text="Open Website", command=open_website).pack(pady=5)
tk.Button(app, text="Generate Random Password", command=generate_and_insert_password).pack(pady=5)
tk.Button(app, text="Send Test Email", command=lambda: send_email("Test", "This is a test email", email_entry.get(), attach_log=True)).pack(pady=5)
tk.Button(app, text="Info Page", command=show_info_page).pack(pady=5)
tk.Button(app, text="Scan on VirusTotal (API)", command=scan_and_display).pack(pady=10)

tk.Label(app, text="Currently Blocked Sites:").pack(pady=10)
listbox = tk.Listbox(app, width=80, height=10)
listbox.pack()

refresh_blocked_list()
app.mainloop()
