from flask import Flask, render_template, request, session, redirect, url_for
import secrets
import csv
import requests
from cryptography.fernet import Fernet
import os
import datetime

# Generate a secure random secret key for session
secret_key = secrets.token_urlsafe(16)
print(f"Secret Key: {secret_key}")

API_KEY = '6896b75e9c39a1637ccc40695c5a2a9a'  # OpenWeatherMap API Key
WEATHER_URL = 'http://api.openweathermap.org/data/2.5/weather'
LAST_LOGIN_FILE = "last_login.txt"
app = Flask(__name__)
app.secret_key = secret_key

# Load the encryption key (this should be the same key used for encryption)
def load_key(key_file="key.key"):
    with open(key_file, "rb") as f:
        return f.read()

# Decrypt a stored encrypted password
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_password)  # No encoding here
    return decrypted.decode()  # Return the decrypted password as a string

# Validate credentials by decrypting the stored password
def validate_credentials(username, password):
    key = load_key()  # Load the encryption key
    with open('encrypted_passwords.csv', 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            if len(row) >= 3:  # Ensure there are enough columns in the row
                stored_username, encrypted_password = row[1], row[2]
                if username == stored_username:
                    decrypted_password = decrypt_password(encrypted_password, key)
                    if decrypted_password == password:
                        return True
    return False

def get_last_login(username):
    """Retrieve the last login time for a specific username."""
    if os.path.exists(LAST_LOGIN_FILE):
        with open(LAST_LOGIN_FILE, 'r') as file:
            lines = file.readlines()
            for line in lines:
                # Each line format: "username : timestamp"
                if line.startswith(username + " :"):

                    return line[7:]  # Return the matching line
    return f"No login recorded for {username}."

now = datetime.datetime.now()


def update_last_login(username):
    """Update the last login information for a specific username."""
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")

    # Read existing entries
    if os.path.exists(LAST_LOGIN_FILE):
        with open(LAST_LOGIN_FILE, 'r') as file:
            lines = file.readlines()
    else:
        lines = []

    # Check if username exists and update its row
    updated = False
    for i in range(len(lines)):
        if lines[i].startswith(username + " :"):
            lines[i] = f"{username} : {current_time}\n"
            updated = True
            break

    # If username not found, append a new entry
    if not updated:
        lines.append(f"{username} : {current_time}\n")

    # Write back the updated content
    with open(LAST_LOGIN_FILE, 'w') as file:
        file.writelines(lines)


@app.route('/')
def home():
    # Check if the user is already logged in
    if 'username' in session:
        # Fetch weather data
        temperature, description, icon = get_weather()
        return render_template('homepage.html', username=session['username'], temperature=temperature,
                               description=description, icon=icon)
    else:
        temperature, description, icon = get_weather()
        return render_template('unlogggedhome.html', temperature=temperature,
                               description=description, icon=icon)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        password = request.form['password']

        # Validate credentials from the CSV file
        if validate_credentials(username, password):
            # Store session cookie showing user authenticated
            session['username'] = username
            update_last_login(session['username'])

            return redirect(url_for('home'))
        else:
            return "Invalid credentials. Please try again.<br><a href='/login'>Try Again</a>"

    # If GET request, show the login form
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'username' in session:

        return render_template('profile.html', username=session['username'], lastlogin = get_last_login(session['username']))
    return render_template('unlogggedhome.html')


@app.route('/changePass', methods=['GET', 'POST'])
def changePass():
    if 'username' in session:
        username = session['username']

        if request.method == 'POST':
            # Get the form data (old password, new password)
            old_password = request.form['old_password']
            new_password = request.form['new_password']

            # Validate old password
            key = load_key()  # Load the encryption key
            with open('encrypted_passwords.csv', 'r') as file:
                reader = csv.reader(file)
                next(reader)  # Skip header row
                user_found = False
                for row in reader:
                    if row[1] == username:  # Match username
                        decrypted_password = decrypt_password(row[2], key)
                        if decrypted_password == old_password:  # Check old password
                            user_found = True
                            break

            if not user_found:
                return "Invalid old password. Please try again."

            # Encrypt new password
            fernet = Fernet(key)
            encrypted_new_password = fernet.encrypt(new_password.encode())

            # Update the CSV file with the new encrypted password
            updated = False
            with open('encrypted_passwords.csv', 'r') as file:
                lines = file.readlines()

            with open('encrypted_passwords.csv', 'w') as file:
                for line in lines:
                    if line.startswith(username):
                        file.write(f"{username},{row[1]},{encrypted_new_password.decode()}\n")  # Update password
                        updated = True
                    else:
                        file.write(line)

            if not updated:
                return "Error updating password."

            return "Password changed successfully."

        # If GET request, show the password change form
        return render_template('NewPassword.html', username=session['username'])

    else:
        return redirect(url_for('login'))


@app.route('/about')
def about():
    return "no"

@app.route('/pricing')
def pricing():
    return render_template("pricing.html")

@app.route('/success')
def success():
    if 'username' in session:
        username = session['username']
        return redirect(url_for('/'))
    else:
        return redirect(url_for('/'))

@app.route('/logout')
def logout():
    # Log the user out
    session.pop('username', None)
    return redirect(url_for('home'))


def get_weather(city='London'):
    params = {
        'q': city,
        'appid': API_KEY,
        'units': 'metric'  # You can change this to 'imperial' for Fahrenheit
    }
    response = requests.get(WEATHER_URL, params=params)

    if response.status_code == 200:
        data = response.json()
        temperature = data['main']['temp']
        description = data['weather'][0]['description']
        icon = data['weather'][0]['icon']
        return temperature, description, icon
    else:
        return None, "Weather data could not be retrieved.", None


if __name__ == '__main__':
    app.run(debug=False)
