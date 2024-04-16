from flask import Flask, render_template, request, session, redirect, url_for, flash
from cipher import store_cipher, decrypt_cipher, get_all_ciphers, clear_user_ciphers
from users import validate_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'

ADMIN_USERNAME = 'admin1'

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form['username']
    password = request.form['password']
    if validate_user(username, password):  # Assuming you have a validate_user function
        session['username'] = username
        flash('Login successful!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Invalid credentials. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/index')
def index():
    if 'username' in session:
        username = session['username']
        is_admin = (username == ADMIN_USERNAME)
        ciphers = None
        if is_admin:
            ciphers = get_all_ciphers(username=ADMIN_USERNAME)  # Pass the username to get all ciphers for admin
        return render_template('index.html', username=username, is_admin=is_admin, ciphers=ciphers)
    return redirect(url_for('login'))


@app.route('/store', methods=['POST'])
def store_password():
    if 'username' in session:
        name = request.form['name']
        password = request.form['password']
        encrypted_password = store_cipher(session['username'], name, password)
        message = "Password encrypted successfully. Here is your cipher: " + encrypted_password
        return render_template('show_encrypted_message.html', encrypted_password=encrypted_password)
    return redirect(url_for('login'))


@app.route('/decrypt', methods=['POST'])
def decrypt_password():
    if 'username' in session:
        ciphertext = request.form['ciphertext']
        decrypted_password = decrypt_cipher(session['username'], ciphertext)
        if decrypted_password:
            flash(f'Decrypted password: {decrypted_password}', 'success')
            return render_template('show_decrypted_message.html', decrypted_password=decrypted_password)
        else:
            flash('Error decrypting password. Invalid cipher.', 'error')
        return redirect(url_for('index'))
    return redirect(url_for('login'))


@app.route('/clear', methods=['POST'])
def clear_passwords():
    if 'username' in session:
        username = session['username']
        success = clear_user_ciphers(username)
        if success:
            flash('All your stored passwords have been cleared successfully.', 'success')
        else:
            flash('Error clearing stored passwords.', 'error')
    return redirect(url_for('index'))


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)