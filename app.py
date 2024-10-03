from flask import Flask, flash, render_template, make_response, request, redirect, session, url_for, abort, send_file
import hashlib
import os
import io
import re
from datetime import datetime
from flask_mysqldb import MySQL
from config import Config
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'tu_clave_secreta_aqui'
mysql = MySQL(app)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cedula = request.form.get("cedula")
        recaptcha_response = request.form.get('g-recaptcha-response')
        # Validar reCAPTCHA (suponiendo que tienes una clave secreta)
        secret_key = 'TU_CLAVE_SECRETA'
        recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {'secret': secret_key, 'response': recaptcha_response}
        recaptcha_response = requests.post(recaptcha_verify_url, data=payload)
        recaptcha_result = recaptcha_response.json()

        if recaptcha_result.get("success"):
            return f"Consulta recibida para la cédula: {cedula}"
        else:
            return "reCAPTCHA no verificado. Inténtelo de nuevo."

    return render_template("index.html")

@app.route('/header')
def header():
    return render_template('header.html')
@app.route('/footer')
def footer():
    return render_template('footer.html')
if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], port=app.config['PORT'])
