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


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or not session['loggedin']:
            flash('Debe iniciar sesión para acceder a esta página', 'login-warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
 
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id_mt, nombre FROM motivoautorizacion")
    motivoautorizacion = cursor.fetchall()
 
    cursor.execute("SELECT id_val, nombre FROM validaciondocumentos")
    validaciondocumentos = cursor.fetchall()
 
    cursor.execute("SELECT id_dc, nombre FROM documentos")
    tipodocumento = cursor.fetchall()
 
    cursor.execute("SELECT id_bc, nombre FROM banco")
    banco = cursor.fetchall()
 
    cursor.execute("SELECT id_dp, departamentos FROM departamentos")
    departamentos = cursor.fetchall()
 
    cursor.execute("SELECT id_lc, localidad FROM localidades")
    localidades = cursor.fetchall()
 
    nombre_usuario = session.get('nombre')
 
    return render_template('index.html', motivoautorizacion=motivoautorizacion, validaciondocumentos=validaciondocumentos, tipodocumento=tipodocumento, bancos=banco, departamentos=departamentos, localidades=localidades, nombre_usuario=nombre_usuario)

@app.route('/add_oficios', methods=['POST'])
def add_oficios():
    # Recupera el idUser desde la sesión
    idUser = session.get('idUser')
    if idUser is None:
        flash('No estás autenticado. Inicia sesión para continuar.','login-success')
        return redirect(url_for('index'))

    fechaTramite = request.form.get('fechaTramite') or None
    numeroFolio = request.form.get('numeroFolio') or None
    numeroDocumento = request.form.get('nDocumento')
    nombre = request.form.get('Usuario')
    fechaConsignacion = request.form.get('dfecha') or None
    valorConsignacion = request.form.get('valorConsignacion') or None
    docCompleta = request.form.get('') or None
    codigoUnico = request.form.get('codigoUnico') or None
    archivoPlano = request.form.get('aPlano') or None
    observacion = request.form.get('observacion') or None
    departamento = request.form.get('lTramite') or None
    localidad = request.form.get('lLocalidad') or None
    tipoDocumento = request.form.get('tipoDocumento')
    banco = request.form.get('banco')
    motivo_autorizacion = request.form.get('motivoAutorizacion')
    
    # Obtener los valores seleccionados en el checkbox de validación
    validacion = request.form.getlist('vDoc')  # devuelve una lista de valores seleccionados

    # Si validacion está vacío, asignar None
    validacion = None if not validacion else ','.join(validacion)
    
    # Usa mysql.connection.cursor() para obtener el cursor
    cursor = mysql.connection.cursor()
    
    try:
        sql = """
            INSERT INTO oficios (
                fechaTramite, numeroFolio, numeroDocumento, nombre, 
                fechaConsignacion, valorConsignacion, docCompleta, 
                codigoUnico, archivoPlano, observacion, 
                id_dp, id_lc, id_dc, id_bc, id_mt, idUser, id_val
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        # Asegúrate de tener valores predeterminados en caso de que algunos campos sean opcionales
        data = (
            fechaTramite, numeroFolio, numeroDocumento, nombre,
            fechaConsignacion, valorConsignacion, docCompleta,
            codigoUnico, archivoPlano, observacion,
            departamento, localidad, tipoDocumento, banco, motivo_autorizacion, idUser, validacion
        )
        
        cursor.execute(sql, data)
        mysql.connection.commit()
        flash('Oficio agregado correctamente', 'success')
    except mysql.connection.Error as err:
        flash(f"Error al agregar el oficio: {err}", 'error')
        mysql.connection.rollback()
    finally:
        cursor.close()
    
    return redirect(url_for('index'))


@app.route('/download/<filename>')
def download_file(filename):
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT nombre FROM archivos WHERE nombre = %s', (filename,))
    result = cursor.fetchone()
    
    if result:
        filename = result[0]

        # Busca en todas las subcarpetas dentro de _docs
        file_path = None
        for root, dirs, files in os.walk('_docs'):
            if filename in files:
                file_path = os.path.join(root, filename)
                break

        if file_path and os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                file_content = f.read()

            return send_file(
                io.BytesIO(file_content),
                download_name=filename,
                as_attachment=True
            )
        else:
            abort(404, description="Archivo no encontrado en el sistema de archivos")
    else:
        abort(404, description="Archivo no encontrado en la base de datos")

@app.route('/footer')
def footer():
    return render_template('footer.html')

@app.route('/header')
def header():
    return render_template('header.html')


# Función para encriptar contraseñas con SHA-1
def encrypt_password(password):
    return hashlib.sha1(password.encode()).hexdigest()

# Ruta de inicio de sesión
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    correo = request.form['correo']

    # Verificar si el correo existe en la base de datos
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT correo FROM usuarios WHERE correo = %s", (correo,))
    user = cursor.fetchone()
    cursor.close()

    if user:
        # Si el correo existe, redirigir al formulario de restablecimiento de contraseña
        return redirect(url_for('reset_password', correo=correo))
    else:
        flash('No se encontró una cuenta asociada a ese correo electrónico.', 'error')
        return redirect(url_for('login'))
    
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    correo = request.form.get('correo') or request.args.get('correo')

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Las contraseñas no coinciden.', 'error')
            return redirect(url_for('reset_password', correo=correo))

        if validar_contraseña(new_password):  # Validar que la contraseña cumple los requisitos
            hashed_password = encrypt_password(new_password)

            if hashed_password is None:
                flash('Error al encriptar la contraseña.', 'error')
                return redirect(url_for('reset_password', correo=correo))

            cursor = mysql.connection.cursor()
            try:
                cursor.execute("UPDATE usuarios SET contraseña = %s WHERE correo = %s", (hashed_password, correo))
                mysql.connection.commit()

                if cursor.rowcount == 0:
                    flash('No se encontró el correo en la base de datos.', 'error')
                    return redirect(url_for('reset_password', correo=correo))

                flash('Tu contraseña ha sido actualizada correctamente.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                mysql.connection.rollback()
                flash('Ocurrió un error al actualizar la contraseña. Inténtalo de nuevo.', 'error')
                print(f"Error al actualizar la contraseña: {e}")
            finally:
                cursor.close()
        else:
            flash('La contraseña debe contener al menos una letra mayúscula, una letra minúscula y un número.', 'error-login')

    return render_template('reset_password.html', correo=correo)

@app.route('/', methods=['GET', 'POST'])
def login():
    cursor = mysql.connection.cursor()
    if request.method == 'POST':
        usuario = request.form['usuario']
        contraseña = encrypt_password(request.form['contraseña'])
        
        cursor.execute("SELECT idUser, nombre, estado FROM usuarios WHERE usuario=%s AND contraseña=%s", (usuario, contraseña))
        usuario_data = cursor.fetchone()

        if usuario_data:
            if usuario_data[2] == 'A':  # Verificar que el estado sea activo
                session['usuario'] = usuario  # Almacenar el nombre de usuario en la sesión
                session['nombre'] = usuario_data[1]
                session['idUser'] = usuario_data[0]  # Guardar idUser en la sesión
                session['loggedin'] = True  # Establecer que el usuario ha iniciado sesión
                if usuario == 'admin':  # Si el usuario es 'admin'
                    return redirect(url_for('admin'))  # Redirigir a la página de administración
                return redirect(url_for('index'))  # Redirigir a la página de inicio por defecto
            else:
                flash("Tu cuenta está inactiva, contacta al administrador para activar tu cuenta.", 'login-warning')
        else:
            flash("Usuario o contraseña incorrectos", 'login-error')
        
    cursor.close()
    return render_template('login.html')


def validar_contraseña(contraseña):
    if (re.search(r'[A-Z]', contraseña) and   # Al menos una letra mayúscula
        re.search(r'[a-z]', contraseña) and   # Al menos una letra minúscula
        re.search(r'\d', contraseña)):        # Al menos un número
        return True
    return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = mysql.connection.cursor()  # Definir el cursor aquí
    if request.method == 'POST':
        nombre = request.form['nombre']
        usuario = request.form['usuario']
        correo = request.form['correo']
        contraseña = encrypt_password(request.form['contraseña'])

        # Verificar si el correo termina en '@registraduria.gov.co'
        if not correo.endswith('@registraduria.gov.co'):
            flash("El correo debe ser de dominio @registraduria.gov.co.", 'register-error')
            return render_template('login.html')

        # Verificar si el usuario ya existe
        cursor.execute("SELECT id FROM usuarios WHERE usuario=%s", (usuario,))
        usuario_existente = cursor.fetchone()

        # Verificar si el correo ya existe
        cursor.execute("SELECT id FROM usuarios WHERE correo=%s", (correo,))
        correo_existente = cursor.fetchone()

        # Comprobar qué campos ya existen y generar mensajes específicos
        errores = []
        if usuario_existente:
            errores.append("El usuario ya está en uso.")
        if correo_existente:
            errores.append("El correo ya está en uso.")
        
        # Si hay errores, mostrar los mensajes
        if errores:
            flash(" ".join(errores), 'register-warning')
        else:
            try:
                cursor.execute("INSERT INTO usuarios (nombre, usuario, correo, contraseña, estado) VALUES (%s, %s, %s, %s, 'I')", 
                               (nombre, usuario, correo, contraseña))
                mysql.connection.commit()
                flash("Registro exitoso. ¡Ya puedes iniciar sesión!", 'login-success')
            except Exception as e:
                mysql.connection.rollback()  # Revertir en caso de error
                flash("Ocurrió un error al registrar. Inténtalo de nuevo.", 'register-error')

    cursor.close()  # Cerrar el cursor
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('usuario', None)
    
    flash('Sesión cerrada correctamente', 'login-success')
    
    resp = make_response(redirect(url_for('login')))
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Ruta para habilitar un usuario
@app.route('/habilitar/<int:id>')
@login_required
def habilitar_usuario(id):
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE usuarios SET estado = 'A' WHERE idUser = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash('Usuario habilitado correctamente', 'success')
    return redirect(url_for('admin'))

# Ruta para inhabilitar un usuario
@app.route('/inhabilitar/<int:id>')
@login_required
def inhabilitar_usuario(id):
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE usuarios SET estado = 'I' WHERE idUser = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash('Usuario inhabilitado correctamente', 'success')
    return redirect(url_for('admin'))

# Ruta para actualizar un usuario
@app.route('/actualizar_usuario/<int:id>', methods=['POST'])
@login_required
def actualizar_usuario(id):
    nombre = request.form['nombre']
    correo = request.form['correo']
    usuario = request.form['usuario']
    
    cursor = mysql.connection.cursor()
    cursor.execute("""
        UPDATE usuarios 
        SET nombre = %s, correo = %s, usuario = %s 
        WHERE id = %s
    """, (nombre, correo, usuario, id))
    mysql.connection.commit()
    cursor.close()
    
    flash('Usuario actualizado correctamente', 'success')
    return redirect(url_for('admin'))


# Ruta para mostrar la lista de usuarios y las acciones de habilitar, inhabilitar, editar y eliminar
@app.route('/admin')
@login_required  # Asegurarse de que esta ruta esté protegida por login
def admin():
    cursor = mysql.connection.cursor()
    # Excluir a los usuarios con rol 'admin'
    cursor.execute("SELECT * FROM usuarios WHERE usuario != 'admin'")
    usuarios = cursor.fetchall()
    cursor.close()
    return render_template('admin.html', usuarios=usuarios)


# Captar el perfil para obtener el nombre de la persona dueña del perfil #
@app.route('/perfilE')
def perfilE():
    if 'user_id' not in session:
        return redirect(url_for('iniciosesion'))

    user_id = session['user_id']

    # Lógica para obtener la información del empleado desde la base de datos
    funcionario = (user_id)


    return render_template('empleados/perfilE.html', funcionario=funcionario)

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], port=app.config['PORT'])
