import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

# create a Blueprint names 'auth'
bp = Blueprint('auth', __name__, url_prefix='/auth')

# assosiacte register to the function


@bp.route('/register', methods=('GET', 'POST'))  # post for submitting forms
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:  # fetchone() returns one row, fetchall() returns a list of results
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute('INSERT INTO user (username,password) VALUES (?,?)',
                       (username, generate_password_hash(password)))  # hash passwords for security
            db.commit()
            return redirect(url_for('auth.login'))  # url_for generates a urlr

        flash(error)  # stores messages for the rendering template

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username'
        # compares database password and issued password via hashing
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

# load before the view function to check if user is logged in


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id),).fetchone()


def logout():  # handle log-out
    session.clear()
    return redirect(url_for('index'))


def login_required(view):  # decorator to check if user is logged in
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:  # if no user redirect to login
            return redirect(url_for('auth.login'))

        return view(**args)

    return wrapped_view
