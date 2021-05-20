from flask import Blueprint, render_template

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html', title='ورود')

@auth.route('/logout')
def logout():
    return render_template('logout.html', title='خروج')

@auth.route('/signup')
def signup():
    return render_template('signup.html', title='ثبت نام')

