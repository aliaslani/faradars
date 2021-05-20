from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('با موفقیت وارد حساب کاربری خود شدید', category='success')
                return redirect(url_for('views.home'))
        
    return render_template('login.html', title='ورود')

@auth.route('/logout', methods=['POST', 'GET'])
def logout():
    return render_template('logout.html', title='خروج')

@auth.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        if len(firstname) < 3:
            flash('نامی که وارد می کنید باید حداقل سه حرف باشد.', category='error')
        elif len(lastname) < 2:
            flash('نام خانوادگی که وارد می کنید باید حداقل دو حرف باشد.', category='error')
        elif len(email) < 8:
            flash('ایمیل وارد شده معتبر نیست.', category='error')
        elif len(password1) < 6:
            flash('رمز عبور باید حداقل شش کاراکتر باشد.', category='error')
        elif password1 != password2:
            flash('رمزهای عبور با هم مطابقت ندارد.', category='error')
        else:
            new_user = User(firstname = firstname, lastname = lastname, email=email, password = generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('ثبت نام شما با موفقیت انجام شد.', category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html', title='ثبت نام')

