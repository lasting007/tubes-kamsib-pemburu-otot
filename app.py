from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField
from wtforms.validators import DataRequired
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import escape
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24) 

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f'<Student {self.name}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class EditStudentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired()])
    grade = StringField('Grade', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() 
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        
        return "Invalid username or password"

    return render_template('login.html', form=form) 

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    students = db.session.execute(text('SELECT * FROM student')).fetchall()
    return render_template('index.html', students=students)

@app.route('/add', methods=['POST'])
@login_required
def add_student():
    name = request.form['name']
    age = request.form['age']
    grade = request.form['grade']

    name = escape(name)
    age = escape(age)
    grade = escape(grade)
    
    query = text("INSERT INTO student (name, age, grade) VALUES (:name, :age, :grade)")
    db.session.execute(query, {'name': name, 'age': age, 'grade': grade})
    db.session.commit()
    
    return redirect(url_for('index'))

@app.route('/delete/<string:id>', methods=['POST'])
@login_required
def delete_student(id):
    query = text("DELETE FROM student WHERE id=:id")
    #db.session.execute(text(f"DELETE FROM student WHERE id={id}")) #INI SEBELUM REVISI
    db.session.execute(query, {'id': id}) #REVISI UNTUK MENGHINDARI SQL INJECTION
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_student(id):
    student = db.session.execute(text(f"SELECT * FROM student WHERE id=:id"), {'id': id}).fetchone()

    form = EditStudentForm()

    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data
        age = form.age.data
        grade = form.grade.data
        query = text("UPDATE student SET name=:name, age=:age, grade=:grade WHERE id=:id")
        #db.session.execute(text(f"UPDATE student SET name='{name}', age={age}, grade='{grade}' WHERE id={id}")) #INI SEBELUM REVISI
        db.session.execute(query, {'name': name, 'age': age, 'grade': grade, 'id': id}) #REVISI UNTUK MENGHINDARI SQL INJECTION
        db.session.commit()
        
        return redirect(url_for('index'))

    return render_template('edit.html', student=student, form=form)

@app.route('/serangg')
@csrf.exempt
def serangg():
    return render_template('serangg.html')

@app.before_request
def disable_csrf_for_attack():
    if request.endpoint == 'serangg':
        print("Disabling CSRF for serangg endpoint")
        csrf._disable_on_request = True

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
