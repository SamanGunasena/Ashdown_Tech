import uuid

from flask import Flask, render_template, redirect, url_for, flash, session, request, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
from forms import PostForm, RegistrationForm, QuestionForm, AnswerForm


UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Abcde1234!'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, firstname, lastname, email, password, is_admin, is_approved):
        self.id = id
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.password = password
        self.is_admin = is_admin
        self.is_approved = is_approved

    @property
    def is_active(self):
        return self.is_approved  # Example: Only approved users are considered active


def get_db_connection():
    conn = sqlite3.connect('site.db')
    conn.row_factory = sqlite3.Row  # Allows us to access columns by name
    return conn


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user is None:
        return None
    return User(user['id'], user['firstname'], user['lastname'], user['email'], user['password'], user['is_admin'],
                user['is_approved'])


# Home page to display all posts
@app.route('/')
def home():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    # Fetch questions with answers using the helper function
    questions = get_questions_and_answers(conn)
    conn.close()
    current_year = datetime.now().year
    return render_template('home.html', posts=posts, questions=questions, current_year=current_year)


# user registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        password = generate_password_hash(form.password.data)  # Hash the password for security

        # Save user to the database
        conn = get_db_connection()
        conn.execute('INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)',
                     (firstname, lastname, email, password))
        conn.commit()
        conn.close()

        flash('Your account has been created successfully!', 'success')
        return redirect(url_for('login'))  # Redirect to login after registration

    return render_template('register.html', form=form)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get and escape the user input
        email = escape(request.form['email'])
        password = request.form['password']

        conn = get_db_connection()
        # Use a parameterized query to prevent SQL injection
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        # Check if the user exists and if the password matches
        if user and check_password_hash(user['password'], password):
            if user['is_approved']:
                user_obj = User(user['id'], user['firstname'], user['lastname'], user['email'],
                                user['password'], user['is_admin'], user['is_approved'])
                login_user(user_obj)
                flash('You have been logged in!', 'success')

                # Redirect to admin dashboard if user is an admin
                if user['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('home'))
            else:
                flash('Your account is awaiting approval from the admin.', 'warning')
        else:
            flash('Login Unsuccessful. Please check your credentials.', 'danger')

    return render_template('login.html')


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('home'))


# add post route
@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        file = form.file.data  # This should be a FileField
        show_author = form.show_author.data  # Get the boolean value

        filename = None
        if file:  # Check if a file was uploaded
            original_filename = secure_filename(file.filename)
            # Create a timestamp for the filename
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')  # Format: YYYYMMDDHHMMSS
            # Construct the new filename
            filename = f"{timestamp}_{original_filename}"
            # Save the file to the uploads folder
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Insert the post into the database
        conn = get_db_connection()
        conn.execute('INSERT INTO posts (title, content, author, filename, show_author) VALUES (?, ?, ?, ?, ?)',
                     (title, content, current_user.firstname, filename, show_author))
        conn.commit()
        conn.close()

        flash('Post added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_post.html', form=form)  # Pass the form to the template


# admin dashboard routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ').fetchall()
    posts = conn.execute('SELECT * from posts ').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users, posts=posts)


# delete user route
@app.route('/admin/delete/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash(f'User with ID {user_id} has been deleted!', 'success')
    return redirect(url_for('admin_dashboard'))


# delete post route
@app.route('/admin/delete_post/<int:post_id>', methods=['GET'])
@login_required
def delete_post(post_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    conn = get_db_connection()

    # Fetch the post to get the filename
    post = conn.execute('SELECT filename FROM posts WHERE id = ?', (post_id,)).fetchone()

    if post:
        # Delete the associated file if it exists
        filename = post['filename']
        if filename:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

        # Now delete the post from the database
        conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()

        flash(f'Post with ID {post_id} has been deleted!', 'success')
    else:
        flash(f'Post with ID {post_id} not found!', 'danger')

    conn.close()
    return redirect(url_for('admin_dashboard'))


# Approve a user
@app.route('/admin/approve/<int:user_id>')
@login_required
def approve_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    conn = get_db_connection()
    conn.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash(f'User {user_id} has been approved!', 'success')
    return redirect(url_for('admin_dashboard'))


# single post page
@app.route('/post/<int:post_id>')
def post_detail(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    if post is None:
        flash('Post not found.', 'danger')
        return redirect(url_for('home'))
    return render_template('post_detail.html', post=post)


# search a post
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')  # Get the search query from the URL
    conn = get_db_connection()
    posts = conn.execute(
        'SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?',
        (f'%{query}%', f'%{query}%')
    ).fetchall()
    conn.close()
    return render_template('posts.html', posts=posts, query=query)


# search a question
@app.route('/q_search', methods=['GET'])
def q_search():
    query = request.args.get('query', '')  # Get the search query from the URL
    conn = get_db_connection()
    questions = conn.execute(
        'SELECT * FROM questions WHERE topic LIKE ? OR question LIKE ?',
        (f'%{query}%', f'%{query}%')
    ).fetchall()
    conn.close()
    return render_template('questions.html', questions=questions, query=query)


@app.route('/answer_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def answer_question(question_id):
    form = AnswerForm()

    conn = get_db_connection()

    # Fetch the question and its related answers
    question = conn.execute('SELECT * FROM questions WHERE id = ?', (question_id,)).fetchone()
    answers = conn.execute(
        'SELECT a.answer, a.created_at, u.firstname AS author FROM answers a '
        'LEFT JOIN users u ON a.user_id = u.id WHERE a.question_id = ?',
        (question_id,)
    ).fetchall()

    if not question:
        flash('Question not found!', 'danger')
        return redirect(url_for('home'))

    if form.validate_on_submit():
        new_answer = form.answer.data
        user_id = current_user.id  # Assuming you have a logged-in user

        # Insert the new answer into the database
        conn.execute(
            'INSERT INTO answers (question_id, answer, author, user_id) VALUES (?, ?, ?, ?)',
            (question_id, new_answer, current_user.firstname, current_user.id)
        )
        conn.commit()
        conn.close()

        flash('Your answer has been submitted successfully!', 'success')
        return redirect(url_for('answer_question', question_id=question_id))

    conn.close()
    return render_template('answer_question.html', question=question, answers=answers, form=form)


@app.route('/questions')
def questions():
    conn = get_db_connection()
    questions = conn.execute('SELECT * FROM questions').fetchall()

    questions_with_answers = []
    for question in questions:
        answers = conn.execute('SELECT * FROM answers WHERE question_id = ?', (question['id'],)).fetchall()
        questions_with_answers.append({
            'question': question['question'],
            'id': question['id'],
            'created_at': question['created_at'],
            'answers': answers
        })

    conn.close()
    return render_template('questions.html', questions=questions_with_answers)


@app.route('/ask_question', methods=['GET', 'POST'])
@login_required
def ask_question():
    form = QuestionForm()
    if request.method == 'POST':

        topic = form.topic.data
        question = form.question.data
        author = current_user.firstname

        # Insert the new question into the database
        conn = get_db_connection()
        conn.execute('INSERT INTO questions (topic, question, author) VALUES (?, ?, ?)', (topic, question, author))
        conn.commit()
        conn.close()

        flash('Your question has been submitted successfully!', 'success')
        return redirect(url_for('questions'))

    return render_template('ask_question.html', form=form)


def get_questions_and_answers(conn):
    questions = conn.execute('SELECT * FROM questions').fetchall()
    questions_with_answers = []

    for question in questions:
        answers = conn.execute('SELECT a.answer, a.created_at, u.firstname AS author FROM answers a '
                               'LEFT JOIN users u ON a.user_id = u.id '
                               'WHERE a.question_id = ?', (question['id'],)).fetchall()

        question_dict = dict(question)
        question_dict['answers'] = answers
        questions_with_answers.append(question_dict)

    return questions_with_answers


if __name__ == '__main__':
    # Create the database and tables if they don't exist
    with app.app_context():
        conn = get_db_connection()
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_approved INTEGER DEFAULT 0
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            filename TEXT,
            show_author BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Create the questions table if not already created
        conn.execute('''
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                question TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create the answers table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id INTEGER NOT NULL,
                answer TEXT NOT NULL,
                author TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
            )
        ''')

        conn.commit()
        conn.close()

    app.run(debug=True)
