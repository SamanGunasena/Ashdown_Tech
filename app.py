from flask import Flask, render_template, redirect, url_for, flash, session, request, abort, current_app
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
from flask_mail import Mail, Message

from wtforms.validators import ValidationError

from forms import PostForm, RegistrationForm, QuestionForm, AnswerForm, LoginForm
from dotenv import load_dotenv
from flask_limiter import Limiter

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
# secure cookie settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configure the Flask-Mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587  # For TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ashdowncontrolsr58k@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'qgxwmewfcyevpgmk'  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = 'ashdowncontrolsr58k@gmail.com'  # Default sender

mail = Mail(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)

# Initialize the limiter with the app
limiter.init_app(app)

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
    posts = conn.execute('SELECT * FROM posts ORDER BY created_at DESC LIMIT 9').fetchall()
    # Fetch questions with answers using the helper function
    questions = get_questions_and_answers(conn)
    conn.close()
    current_year = datetime.now().year
    return render_template('home.html', posts=posts, questions=questions, current_year=current_year)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# user registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        if email_exists(form.email.data):
            form.email.errors.append('That email is already registered. Please choose a different one.')
            return render_template('register.html', form=form)

        firstname = form.firstname.data
        lastname = form.lastname.data
        password = generate_password_hash(form.password.data)

        # Save user to the database
        conn = get_db_connection()
        conn.execute('INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)',
                     (firstname, lastname, form.email.data, password))
        conn.commit()
        conn.close()

        flash('Your account has been created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


def email_exists(email):
    conn = get_db_connection()
    existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return existing_user is not None


# Login route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    form = LoginForm()  # Create an instance of the LoginForm

    if form.validate_on_submit():  # Use the form's validation
        email = form.email.data  # Get the email from the form
        password = form.password.data  # Get the password from the form

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if user['is_approved']:
                user_obj = User(user['id'], user['firstname'], user['lastname'], user['email'],
                                user['password'], user['is_admin'], user['is_approved'])
                login_user(user_obj)
                flash('You have been logged in!', 'success')

                next_page = request.args.get('next')  # Check if there's a 'next' parameter
                if next_page:  # Redirect to 'next' if available
                    return redirect(next_page)

                if user['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('home'))
            else:
                flash('Your account is awaiting approval from the admin.', 'warning')
        else:
            flash('Login Unsuccessful. Please check your credentials.', 'danger')

    return render_template('login.html', form=form)  # Pass the form to the template


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
        post_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]  # Get the new post's ID
        conn.commit()

        # Fetch all user emails from the database
        users = conn.execute('SELECT email FROM users').fetchall()
        conn.close()

        # Send email notification to all users
        post_url = url_for('post_detail', post_id=post_id, _external=True)
        send_new_post_notification(users, title, content, post_url)

        flash('Post added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_post.html', form=form)  # Pass the form to the template


def send_new_post_notification(users, post_title, post_content, post_url):
    """Send email notifications to all users about a new post."""
    subject = "New Post Alert!"
    sender = app.config['MAIL_DEFAULT_SENDER']

    for user in users:
        recipient = user['email']  # Assuming your query returns a dictionary with 'email' key
        msg = Message(subject, recipients=[recipient], sender=sender)

        msg.body = f"""Hello,

A new post titled "{post_title}" has been added. Here's a preview:

{post_content[:150]}...

Read the full post here: {post_url}

Best regards,
Your Website Team
"""
        # Send the email
        mail.send(msg)


# admin dashboard routes
@app.route('/admin_dashboard')
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    qanda = conn.execute('SELECT * FROM questions').fetchall()

    questions_with_answers = []
    for question in qanda:
        answers = conn.execute('SELECT * FROM answers WHERE question_id = ?', (question['id'],)).fetchall()
        questions_with_answers.append({
            'question': question['question'],
            'id': question['id'],
            'created_at': question['created_at'],
            'answers': answers
        })

    conn.close()
    return render_template('admin_dashboard.html', users=users, posts=posts,
                           questions_with_answers=questions_with_answers)


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


@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required  # Ensure only authorized users can delete questions
def delete_question(question_id):
    conn = get_db_connection()

    # Check if the question exists
    question = conn.execute('SELECT * FROM questions WHERE id = ?', (question_id,)).fetchone()

    if not question:
        flash('Question not found!', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Fetch all answers related to this question
    answers = conn.execute('SELECT * FROM answers WHERE question_id = ?', (question_id,)).fetchall()

    # Delete the associated attachments for each answer
    for answer in answers:
        if answer['attachment']:  # Assuming you store attachment filenames in an 'attachment' column
            attachment_path = os.path.join(current_app.root_path, 'static/uploads', answer['attachment'])
            if os.path.exists(attachment_path):
                os.remove(attachment_path)

    # Delete answers related to this question
    conn.execute('DELETE FROM answers WHERE question_id = ?', (question_id,))

    # Delete the question itself
    conn.execute('DELETE FROM questions WHERE id = ?', (question_id,))

    conn.commit()
    conn.close()

    flash('The question and all related answers (including attachments) have been deleted.', 'success')
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
        'SELECT a.answer, a.created_at, a.attachment, u.firstname AS author FROM answers a '
        'LEFT JOIN users u ON a.user_id = u.id WHERE a.question_id = ?',
        (question_id,)
    ).fetchall()

    if not question:
        flash('Question not found!', 'danger')
        return redirect(url_for('home'))

    if form.validate_on_submit():
        new_answer = form.answer.data
        user_id = current_user.id  # Assuming you have a logged-in user

        # Handle file upload if an attachment is provided
        attachment_filename = None
        if 'attachment' in request.files:
            attachment = request.files['attachment']
            if attachment and allowed_file(attachment.filename):  # Check if the file is allowed
                original_filename = secure_filename(attachment.filename)
                # Generate a unique filename
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')  # Format: YYYYMMDDHHMMSS
                attachment_filename = f"{timestamp}_{original_filename}"  # Append timestamp to filename
                attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], attachment_filename))

        # Insert the new answer into the database
        conn.execute(
            'INSERT INTO answers (question_id, answer, author, user_id, attachment) VALUES (?, ?, ?, ?, ?)',
            (question_id, new_answer, current_user.firstname, user_id, attachment_filename)
        )
        conn.commit()

        # Fetch the question author's email
        author_email = conn.execute('SELECT email FROM users WHERE id = ?', (question['author_id'],)).fetchone()

        conn.close()

        # Email the question's author
        if author_email:
            send_answer_notification(author_email['email'], question, new_answer)

        flash('Your answer has been submitted successfully!', 'success')
        return redirect(url_for('answer_question', question_id=question_id))

    conn.close()
    return render_template('answer_question.html', question=question, answers=answers, form=form)


@app.route('/questions')
def questions():
    conn = get_db_connection()
    questions = conn.execute('SELECT * FROM questions ').fetchall()

    questions_with_answers = []
    for question in questions:
        answers = conn.execute('SELECT * FROM answers WHERE question_id = ? ', (question['id'],)).fetchall()
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
        author_id = current_user.id

        # Insert the new question into the database
        conn = get_db_connection()
        cursor = conn.execute('INSERT INTO questions (topic, question, author, author_id) VALUES (?, ?, ?, ?)',
                              (topic, question, author, author_id))
        question_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Send notification to all users
        send_notification_email(question, topic, author, question_id)

        flash('Your question has been submitted successfully!', 'success')
        return redirect(url_for('questions'))

    return render_template('ask_question.html', form=form)


def get_questions_and_answers(conn):
    questions = conn.execute('SELECT * FROM questions ORDER BY created_at DESC LIMIT 100').fetchall()
    questions_with_answers = []

    for question in questions:
        answers = conn.execute('SELECT a.answer, a.created_at, u.firstname AS author FROM answers a '
                               'LEFT JOIN users u ON a.user_id = u.id '
                               'WHERE a.question_id = ? ORDER BY a.created_at DESC LIMIT 1',
                               (question['id'],)).fetchall()

        question_dict = dict(question)
        question_dict['answers'] = answers
        questions_with_answers.append(question_dict)

    return questions_with_answers


def send_notification_email(question, topic, author, question_id):
    conn = get_db_connection()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()

    # URL for the question detail page
    question_link = url_for('question_detail', question_id=question_id, _external=True)

    for user in users:
        try:
            msg = Message(subject=f'New Question on {topic} by {author}',
                          recipients=[user['email']])
            msg.body = f"New Topic: {topic}\n\n" \
                       f"Question: {question}\n\n" \
                       f"Asked by: {author}\n\n" \
                       f"View and answer the question here: {question_link}"
            mail.send(msg)
        except Exception as e:
            print(f'Failed to send email to {user["email"]}: {e}')


@app.route('/question/<int:question_id>')
def question_detail(question_id):
    conn = get_db_connection()
    question = conn.execute('SELECT * FROM questions WHERE id = ?', (question_id,)).fetchone()
    answers = conn.execute(
        'SELECT a.answer, a.created_at, a.attachment, u.firstname AS author FROM answers a '
        'LEFT JOIN users u ON a.user_id = u.id WHERE a.question_id = ?',
        (question_id,)
    ).fetchall()
    conn.close()

    if not question:
        flash('Question not found!', 'danger')
        return redirect(url_for('home'))

    return render_template('question_detail.html', question=question, answers=answers)


def send_answer_notification(author_email, question, new_answer):
    msg = Message(
        subject="New Answer to Your Question",
        recipients=[author_email],  # The email address of the question's author
        body=f"Hello,\n\nYour question titled '{question['topic']}' has received a new answer:\n\n{new_answer}\n\nBest regards,\nYour Website Team"
    )
    try:
        mail.send(msg)
        print(f"Notification sent to {author_email}.")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")


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
                author_id TEXT NOT NULL,
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
                attachment TEXT,
                FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
                
            )
        ''')

        conn.commit()
        conn.close()

    app.run(debug=True)
