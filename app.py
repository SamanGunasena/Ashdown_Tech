from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
from forms import PostForm

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
    def __init__(self, id, firstname,lastname, email,  password, is_admin, is_approved):
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
    return User(user['id'], user['firstname'], user['lastname'], user['email'], user['password'], user['is_admin'], user['is_approved'])


# Home page to display all blog posts
@app.route('/')
def home():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    current_year = datetime.now().year
    return render_template('home.html', posts=posts, current_year=current_year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute('INSERT INTO users (firstname,lastname, email, password, is_admin, is_approved) VALUES (?, ?, '
                     '?, ?, 0, 0)',
                     (firstname, lastname, email, hashed_password))
        conn.commit()
        conn.close()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        print(email, password)

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        print(user)
        if user and check_password_hash(user['password'], password):
            print("logged in")
            if user['is_approved']:
                user_obj = User(user['id'], user['firstname'], user['lastname'], user['email'], user['password'], user['is_admin'], user['is_approved'])
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
                     (title, content, current_user.username, filename, show_author))
        conn.commit()
        conn.close()

        flash('Post added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_post.html', form=form)  # Pass the form to the template


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


@app.route('/post/<int:post_id>')
def post_detail(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    if post is None:
        flash('Post not found.', 'danger')
        return redirect(url_for('home'))
    return render_template('post_detail.html', post=post)


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')  # Get the search query from the URL
    conn = get_db_connection()
    posts = conn.execute(
        'SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?',
        (f'%{query}%', f'%{query}%')
    ).fetchall()
    conn.close()
    return render_template('home.html', posts=posts)


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
        conn.commit()
        conn.close()

    app.run(debug=True)
