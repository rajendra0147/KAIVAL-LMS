# ./app.py

from flask import Flask, render_template, request, redirect, url_for, session,  request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from bson import ObjectId
from pymongo import MongoClient
import bcrypt
from datetime import datetime
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Database configuration
app.config["MONGO_URI"] = os.getenv('MONGO_URI')
mongo = PyMongo(app)
users_collection = mongo.db.users
issued_books_collection=mongo.db.issued_books
books_collection = mongo.db.books
authors_collection = mongo.db.authors
category_collection = mongo.db.category

def create_admin_user():
    admin_username = 'admin'
    admin_password = 'admin'
    admin_role = 'Admin'
    admin_email = 'admin@gmail.com'
    admin_mobile = '1234567890'
    admin_address = 'Admin Address'
    # Check if admin user already exists
    existing_admin = users_collection.find_one({"username": admin_username, "role": admin_role})
    
    if existing_admin:
        print("Admin user already exists. Skipping creation.")
    else:
        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        admin_user = {
            "username": admin_username,
            "password": hashed_password,
            "role": admin_role,
            "email": admin_email,
            "mobile": admin_mobile,
            "address": admin_address
        }
        users_collection.insert_one(admin_user)
        print("Admin user created successfully.")

# Define User model for authentication
class User(UserMixin):
    def __init__(self, user_dict):
        self.id = user_dict.get('_id')
        self.username = user_dict.get('username')
        self.password = user_dict.get('password')
        self.email = user_dict.get('email')
        self.mobile = user_dict.get('mobile')
        self.address = user_dict.get('address')
        self.role = user_dict.get('role', 'User')
        self.book_id = user_dict.get('book_id')

    def is_admin(self):
        return self.role == 'Admin'
    
    

@login_manager.user_loader
def load_user(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})  # Convert to ObjectId
        print(f"load_user: user_id={ObjectId(user_id)}, user={user}")  # Debugging statement
        if user:
            return User(user)
    except Exception as e:
        print(f"Error loading user: {e}")  # Add error logging
    return None


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        
        user = users_collection.find_one({"email": email, "role": "User"})
        if user and bcrypt.checkpw(password, user['password']):
            session['email'] = email
            user_obj = User(user)
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('index.html')
        
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        mobile = request.form['mobile']
        address = request.form['address']
        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
                flash('Username already exists. Please choose a different username.', 'danger')
                return redirect(url_for('register'))
        elif username and password:
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
            new_user = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "mobile": mobile,
            "address": address,
            "role": "User"
            }
            users_collection.insert_one(new_user)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Username and password are required.', 'danger')
    return render_template('register.html')
    


@app.route('/dashboard')
@login_required
def dashboard():
    user = users_collection.find_one({"email": session['email']})
    issued_book = issued_books_collection.find({"student_name": user['username']})
    issued_book_count = issued_books_collection.count_documents({"student_name": user['username']})

    return render_template('user_dashboard.html', 
                            user_name=user['username'], 
                            email=user['email'],
                            issued_book=issued_book,
                            issued_book_count=issued_book_count)
    


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_email = request.form['email']
        admin_password = request.form['password'].encode('utf-8')
        
        admin_user = users_collection.find_one({"email": admin_email, "role": "Admin"})
        if admin_user and bcrypt.checkpw(admin_password, admin_user['password']):
            session['email'] = admin_email
            user_obj = User(admin_user)
            login_user(user_obj)
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid admin login credentials"
    
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    user = users_collection.find_one({"email": session['email']})
    user_count = users_collection.count_documents({"role": "User"})
    book_count = books_collection.count_documents({})
    author_count = authors_collection.count_documents({})
    issue_book_count = issued_books_collection.count_documents({})
    category_count = category_collection.count_documents({})

    return render_template('admin_dashboard.html',
                            user_name=user['username'], 
                            email=user['email'],
                            user_count=user_count,
                            book_count=book_count,
                            author_count=author_count,
                            issue_book_count=issue_book_count,
                            category_count=category_count)

@app.route('/view_profile')
@login_required
def view_profile():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})

        return render_template('view_profile.html', 
                                user_name=user['username'], 
                                email=user['email'],
                                mobile=user['mobile'],
                                address=user['address'])
    else:
        return redirect(url_for('index'))
    
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        if request.method == 'POST':
            updated_profile = {
                "username": request.form['username'],
                "email": request.form['email'],
                "mobile": request.form['mobile'],
                "address": request.form['address']
            }

            users_collection.update_one({"_id": user["_id"]}, {"$set": updated_profile})
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('view_profile'))
        else:
            return render_template('edit_profile.html', 
                                    user_name=user['username'], 
                                    email=user['email'],
                                    mobile=user['mobile'],
                                    address=user['address'])

    else:
        return redirect(url_for('index'))


    
@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        if request.method == 'POST':
            old_password = request.form['old_password'].encode('utf-8')
            if bcrypt.checkpw(old_password, user['password']):
                new_password = request.form['new_password'].encode('utf-8')
                hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
                users_collection.update_one({"_id": user["_id"]}, {"$set": {"password":hashed_password}})
                flash('Password updated successfully!', 'success')
                return redirect(url_for('logout'))
            else:       
                flash('Old password is incorrect.', 'danger')
                return redirect(url_for('update_password'))
        return render_template('change_password.html',
                                user_name=user['username'], 
                                email=user['email'])
    else:
        return redirect(url_for('index'))

@app.route('/view_issued_book')
@login_required
def view_issued_book():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        if user['role']== 'Admin':
            issued_book = issued_books_collection.find()
        else:
            issued_book = issued_books_collection.find({"student_name": user['username']})
        return render_template('view_issued_book.html', books=issued_book,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))

@app.route('/view_registered_user')
@login_required
def view_registered_user():
    if current_user.is_authenticated:
        users = users_collection.find()
        user = users_collection.find_one({"email": session['email']})
        return render_template('view_registered_user.html', users=users,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))
    
@app.route('/add_new_book', methods=['GET', 'POST'])
@login_required
def add_new_book():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        if request.method == 'POST':
            book_name=request.form['book_name']
            book_author=request.form['book_author']
            book_category=request.form['book_category']
            book_price=request.form['book_price']
            new_book = {
                "book_name":book_name,
                "book_author":book_author,
                "book_category":book_category,
                "book_price":book_price
            }
            books_collection.insert_one(new_book)
            flash('New Book successful added!', 'success')
            return redirect(url_for('add_new_book'))
        return render_template('add_book.html',
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))
    

@app.route('/manage_book', methods=['GET', 'POST'])
@login_required
def manage_book():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        books = books_collection.find()
        return render_template('manage_book.html',
                               books=books,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))
    

@app.route('/edit_book/<book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = books_collection.find_one({"_id": ObjectId(book_id)})
    user = users_collection.find_one({"email": session['email']})
    if not book:
        flash('Book not found', 'danger')
        return redirect(url_for('manage_book'))
    
    if request.method == 'POST':
        book_name=request.form['book_name']
        book_author=request.form['book_author']
        book_category=request.form['book_category']
        book_price=request.form['book_price']
        update_book = {
            "book_name":book_name,
            "book_author":book_author,
            "book_category":book_category,
            "book_price":book_price
        }
        books_collection.update_one({"_id": ObjectId(book_id)}, {"$set": update_book})
        flash('Book updated successfully', 'success')
        return redirect(url_for('manage_book'))
    
    return render_template('edit_book.html',
                                user_name=user['username'],
                                email=user['email'],
                                book_name=book['book_name'],
                                book_author=book['book_author'],
                                book_category=book['book_category'],
                                book_price=book['book_price'])

@app.route('/delete_book/<book_id>', methods=['GET', 'POST'])
@login_required
def delete_book(book_id):
    if request.method == 'GET':
        book = books_collection.find_one({"_id":ObjectId(book_id)})
        if not book:
            flash('Book not found', 'danger')
            return redirect(url_for('manage_book'))
        books_collection.delete_one({"_id": ObjectId(book_id)})
        flash('book deleted successfully', 'success')
    return redirect(url_for('manage_book'))

@app.route('/view_registered_book')
@login_required
def view_registered_book():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        books = books_collection.find()
        return render_template('view_registered_book.html', books=books,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))
    

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        if request.method == 'POST':
            category_name = request.form['category_name']
            category = {
                "category_name":category_name
            }
            category_collection.insert_one(category)
            flash('Category successful added!', 'success')
            return redirect(url_for('add_category'))
        return render_template('add_category.html',
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))


@app.route('/manage_category', methods=['GET', 'POST'])
@login_required
def manage_category():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        categories = category_collection.find()
        return render_template('manage_category.html',
                               categories=categories,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))

@app.route('/edit_category/<category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = category_collection.find_one({"_id": ObjectId(category_id)})
    user = users_collection.find_one({"email": session['email']})
    if not category:
        flash('Category not found', 'danger')
        return redirect(url_for('manage_category'))
    
    if request.method == 'POST':
        category_name=request.form['category_name']
        update_category = {
            "category_name":category_name,
        }
        category_collection.update_one({"_id": ObjectId(category_id)}, {"$set": update_category})
        flash('Category updated successfully', 'success')
        return redirect(url_for('manage_category'))
    
    return render_template('edit_category.html',
                                user_name=user['username'],
                                email=user['email'],
                                category_name=category['category_name'])

@app.route('/delete_category/<category_id>', methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    if request.method == 'GET':
        category = category_collection.find_one({"_id":ObjectId(category_id)})
        if not category:
            flash('Category not found', 'danger')
            return redirect(url_for('manage_category'))
        category_collection.delete_one({"_id": ObjectId(category_id)})
        flash('Category deleted successfully', 'success')
    return redirect(url_for('manage_category'))


@app.route('/view_registered_category')
@login_required
def view_registered_category():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        categories = category_collection.find()
        return render_template('view_registered_category.html', categories=categories,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))

@app.route('/add_author', methods=['GET', 'POST'])
@login_required
def add_author():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        if request.method == 'POST':
            author_name = request.form['author_name']
            author = {
                "author_name":author_name
            }
            authors_collection.insert_one(author)
            flash('Author successful added!', 'success')
            return redirect(url_for('add_author'))
        return render_template('add_author.html',
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))


@app.route('/manage_author', methods=['GET', 'POST'])
@login_required
def manage_author():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        authors = authors_collection.find()
        return render_template('manage_author.html',
                               authors=authors,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))

@app.route('/edit_author/<author_id>', methods=['GET', 'POST'])
@login_required
def edit_author(author_id):
    author = authors_collection.find_one({"_id": ObjectId(author_id)})
    user = users_collection.find_one({"email": session['email']})
    if not author:
        flash('Author not found', 'danger')
        return redirect(url_for('manage_author'))
    
    if request.method == 'POST':
        author_name=request.form['author_name']
        update_author = {
            "author_name":author_name,
        }
        authors_collection.update_one({"_id": ObjectId(author_id)}, {"$set": update_author})
        flash('Author updated successfully', 'success')
        return redirect(url_for('manage_author'))
    
    return render_template('edit_author.html',
                                user_name=user['username'],
                                email=user['email'],
                                author_name=author['author_name'])

@app.route('/delete_author/<author_id>', methods=['GET', 'POST'])
@login_required
def delete_author(author_id):
    if request.method == 'GET':
        author = authors_collection.find_one({"_id":ObjectId(author_id)})
        if not author:
            flash('Author not found', 'danger')
            return redirect(url_for('manage_author'))
        authors_collection.delete_one({"_id": ObjectId(author_id)})
        flash('Author deleted successfully', 'success')
    return redirect(url_for('manage_author'))


@app.route('/view_registered_author')
@login_required
def view_registered_author():
    if current_user.is_authenticated:
        user = users_collection.find_one({"email": session['email']})
        authors = authors_collection.find()
        return render_template('view_registered_author.html', authors=authors,
                               user_name=user['username'],
                               email=user['email'])
    else:
        return redirect(url_for('index'))
    
@app.route('/issue_book', methods=['GET', 'POST'])
@login_required
def issue_book():
    user = users_collection.find_one({"email": session['email']})
    authors = authors_collection.find()
    users = users_collection.find()
    books = books_collection.find()
    current_date = datetime.now().strftime('%Y-%m-%d')
    if request.method == 'POST':
        book_name = request.form['book_name']
        book_author = request.form['book_author']
        student_name = request.form['student_name']
        issue_date = request.form['issue_date']
        student = users_collection.find_one({"username": student_name})
        if student:
            issued_books_collection.insert_one({
                "book_name": book_name,
                "book_author": book_author,
                "book_name": book_name,
                "student_id": student["_id"],
                "issue_date": issue_date
            })
            
            flash("Book issued successfully!", 'success')
            return redirect(url_for('issue_book'))
        else:
            flash('Student does not exist', 'danger')

    # For GET request, render the form
    return render_template('issue_book.html',
                            authors=authors,
                            books=books,
                            users=users,
                            current_date=current_date,
                            user_name=user['username'],
                            email=user['email'])

if __name__ == '__main__':
    create_admin_user()
    app.secret_key = os.urandom(24)
    app.run(debug=True)
