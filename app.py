from flask import Flask, render_template, send_from_directory, redirect, request, session, url_for, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import datetime  # Import datetime for blog post timestamps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # Use environment variable for secret key
bcrypt = Bcrypt(app)

# MongoDB Configuration
mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(mongo_uri)
db = client.ivelosi  # Database name
users_collection = db.users  # Collection for users
contacts_collection = db.contacts  # Collection for contacts
blog_posts_collection = db.blog_posts  # Collection for blog posts

# AES Encryption Key (32 bytes for AES-256)
AES_KEY = os.getenv("AES_KEY", "supersecretaeskey1234567890123456").encode()

# AES Encryption Functions
def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_data(iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Serve static files
@app.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates/css'), filename)

@app.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates/js'), filename)

@app.route('/img/<path:filename>')
def serve_images(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates/img'), filename)

@app.route('/lib/<path:filename>')
def serve_lib(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates/lib'), filename)

@app.route('/scss/<path:filename>')
def serve_scss(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates/scss'), filename)

@app.context_processor
def inject_user():
    return dict(logged_in="user_id" in session)

# Redirect .html URLs to clean versions
@app.route('/<path:filename>.html')
def remove_html_extension(filename):
    return redirect(f'/{filename}', code=301)

# Normal Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/feature')
def feature():
    return render_template('feature.html')

@app.route('/FAQ')
def FAQ():
    return render_template('FAQ.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# Contact Form
@app.route('/send_email', methods=['POST'])
def send_email():
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        project = request.form.get('project')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # Encrypt sensitive data
        iv_email, encrypted_email = encrypt_data(email)
        iv_phone, encrypted_phone = encrypt_data(phone)

        contact_data = {
            "name": name,
            "email": f"{iv_email}:{encrypted_email}",
            "phone": f"{iv_phone}:{encrypted_phone}",
            "project": project,
            "subject": subject,
            "message": message
        }
        contacts_collection.insert_one(contact_data)

        return redirect("/success")

    except Exception as e:
        return f"Error: {str(e)}"

# Authentication Routes
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")

        # Check if email already exists
        if users_collection.find_one({"email": email}):
            flash("Email already exists. Try another email.", "error")
            return redirect("/register")

        # Create new user
        user_data = {
            "name": name,
            "email": email,
            "password": password,
            "profile_picture": "",  # Default profile picture
            "bio": ""  # Default bio
        }
        users_collection.insert_one(user_data)

        flash("Registration successful! Please log in.", "success")
        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Check if the user is an admin
        if email == "jaiminpansal@gmail.com" and password == "jai":
            session["user_id"] = "admin"
            session["user_name"] = "Admin"
            session["user_role"] = "admin"  # Set role as admin
            return redirect("/admin")

        # Check normal user authentication
        user = users_collection.find_one({"email": email})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["user_id"] = str(user["_id"])
            session["user_name"] = user["name"]
            session["user_role"] = "user"  # Set role as user
            return redirect("/dashboard")
        else:
            flash("Invalid credentials.", "error")

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" in session:
        return render_template("dashboard.html", name=session["user_name"])
    return redirect("/login")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect("/")

# My Profile
@app.route("/myprofile", methods=["GET", "POST"])
def myprofile():
    if "user_id" not in session:
        return redirect("/login")

    # Handle admin user
    if session["user_id"] == "admin":
        user = {"name": "Admin", "email": "jaiminpansal@gmail.com", "bio": "", "profile_picture": ""}  # Mock admin data
    else:
        # Handle regular users
        user = users_collection.find_one({"_id": ObjectId(session["user_id"])})

    if request.method == "POST":
        name = request.form.get("name")
        bio = request.form.get("bio")
        profile_picture = request.form.get("profile_picture")

        if session["user_id"] == "admin":
            # Admin profile cannot be updated in this example
            flash("Admin profile cannot be updated.", "warning")
        else:
            users_collection.update_one(
                {"_id": ObjectId(session["user_id"])},
                {"$set": {"name": name, "bio": bio, "profile_picture": profile_picture}}
            )
            flash("Profile updated successfully!", "success")

        return redirect("/myprofile")

    return render_template("myprofile.html", user=user)

# Account Settings
@app.route("/account_settings", methods=["GET", "POST"])
def account_settings():
    if "user_id" not in session:
        return redirect("/login")

    # Handle admin user
    if session["user_id"] == "admin":
        user = {"name": "Admin", "email": "jaiminpansal@gmail.com"}  # Mock admin data
    else:
        # Handle regular users
        user = users_collection.find_one({"_id": ObjectId(session["user_id"])})

    if request.method == "POST":
        new_email = request.form.get("email")
        new_password = request.form.get("password")

        if new_email:
            if session["user_id"] == "admin":
                # Admin email cannot be changed in this example
                flash("Admin email cannot be changed.", "warning")
            else:
                users_collection.update_one(
                    {"_id": ObjectId(session["user_id"])},
                    {"$set": {"email": new_email}}
                )
                flash("Email updated successfully!", "success")

        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
            if session["user_id"] == "admin":
                # Admin password cannot be changed in this example
                flash("Admin password cannot be changed.", "warning")
            else:
                users_collection.update_one(
                    {"_id": ObjectId(session["user_id"])},
                    {"$set": {"password": hashed_password}}
                )
                flash("Password updated successfully!", "success")

        return redirect("/account_settings")

    return render_template("account_settings.html", user=user)

# Admin Panel
@app.route('/admin')
def admin():
    if session.get("user_id") != "admin":
        flash("Unauthorized access.", "error")
        return redirect("/login")

    submissions = list(contacts_collection.find())
    return render_template("admin.html", submissions=submissions)

# Blog Routes
@app.route("/admin/create_blog", methods=["GET", "POST"])
def create_blog():
    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect("/login")

    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        author = request.form.get("author")
        image_url = request.form.get("image_url")
        category = request.form.get("category", "Uncategorized")
        description = request.form.get("description", "")

        # Generate a unique filename for the blog post
        filename = f"blog_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.html"
        filepath = os.path.join(app.root_path, "templates", "blog_posts", filename)
        print(f"Filepath: {filepath}")  # Debugging: Print the file path

        # Create the blog post HTML file
        blog_html = f"""
        {{% extends 'base.html' %}}

        {{% block title %}}{title} - Ivelosi{{% endblock %}}

        {{% block content %}}
        <div class="container">
            <h1 class="text-center my-4">{title}</h1>
            <div class="row">
                <div class="col-md-8 mx-auto">
                    <img src="{image_url}" class="img-fluid rounded mb-4" alt="{title}">
                    <p class="lead">{description}</p>
                    <div class="content">
                        {content}
                    </div>
                    <p class="text-muted mt-4">Author: {author}</p>
                    <p class="text-muted">Published on: {datetime.datetime.utcnow().strftime('%d %B, %Y')}</p>
                </div>
            </div>
        </div>
        {{% endblock %}}
        """

        # Ensure the directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        print(f"Directory created: {os.path.dirname(filepath)}")  # Debugging: Print the directory path

        # Save the HTML file with UTF-8 encoding
        try:
            with open(filepath, "w", encoding="utf-8") as file:
                file.write(blog_html)
            print(f"File created: {filepath}")  # Debugging: Confirm file creation
        except Exception as e:
            print(f"Error writing file: {e}")  # Debugging: Print the error
            flash("Error creating blog post file.", "error")
            return redirect("/admin/create_blog")

        # Save the blog post data to MongoDB
        blog_post = {
            "title": title,
            "content": content,
            "author": author,
            "image_url": image_url,
            "category": category,
            "description": description,
            "timestamp": datetime.datetime.utcnow(),
            "filepath": f"blog_posts/{filename}"  # Store the file path
        }
        blog_posts_collection.insert_one(blog_post)

        flash("Blog post created successfully!", "success")
        return redirect("/admin/blog")

    return render_template("create_blog.html")

@app.route("/admin/edit_blog/<post_id>", methods=["GET", "POST"])
def edit_blog(post_id):
    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect("/login")

    post = blog_posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post:
        flash("Blog post not found.", "error")
        return redirect("/admin/blog")

    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        image_url = request.form.get("image_url")

        blog_posts_collection.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": {"title": title, "content": content, "image_url": image_url}}
        )
        flash("Blog post updated successfully!", "success")
        return redirect("/admin/blog")

    return render_template("edit_blog.html", post=post)

@app.route("/admin/delete_blog/<post_id>", methods=["POST"])
def delete_blog(post_id):
    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect("/login")

    blog_posts_collection.delete_one({"_id": ObjectId(post_id)})
    flash("Blog post deleted successfully!", "success")
    return redirect("/admin/blog")

@app.route("/blog")
def blog():
    posts = list(blog_posts_collection.find().sort("timestamp", -1))  # Sort by latest first
    return render_template("blog.html", posts=posts)

@app.route("/blog/<path:filename>")
def blog_post(filename):
    try:
        # Ensure the filename does not include the 'blog_posts/' prefix
        if filename.startswith("blog_posts/"):
            filename = filename[len("blog_posts/"):]
        
        print(f"Rendering blog post: blog_posts/{filename}")  # Debugging: Print the file being accessed
        return render_template(f"blog_posts/{filename}")
    except Exception as e:
        print(f"Error rendering blog post: {e}")  # Debugging: Print the error
        return render_template("404.html"), 404
    
@app.route("/admin/blog")
def admin_blog():
    if "user_id" not in session or session.get("user_role") != "admin":
        return redirect("/login")

    posts = list(blog_posts_collection.find().sort("timestamp", -1))
    return render_template("admin_blog.html", posts=posts)

# 404 Page
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=5000)  # Set debug=False in production
