import os
import sqlite3
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-in-production"
)

DATABASE = "tutor_platform.db"


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")

    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'teacher', 'admin')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS teacher_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            bio TEXT,
            subjects TEXT,
            qualification TEXT,
            experience INTEGER DEFAULT 0,
            location TEXT,
            teaching_mode TEXT DEFAULT 'Online',
            hourly_rate REAL DEFAULT 0,
            phone TEXT,
            profile_image TEXT,
            approved INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            subject TEXT NOT NULL,
            level TEXT,
            mode TEXT DEFAULT 'Online',
            duration TEXT,
            price REAL DEFAULT 0,
            approved INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            course_id INTEGER,
            session_type TEXT NOT NULL,
            session_date TEXT NOT NULL,
            session_time TEXT NOT NULL,
            duration INTEGER DEFAULT 1,
            message TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE SET NULL
        );
    """)

    # Create default admin account
    admin = db.execute(
        "SELECT id FROM users WHERE email = ?",
        ("admin@tutorconnect.com",)
    ).fetchone()

    if not admin:
        db.execute("""
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, ?)
        """, (
            "Administrator",
            "admin@tutorconnect.com",
            generate_password_hash("Admin@123"),
            "admin"
        ))

    db.commit()
    db.close()


# --------------------------------------------------
# AUTHENTICATION HELPERS
# --------------------------------------------------

@app.context_processor
def inject_user():
    return {
        "current_user": session.get("user"),
        "current_role": session.get("role")
    }


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))

            if session.get("role") != role:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("index"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def index():
    db = get_db()

    tutors = db.execute("""
        SELECT
            u.id,
            u.name,
            tp.bio,
            tp.subjects,
            tp.qualification,
            tp.experience,
            tp.location,
            tp.teaching_mode,
            tp.hourly_rate
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.role = 'teacher'
        AND tp.approved = 1
        ORDER BY u.created_at DESC
        LIMIT 6
    """).fetchall()

    return render_template("index.html", tutors=tutors)


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]

        if role not in ["student", "teacher"]:
            flash("Invalid account type.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "danger")
            return redirect(url_for("register"))

        db = get_db()

        try:
            cursor = db.execute("""
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                generate_password_hash(password),
                role
            ))

            user_id = cursor.lastrowid

            if role == "teacher":
                db.execute("""
                    INSERT INTO teacher_profiles (
                        user_id, bio, subjects, qualification,
                        experience, location, teaching_mode, hourly_rate
                    )
                    VALUES (?, '', '', '', 0, '', 'Online', 0)
                """, (user_id,))

            db.commit()

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "danger")

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user"] = user["name"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "teacher":
                return redirect(url_for("teacher_dashboard"))
            else:
                return redirect(url_for("student_dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# --------------------------------------------------
# STUDENT: VIEW TUTORS
# --------------------------------------------------

@app.route("/tutors")
def tutors():
    db = get_db()

    search = request.args.get("search", "").strip()
    subject = request.args.get("subject", "").strip()

    query = """
        SELECT
            u.id,
            u.name,
            tp.bio,
            tp.subjects,
            tp.qualification,
            tp.experience,
            tp.location,
            tp.teaching_mode,
            tp.hourly_rate
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.role = 'teacher'
        AND tp.approved = 1
    """

    params = []

    if search:
        query += """
            AND (
                u.name LIKE ?
                OR tp.subjects LIKE ?
                OR tp.location LIKE ?
            )
        """
        keyword = f"%{search}%"
        params.extend([keyword, keyword, keyword])

    if subject:
        query += " AND tp.subjects LIKE ?"
        params.append(f"%{subject}%")

    query += " ORDER BY u.name ASC"

    tutor_list = db.execute(query, params).fetchall()

    return render_template(
        "tutors.html",
        tutors=tutor_list,
        search=search,
        subject=subject
    )


# --------------------------------------------------
# STUDENT: VIEW TEACHER PROFILE
# --------------------------------------------------

@app.route("/tutor/<int:teacher_id>")
def tutor_detail(teacher_id):
    db = get_db()

    teacher = db.execute("""
        SELECT
            u.id,
            u.name,
            u.email,
            tp.*
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.id = ?
        AND u.role = 'teacher'
        AND tp.approved = 1
    """, (teacher_id,)).fetchone()

    if not teacher:
        flash("Tutor not found or not approved.", "danger")
        return redirect(url_for("tutors"))

    courses = db.execute("""
        SELECT *
        FROM courses
        WHERE teacher_id = ?
        AND approved = 1
        ORDER BY created_at DESC
    """, (teacher_id,)).fetchall()

    return render_template(
        "tutor_detail.html",
        teacher=teacher,
        courses=courses
    )


# --------------------------------------------------
# STUDENT DASHBOARD
# --------------------------------------------------

@app.route("/student/dashboard")
@role_required("student")
def student_dashboard():
    db = get_db()

    bookings = db.execute("""
        SELECT
            b.*,
            u.name AS teacher_name,
            c.title AS course_title
        FROM bookings b
        JOIN users u ON b.teacher_id = u.id
        LEFT JOIN courses c ON b.course_id = c.id
        WHERE b.student_id = ?
        ORDER BY b.session_date DESC, b.session_time DESC
    """, (session["user_id"],)).fetchall()

    return render_template(
        "student_dashboard.html",
        bookings=bookings
    )


# --------------------------------------------------
# BOOK SESSION
# --------------------------------------------------

@app.route("/book/<int:teacher_id>", methods=["GET", "POST"])
@login_required
def book_session(teacher_id):
    if session.get("role") != "student":
        flash("Only students can book sessions.", "danger")
        return redirect(url_for("index"))

    db = get_db()

    teacher = db.execute("""
        SELECT
            u.id,
            u.name,
            tp.*
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.id = ?
        AND u.role = 'teacher'
        AND tp.approved = 1
    """, (teacher_id,)).fetchone()

    if not teacher:
        flash("Tutor not found.", "danger")
        return redirect(url_for("tutors"))

    courses = db.execute("""
        SELECT *
        FROM courses
        WHERE teacher_id = ?
        AND approved = 1
    """, (teacher_id,)).fetchall()

    if request.method == "POST":
        course_id = request.form.get("course_id") or None
        session_type = request.form["session_type"]
        session_date = request.form["session_date"]
        session_time = request.form["session_time"]
        duration = int(request.form["duration"])
        message = request.form.get("message", "").strip()

        if duration not in [1, 2]:
            flash("Duration must be 1 or 2 hours.", "danger")
            return redirect(url_for("book_session", teacher_id=teacher_id))

        db.execute("""
            INSERT INTO bookings (
                student_id, teacher_id, course_id,
                session_type, session_date, session_time,
                duration, message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            teacher_id,
            course_id,
            session_type,
            session_date,
            session_time,
            duration,
            message
        ))

        db.commit()

        flash("Booking request submitted successfully.", "success")
        return redirect(url_for("student_dashboard"))

    return render_template(
        "book_session.html",
        teacher=teacher,
        courses=courses
    )


# --------------------------------------------------
# TEACHER DASHBOARD
# --------------------------------------------------

@app.route("/teacher/dashboard")
@role_required("teacher")
def teacher_dashboard():
    db = get_db()
    teacher_id = session["user_id"]

    profile = db.execute("""
        SELECT
            u.name,
            u.email,
            tp.*
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.id = ?
    """, (teacher_id,)).fetchone()

    courses = db.execute("""
        SELECT *
        FROM courses
        WHERE teacher_id = ?
        ORDER BY created_at DESC
    """, (teacher_id,)).fetchall()

    bookings = db.execute("""
        SELECT
            b.*,
            u.name AS student_name,
            u.email AS student_email,
            c.title AS course_title
        FROM bookings b
        JOIN users u ON b.student_id = u.id
        LEFT JOIN courses c ON b.course_id = c.id
        WHERE b.teacher_id = ?
        ORDER BY b.session_date ASC, b.session_time ASC
    """, (teacher_id,)).fetchall()

    return render_template(
        "teacher_dashboard.html",
        profile=profile,
        courses=courses,
        bookings=bookings
    )


# --------------------------------------------------
# TEACHER: UPDATE PROFILE
# --------------------------------------------------

@app.route("/teacher/profile", methods=["GET", "POST"])
@role_required("teacher")
def teacher_profile():
    db = get_db()
    teacher_id = session["user_id"]

    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        subjects = request.form.get("subjects", "").strip()
        qualification = request.form.get("qualification", "").strip()
        experience = request.form.get("experience", 0)
        location = request.form.get("location", "").strip()
        teaching_mode = request.form.get("teaching_mode", "Online")
        hourly_rate = request.form.get("hourly_rate", 0)
        phone = request.form.get("phone", "").strip()

        try:
            experience = int(experience)
            hourly_rate = float(hourly_rate)
        except ValueError:
            flash("Experience and hourly rate must be valid numbers.", "danger")
            return redirect(url_for("teacher_profile"))

        db.execute("""
            UPDATE teacher_profiles
            SET bio = ?,
                subjects = ?,
                qualification = ?,
                experience = ?,
                location = ?,
                teaching_mode = ?,
                hourly_rate = ?,
                phone = ?
            WHERE user_id = ?
        """, (
            bio,
            subjects,
            qualification,
            experience,
            location,
            teaching_mode,
            hourly_rate,
            phone,
            teacher_id
        ))

        db.commit()

        flash(
            "Profile updated. If this is your first submission, wait for admin approval.",
            "success"
        )
        return redirect(url_for("teacher_dashboard"))

    profile = db.execute("""
        SELECT
            u.name,
            u.email,
            tp.*
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.id = ?
    """, (teacher_id,)).fetchone()

    return render_template("teacher_profile.html", profile=profile)


# --------------------------------------------------
# TEACHER: ADD COURSE
# --------------------------------------------------

@app.route("/teacher/course/add", methods=["GET", "POST"])
@role_required("teacher")
def add_course():
    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        subject = request.form["subject"].strip()
        level = request.form["level"].strip()
        mode = request.form["mode"]
        duration = request.form["duration"].strip()
        price = request.form["price"]

        try:
            price = float(price)
        except ValueError:
            flash("Please enter a valid price.", "danger")
            return redirect(url_for("add_course"))

        db = get_db()

        db.execute("""
            INSERT INTO courses (
                teacher_id, title, description, subject,
                level, mode, duration, price, approved
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (
            session["user_id"],
            title,
            description,
            subject,
            level,
            mode,
            duration,
            price
        ))

        db.commit()

        flash("Course submitted for admin approval.", "success")
        return redirect(url_for("teacher_dashboard"))

    return render_template("add_course.html")


# --------------------------------------------------
# TEACHER: UPDATE BOOKING STATUS
# --------------------------------------------------

@app.route("/teacher/booking/<int:booking_id>/<action>")
@role_required("teacher")
def update_booking(booking_id, action):
    if action not in ["Accepted", "Rejected", "Completed"]:
        flash("Invalid booking action.", "danger")
        return redirect(url_for("teacher_dashboard"))

    db = get_db()

    db.execute("""
        UPDATE bookings
        SET status = ?
        WHERE id = ?
        AND teacher_id = ?
    """, (
        action,
        booking_id,
        session["user_id"]
    ))

    db.commit()

    flash(f"Booking marked as {action}.", "success")
    return redirect(url_for("teacher_dashboard"))


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    db = get_db()

    pending_teachers = db.execute("""
        SELECT
            u.id,
            u.name,
            u.email,
            u.created_at,
            tp.*
        FROM users u
        JOIN teacher_profiles tp ON u.id = tp.user_id
        WHERE u.role = 'teacher'
        AND tp.approved = 0
        ORDER BY u.created_at DESC
    """).fetchall()

    pending_courses = db.execute("""
        SELECT
            c.*,
            u.name AS teacher_name
        FROM courses c
        JOIN users u ON c.teacher_id = u.id
        WHERE c.approved = 0
        ORDER BY c.created_at DESC
    """).fetchall()

    all_bookings = db.execute("""
        SELECT
            b.*,
            s.name AS student_name,
            t.name AS teacher_name
        FROM bookings b
        JOIN users s ON b.student_id = s.id
        JOIN users t ON b.teacher_id = t.id
        ORDER BY b.created_at DESC
    """).fetchall()

    stats = {
        "students": db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'student'"
        ).fetchone()[0],
        "teachers": db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'teacher'"
        ).fetchone()[0],
        "courses": db.execute(
            "SELECT COUNT(*) FROM courses"
        ).fetchone()[0],
        "bookings": db.execute(
            "SELECT COUNT(*) FROM bookings"
        ).fetchone()[0]
    }

    return render_template(
        "admin_dashboard.html",
        pending_teachers=pending_teachers,
        pending_courses=pending_courses,
        all_bookings=all_bookings,
        stats=stats
    )


# --------------------------------------------------
# ADMIN: APPROVE TEACHER
# --------------------------------------------------

@app.route("/admin/teacher/<int:teacher_id>/<action>")
@role_required("admin")
def admin_teacher_action(teacher_id, action):
    if action not in ["approve", "reject"]:
        flash("Invalid action.", "danger")
        return redirect(url_for("admin_dashboard"))

    db = get_db()

    approved = 1 if action == "approve" else 0

    db.execute("""
        UPDATE teacher_profiles
        SET approved = ?
        WHERE user_id = ?
    """, (approved, teacher_id))

    db.commit()

    flash(f"Teacher profile {action}d successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# ADMIN: APPROVE COURSE
# --------------------------------------------------

@app.route("/admin/course/<int:course_id>/<action>")
@role_required("admin")
def admin_course_action(course_id, action):
    if action not in ["approve", "reject"]:
        flash("Invalid action.", "danger")
        return redirect(url_for("admin_dashboard"))

    db = get_db()

    approved = 1 if action == "approve" else 0

    db.execute("""
        UPDATE courses
        SET approved = ?
        WHERE id = ?
    """, (approved, course_id))

    db.commit()

    flash(f"Course {action}d successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":
    with app.app_context():
        init_db()

    app.run(debug=True)