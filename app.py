# app.py
from flask import Flask, render_template, redirect, url_for, flash, request, session
import os
from datetime import datetime, timedelta
import hashlib
from dotenv import load_dotenv
import uuid

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'campus-skill-hub-secret-key-2024')

# Supabase configuration
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

print(f"Supabase URL: {SUPABASE_URL}")
print(f"Supabase Key present: {bool(SUPABASE_KEY)}")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Please set SUPABASE_URL and SUPABASE_KEY environment variables")

# Initialize Supabase
supabase = None
try:
    from supabase import create_client
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("Supabase client initialized successfully!")
except ImportError:
    print("Supabase package not installed. Please run: pip install supabase")
except Exception as e:
    print(f"Supabase initialization failed: {e}")
    supabase = None

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def safe_dict_get(data, key, default=None):
    """
    Safely get value from dictionary-like or object-like response.
    """
    if isinstance(data, dict):
        return data.get(key, default)
    if hasattr(data, 'get') and callable(getattr(data, 'get')):
        try:
            return data.get(key, default)
        except Exception:
            pass
    if hasattr(data, key):
        try:
            return getattr(data, key, default)
        except Exception:
            pass
    if isinstance(data, (list, tuple)):
        try:
            for item in data:
                if isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == key:
                    return item[1]
        except Exception:
            pass
    return default

def get_current_user():
    """Get current user from session"""
    if supabase is None:
        return None
        
    user_id = session.get('user_id')
    if user_id:
        try:
            response = supabase.table('users').select('*').eq('id', user_id).execute()
            if hasattr(response, 'data') and response.data:
                user_data = response.data[0]
                session['is_authenticated'] = True
                return user_data
        except Exception as e:
            print(f"Error fetching user: {e}")
    return None

def get_skill_categories():
    """Get all skill categories"""
    if supabase is None:
        return []
        
    try:
        response = supabase.table('skill_categories').select('*').execute()
        if hasattr(response, 'data') and response.data:
            return response.data
        return []
    except Exception as e:
        print(f"Error fetching skill categories: {e}")
        return []

# Routes
@app.route('/')
def index():
    current_user = get_current_user()
    if current_user:
        return redirect('/dashboard')
    return render_template('index.html', current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    current_user = get_current_user()
    if current_user:
        return redirect('/dashboard')
    
    if request.method == 'POST':
        identifier = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not identifier or not password:
            flash('Email/Student ID and password are required', 'danger')
            return render_template('login.html', current_user=current_user)
        
        try:
            if supabase is None:
                flash('Database connection unavailable. Please try again later.', 'danger')
                return render_template('login.html', current_user=current_user)
                
            # Find user by email or student_id
            response = supabase.table('users').select('*').or_(f"email.eq.{identifier},student_id.eq.{identifier}").execute()
            
            if hasattr(response, 'data') and response.data:
                user_data = response.data[0]
                
                password_hash = safe_dict_get(user_data, 'password_hash')
                user_id = safe_dict_get(user_data, 'id')
                
                if password_hash and password_hash == hash_password(password):
                    session['user_id'] = str(user_id)
                    session.permanent = True
                    flash('Login successful!', 'success')
                    return redirect('/dashboard')
            
            flash('Invalid email/student ID or password', 'danger')
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash(f'Login failed: {str(e)}', 'danger')
    
    return render_template('login.html', current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    current_user = get_current_user()
    if current_user:
        return redirect('/dashboard')
    
    skill_categories = get_skill_categories()
    
    if request.method == 'POST':
        student_id = request.form.get('student_id', '').strip()
        email = request.form.get('email', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        year = request.form.get('year', '').strip()
        major = request.form.get('major', '').strip()
        bio = request.form.get('bio', '').strip()
        skills = request.form.get('skills', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate required fields
        required_fields = {
            'student_id': student_id,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'year': year,
            'major': major,
            'password': password
        }
        
        for field_name, field_value in required_fields.items():
            if not field_value:
                flash(f'{field_name.replace("_", " ").title()} is required', 'danger')
                return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
        
        # Validate password confirmation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
        
        # Validate password strength
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
        
        # Validate email format
        if '@' not in email:
            flash('Please enter a valid email address', 'danger')
            return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
        
        try:
            if supabase is None:
                flash('Database connection unavailable. Please try again later.', 'danger')
                return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
                
            # Check if user exists
            email_check = supabase.table('users').select('id').eq('email', email).execute()
            student_id_check = supabase.table('users').select('id').eq('student_id', student_id).execute()
            
            if hasattr(email_check, 'data') and email_check.data:
                flash('Email already exists', 'danger')
                return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
            
            if hasattr(student_id_check, 'data') and student_id_check.data:
                flash('Student ID already exists', 'danger')
                return render_template('register.html', current_user=current_user, skill_categories=skill_categories)
            
            # Process skills into array
            skills_list = [skill.strip() for skill in skills.split(',') if skill.strip()]
            
            # Create user data
            user_data = {
                'id': str(uuid.uuid4()),
                'student_id': student_id,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'year': year,
                'major': major,
                'bio': bio,
                'skills': skills_list,
                'password_hash': hash_password(password),
                'created_at': datetime.now().isoformat()
            }
            
            print(f"Attempting to insert user: {user_data['email']}")
            
            # Insert user
            response = supabase.table('users').insert(user_data).execute()
            
            print(f"Insert response: {getattr(response, 'data', response)}")
            
            if hasattr(response, 'data') and response.data:
                flash('Registration successful! Please login.', 'success')
                return redirect('/login')
            else:
                flash('Registration failed. No data returned from database.', 'danger')
                print(f"Registration failed. Response: {response}")
                
        except Exception as e:
            error_msg = f'Registration failed: {str(e)}'
            print(f"Registration error details: {error_msg}")
            flash(error_msg, 'danger')
    
    return render_template('register.html', current_user=current_user, skill_categories=skill_categories)

@app.route('/dashboard')
def dashboard():
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    try:
        if supabase is None:
            flash('Database connection unavailable. Please try again later.', 'danger')
            return render_template('dashboard.html',
                                 current_user=current_user,
                                 my_requests=[],
                                 available_requests=[],
                                 my_connections=[],
                                 stats={'my_requests_count': 0, 'available_requests_count': 0, 'active_connections': 0, 'completed_connections': 0})
        
        user_id = safe_dict_get(current_user, 'id')
        
        # Get user's skill requests
        my_requests_response = supabase.table('skill_requests').select('*, skill_categories(name)').eq('user_id', user_id).execute()
        my_requests = my_requests_response.data if (hasattr(my_requests_response, 'data') and my_requests_response.data) else []

        # Get available requests from others
        available_requests_response = supabase.table('skill_requests').select('*, users(first_name, last_name), skill_categories(name)').eq('status', 'open').neq('user_id', user_id).execute()
        available_requests = available_requests_response.data if (hasattr(available_requests_response, 'data') and available_requests_response.data) else []

        # Get connections where user is involved
        learner_connections_response = supabase.table('connections').select('*, skill_requests(title, skill_categories(name)), users!connections_mentor_id_fkey(first_name, last_name)').eq('learner_id', user_id).execute()
        learner_connections = learner_connections_response.data if (hasattr(learner_connections_response, 'data') and learner_connections_response.data) else []
        
        mentor_connections_response = supabase.table('connections').select('*, skill_requests(title, skill_categories(name)), users!connections_learner_id_fkey(first_name, last_name)').eq('mentor_id', user_id).execute()
        mentor_connections = mentor_connections_response.data if (hasattr(mentor_connections_response, 'data') and mentor_connections_response.data) else []

        my_connections = learner_connections + mentor_connections

        # Get user stats
        stats = {
            'my_requests_count': len(my_requests),
            'available_requests_count': len(available_requests),
            'active_connections': len([c for c in my_connections if safe_dict_get(c, 'status') in ['pending', 'accepted']]),
            'completed_connections': len([c for c in my_connections if safe_dict_get(c, 'status') == 'completed'])
        }

        return render_template('dashboard.html',
                             current_user=current_user,
                             my_requests=my_requests,
                             available_requests=available_requests,
                             my_connections=my_connections,
                             stats=stats)
    except Exception as e:
        flash('Error loading dashboard', 'danger')
        print(f"Dashboard error: {e}")
        return redirect('/')

@app.route('/create_request', methods=['GET', 'POST'])
def create_request():
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    skill_categories = get_skill_categories()
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        skill_category_name = request.form.get('skill_category', '').strip()  # Changed to match form
        urgency_level = request.form.get('urgency_level', 'medium')
        
        if not title or not description or not skill_category_name:
            flash('Title, description, and skill category are required', 'danger')
            return render_template('create_request.html', current_user=current_user, skill_categories=skill_categories)
        
        try:
            if supabase is None:
                flash('Database connection unavailable. Please try again later.', 'danger')
                return render_template('create_request.html', current_user=current_user, skill_categories=skill_categories)
            
            # Get or create skill category ID
            skill_category_id = None
            
            # First, try to find existing category
            category_response = supabase.table('skill_categories').select('id').eq('name', skill_category_name).execute()
            if hasattr(category_response, 'data') and category_response.data:
                skill_category_id = category_response.data[0]['id']
            else:
                # Create new category if it doesn't exist
                new_category_data = {
                    'id': str(uuid.uuid4()),
                    'name': skill_category_name,
                    'description': f'Category for {skill_category_name} skills',
                    'created_at': datetime.now().isoformat()
                }
                new_category_response = supabase.table('skill_categories').insert(new_category_data).execute()
                if hasattr(new_category_response, 'data') and new_category_response.data:
                    skill_category_id = new_category_response.data[0]['id']
            
            if not skill_category_id:
                flash('Failed to create skill category. Please try again.', 'danger')
                return render_template('create_request.html', current_user=current_user, skill_categories=skill_categories)
                
            request_data = {
                'id': str(uuid.uuid4()),
                'user_id': safe_dict_get(current_user, 'id'),
                'title': title,
                'description': description,
                'skill_category_id': skill_category_id,
                'urgency_level': urgency_level,
                'status': 'open',
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=30)).isoformat()
            }
            
            response = supabase.table('skill_requests').insert(request_data).execute()
            
            if hasattr(response, 'data') and response.data:
                flash('Skill request created successfully! Others can now offer to help.', 'success')
                return redirect('/dashboard')
            else:
                flash('Failed to create request. Please try again.', 'danger')
                
        except Exception as e:
            flash('Failed to create request. Please try again.', 'danger')
            print(f"Create request error: {e}")
    
    return render_template('create_request.html', current_user=current_user, skill_categories=skill_categories)

@app.route('/help_request/<request_id>', methods=['POST'])
def help_request(request_id):
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    try:
        if supabase is None:
            flash('Database connection unavailable. Please try again later.', 'danger')
            return redirect('/dashboard')
            
        # Check if request exists and is open
        request_response = supabase.table('skill_requests').select('*, users(first_name, last_name)').eq('id', request_id).eq('status', 'open').execute()
        if not (hasattr(request_response, 'data') and request_response.data):
            flash('Request not found or already accepted.', 'danger')
            return redirect('/dashboard')
        
        skill_request = request_response.data[0]
        
        # Check if current user is trying to help their own request
        request_user_id = safe_dict_get(skill_request, 'user_id')
        if request_user_id == safe_dict_get(current_user, 'id'):
            flash('You cannot help with your own request.', 'warning')
            return redirect('/dashboard')
        
        # Check if already connected
        existing_connection = supabase.table('connections').select('*').eq('request_id', request_id).in_('status', ['pending', 'accepted']).execute()
        if hasattr(existing_connection, 'data') and existing_connection.data:
            flash('Someone else is already helping with this request.', 'warning')
            return redirect('/dashboard')
        
        # Create connection
        connection_data = {
            'id': str(uuid.uuid4()),
            'request_id': request_id,
            'learner_id': request_user_id,
            'mentor_id': safe_dict_get(current_user, 'id'),
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        response = supabase.table('connections').insert(connection_data).execute()
        
        if hasattr(response, 'data') and response.data:
            title = safe_dict_get(skill_request, 'title', 'Unknown')
            flash(f'You have offered to help with "{title}"! Waiting for acceptance.', 'success')
        else:
            flash('Failed to offer help. Please try again.', 'danger')
            
    except Exception as e:
        flash('Failed to offer help. Please try again.', 'danger')
        print(f"Help request error: {e}")
    
    return redirect('/dashboard')

@app.route('/manage_connection/<connection_id>', methods=['POST'])
def manage_connection(connection_id):
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    action = request.form.get('action')
    
    try:
        if supabase is None:
            flash('Database connection unavailable. Please try again later.', 'danger')
            return redirect('/dashboard')
            
        connection_response = supabase.table('connections').select('*').eq('id', connection_id).execute()
        if not (hasattr(connection_response, 'data') and connection_response.data):
            flash('Connection not found.', 'danger')
            return redirect('/dashboard')
        
        connection = connection_response.data[0]
        
        # Check if user has permission
        learner_id = safe_dict_get(connection, 'learner_id')
        mentor_id = safe_dict_get(connection, 'mentor_id')
        request_id = safe_dict_get(connection, 'request_id')
        
        if action in ['accept', 'reject'] and safe_dict_get(current_user, 'id') != learner_id:
            flash('You do not have permission to manage this connection.', 'danger')
            return redirect('/dashboard')
        
        if action == 'accept':
            supabase.table('connections').update({'status': 'accepted'}).eq('id', connection_id).execute()
            supabase.table('skill_requests').update({'status': 'accepted'}).eq('id', request_id).execute()
            flash('Connection accepted! You can now chat with your helper.', 'success')
        elif action == 'reject':
            supabase.table('connections').update({'status': 'rejected'}).eq('id', connection_id).execute()
            supabase.table('skill_requests').update({'status': 'open'}).eq('id', request_id).execute()
            flash('Connection rejected.', 'info')
        elif action == 'complete':
            if safe_dict_get(current_user, 'id') not in [learner_id, mentor_id]:
                flash('You do not have permission to complete this connection.', 'danger')
                return redirect('/dashboard')
                
            supabase.table('connections').update({
                'status': 'completed', 
                'completed_at': datetime.now().isoformat()
            }).eq('id', connection_id).execute()
            supabase.table('skill_requests').update({'status': 'completed'}).eq('id', request_id).execute()
            flash('Skill exchange completed!', 'success')
        else:
            flash('Invalid action.', 'danger')
            
    except Exception as e:
        flash('Failed to manage connection. Please try again.', 'danger')
        print(f"Manage connection error: {e}")
    
    return redirect('/dashboard')

@app.route('/profile')
def profile():
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    try:
        if supabase is None:
            flash('Database connection unavailable. Please try again later.', 'danger')
            return render_template('profile.html',
                                 current_user=current_user,
                                 user_skills=[],
                                 reviews=[])
        
        # Get user's detailed information
        user_skills_response = supabase.table('user_skills').select('*').eq('user_id', safe_dict_get(current_user, 'id')).execute()
        user_skills = user_skills_response.data if (hasattr(user_skills_response, 'data') and user_skills_response.data) else []
        
        # Get user's reviews
        reviews_response = supabase.table('reviews').select('*, users!reviews_reviewer_id_fkey(first_name, last_name)').eq('reviewed_user_id', safe_dict_get(current_user, 'id')).execute()
        reviews = reviews_response.data if (hasattr(reviews_response, 'data') and reviews_response.data) else []
        
        return render_template('profile.html',
                             current_user=current_user,
                             user_skills=user_skills,
                             reviews=reviews)
    except Exception as e:
        flash('Error loading profile', 'danger')
        print(f"Profile error: {e}")
        return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_authenticated', None)
    flash('You have been logged out.', 'info')
    return redirect('/')

# Simple error handlers to avoid template errors
@app.errorhandler(404)
def not_found_error(error):
    return "<h1>404 - Page Not Found</h1><p>The page you are looking for does not exist.</p>", 404

@app.errorhandler(500)
def internal_error(error):
    return "<h1>500 - Internal Server Error</h1><p>Something went wrong on our end. Please try again later.</p>", 500

if __name__ == '__main__':
    print("Starting Campus Skill Exchange Hub...")
    print("Enhanced Database Schema Ready!")
    print("Visit: http://localhost:5000")
    print("Features: Skill Requests, Mentorship, Private Chat, Reviews")
    app.run(debug=True, host='0.0.0.0', port=5000)