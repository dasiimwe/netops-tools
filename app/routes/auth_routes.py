from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.routes import auth_bp
from app.models import db, User, AuditLog
from app.auth import authenticate_user, create_local_user, validate_password_strength
from datetime import datetime
from sqlalchemy import or_, desc, asc

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        auth_type = request.form.get('auth_type', 'local')
        
        user = authenticate_user(username, password, auth_type)
        
        if user:
            login_user(user, remember=request.form.get('remember'))
            
            # Log successful login
            audit_log = AuditLog(
                user_id=user.id,
                action='login',
                details=f'User logged in via {auth_type}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        else:
            flash('Invalid username or password', 'danger')
            
            # Log failed login attempt
            audit_log = AuditLog(
                action='failed_login',
                details=f'Failed login attempt for username: {username} via {auth_type}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    # Log logout
    audit_log = AuditLog(
        user_id=current_user.id,
        action='logout',
        details='User logged out',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            # Validate password strength
            is_valid, errors = validate_password_strength(password)
            if not is_valid:
                for error in errors:
                    flash(error, 'danger')
            else:
                try:
                    user = create_local_user(username, password, email, is_admin)
                    
                    # Log user creation
                    audit_log = AuditLog(
                        user_id=current_user.id,
                        action='user_created',
                        details=f'Created user: {username}',
                        ip_address=request.remote_addr
                    )
                    db.session.add(audit_log)
                    db.session.commit()
                    
                    flash(f'User {username} created successfully', 'success')
                    return redirect(url_for('auth.users'))
                except ValueError as e:
                    flash(str(e), 'danger')
                except Exception as e:
                    flash(f'Error creating user: {str(e)}', 'danger')
    
    return render_template('auth/register.html')

@auth_bp.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))

    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'username')
    sort_order = request.args.get('sort_order', 'asc')
    status_filter = request.args.get('status', '')
    role_filter = request.args.get('role', '')
    auth_type_filter = request.args.get('auth_type', '')

    # Validate per_page limits
    if per_page not in [5, 10, 25, 50, 100]:
        per_page = 10

    # Validate sort_by field
    valid_sort_fields = ['username', 'email', 'auth_type', 'is_admin', 'is_active', 'created_at', 'last_login']
    if sort_by not in valid_sort_fields:
        sort_by = 'username'

    # Validate sort_order
    if sort_order not in ['asc', 'desc']:
        sort_order = 'asc'

    # Start building the query
    query = User.query

    # Apply search filter
    if search:
        search_filter = or_(
            User.username.ilike(f'%{search}%'),
            User.email.ilike(f'%{search}%')
        )
        query = query.filter(search_filter)

    # Apply status filter
    if status_filter == 'active':
        query = query.filter(User.is_active == True)
    elif status_filter == 'inactive':
        query = query.filter(User.is_active == False)

    # Apply role filter
    if role_filter == 'admin':
        query = query.filter(User.is_admin == True)
    elif role_filter == 'user':
        query = query.filter(User.is_admin == False)

    # Apply auth type filter
    if auth_type_filter in ['local', 'tacacs']:
        query = query.filter(User.auth_type == auth_type_filter)

    # Apply sorting
    sort_column = getattr(User, sort_by)
    if sort_order == 'desc':
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    # Apply pagination
    users_paginated = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    # Get statistics for all users (not just filtered)
    total_users = User.query.count()
    admin_users = User.query.filter_by(is_admin=True).count()
    active_users = User.query.filter_by(is_active=True).count()
    tacacs_users = User.query.filter_by(auth_type='tacacs').count()

    return render_template('auth/users.html',
                         users=users_paginated.items,
                         pagination=users_paginated,
                         search=search,
                         sort_by=sort_by,
                         sort_order=sort_order,
                         status_filter=status_filter,
                         role_filter=role_filter,
                         auth_type_filter=auth_type_filter,
                         per_page=per_page,
                         total_users=total_users,
                         admin_users=admin_users,
                         active_users=active_users,
                         tacacs_users=tacacs_users)

@auth_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.is_admin = request.form.get('is_admin') == 'on'

        # Only allow changing is_active status when not editing your own account
        # (disabled checkboxes don't get submitted in forms)
        if user.id != current_user.id:
            user.is_active = request.form.get('is_active') == 'on'
        
        # Update password if provided (only for local users)
        new_password = request.form.get('new_password')
        if new_password and user.auth_type == 'local':
            is_valid, errors = validate_password_strength(new_password)
            if not is_valid:
                for error in errors:
                    flash(error, 'danger')
                return render_template('auth/edit_user.html', user=user)
            
            user.set_password(new_password)
        
        try:
            db.session.commit()
            
            # Log user update
            audit_log = AuditLog(
                user_id=current_user.id,
                action='user_updated',
                details=f'Updated user: {user.username}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            flash(f'User {user.username} updated successfully', 'success')
            return redirect(url_for('auth.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')
    
    return render_template('auth/edit_user.html', user=user)

@auth_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deletion of current user
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('auth.users'))
    
    # Prevent deletion of last admin user
    admin_count = User.query.filter_by(is_admin=True).count()
    if user.is_admin and admin_count <= 1:
        flash('Cannot delete the last admin user', 'danger')
        return redirect(url_for('auth.users'))
    
    username = user.username
    
    try:
        # Log user deletion
        audit_log = AuditLog(
            user_id=current_user.id,
            action='user_deleted',
            details=f'Deleted user: {username}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User {username} deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('auth.users'))

@auth_bp.route('/users/<int:user_id>/toggle_status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deactivating current user
    if user.id == current_user.id:
        flash('Cannot deactivate your own account', 'danger')
        return redirect(url_for('auth.users'))
    
    # Prevent deactivating last admin user
    if user.is_admin and user.is_active:
        active_admin_count = User.query.filter_by(is_admin=True, is_active=True).count()
        if active_admin_count <= 1:
            flash('Cannot deactivate the last active admin user', 'danger')
            return redirect(url_for('auth.users'))
    
    try:
        user.is_active = not user.is_active
        
        # Log status change
        audit_log = AuditLog(
            user_id=current_user.id,
            action='user_status_changed',
            details=f'{"Activated" if user.is_active else "Deactivated"} user: {user.username}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        status = "activated" if user.is_active else "deactivated"
        flash(f'User {user.username} {status} successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user status: {str(e)}', 'danger')
    
    return redirect(url_for('auth.users'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_email':
            email = request.form.get('email')
            current_user.email = email
            db.session.commit()
            flash('Email updated successfully', 'success')
            
        elif action == 'change_password' and current_user.auth_type == 'local':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'danger')
            else:
                is_valid, errors = validate_password_strength(new_password)
                if not is_valid:
                    for error in errors:
                        flash(error, 'danger')
                else:
                    current_user.set_password(new_password)
                    db.session.commit()
                    flash('Password changed successfully', 'success')
    
    return render_template('auth/profile.html', user=current_user)