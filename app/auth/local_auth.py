from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from app.models import db, User, AuditLog
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def authenticate_local(username: str, password: str) -> User:
    """Authenticate user with local credentials"""
    user = User.query.filter_by(username=username, auth_type='local').first()
    
    if user and user.check_password(password):
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Log successful authentication
        logger.info(f"Local authentication successful for user: {username}")
        return user
    
    logger.warning(f"Local authentication failed for user: {username}")
    return None

def create_local_user(username: str, password: str, email: str = None, is_admin: bool = False) -> User:
    """Create a new local user"""
    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        raise ValueError(f"User {username} already exists")
    
    user = User(
        username=username,
        email=email,
        auth_type='local',
        is_admin=is_admin
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    logger.info(f"Created new local user: {username}")
    return user

def update_local_password(user: User, new_password: str) -> bool:
    """Update password for local user"""
    if user.auth_type != 'local':
        logger.error(f"Cannot update password for non-local user: {user.username}")
        return False
    
    user.set_password(new_password)
    db.session.commit()
    
    logger.info(f"Password updated for user: {user.username}")
    return True

def validate_password_strength(password: str) -> tuple:
    """Validate password strength"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")
    
    return len(errors) == 0, errors