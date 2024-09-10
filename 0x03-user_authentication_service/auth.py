#!/usr/bin/env python3
"""Module for the Auth"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> bytes:
    """
    Returns a salted hash of the input password, hashed with bcrypt
    """
    if not password:
        return
    encoded_password = password.encode('UTF-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(encoded_password, salt)
    return hashed_password


def _generate_uuid() -> str:
    """Returns a string representation of a new UUID"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers new user to the DB"""
        try:
            if self._db.find_user_by(email=email):
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates the if the user exists"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        encoded_password = password.encode('UTF-8')
        if bcrypt.checkpw(encoded_password, user.hashed_password):
            return True
        return False

    def create_session(self, email: str) -> str:
        """Returns the session ID as a string"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_uuid = _generate_uuid()

        user.session_id = session_uuid
        self._db.update_user(user.id)

        return session_uuid

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Finds the user by session ID and returns the user"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Finds user by user ID and destroys the session"""
        if user_id is None or not isinstance(user_id, int):
            raise ValueError
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token"""
        if email is None or not isinstance(email, str):
            raise ValueError("Invalid email")

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("User not found")

        reset_token = str(uuid4())
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the password for a user using a reset token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        encoded_password = password.encode('UTF-8')
        hashed_password = bcrypt.hashpw(encoded_password, bcrypt.gensalt())

        self._db.update_user(user.id, hashed_password=hashed_password,
                             reset_token=None)
        return None
