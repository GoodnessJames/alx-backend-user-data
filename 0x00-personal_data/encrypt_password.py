#!/usr/bin/env python3
"""Encrypting passwords with bcrypt"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Takes in string arg and converts to unicode"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if hashed and unhashed pswds are same"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
