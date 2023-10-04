from rest_framework_simplejwt.authentication import JWTAuthentication
from functools import wraps

JWT_authenticator = JWTAuthentication()

def jwt_auth_check(func):
    @wraps(func)
    def _wrapper(*args, **kwargs):
        
        response = JWT_authenticator.authenticate(args[1])
        if response is not None:
            # unpacking
            _, token = response
            
            print("this is decoded token claims", token.payload)
            return func(*args, **kwargs)
        else:
            print("no token is provided in the header or the header is missing")

    return _wrapper