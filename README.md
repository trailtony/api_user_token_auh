# Authenticate Users with FastAPI and Token Authentication
- A quick step by step on how to authenticate users with FastAPI and Token Authentication.
- Based on FASTAPI documentation website: https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/#hash-and-verify-the-passwords.
- Based on TWT's video tutorial https://www.youtube.com/watch?v=5GxQ1rLTwaU

## Setup uvicorn development server
- Run the following command to startup application: 
    $ uvicorn main: app --reload
- Open web page http://localhost:8000/docs to see your API root endpoints.
 
## Mock data
- Mock DB and API configuration variables are explicitly available inside main.py for example purposes.

## Errors on passlib due to bcrypt's newer versions
-  bcrypt's version has to be pinned at older versions until they fix a "AttributeError: module 'bcrypt' has no attribute '__about__'" bug in passlib package.