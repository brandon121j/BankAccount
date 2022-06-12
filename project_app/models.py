from django.db import models
import re 
import bcrypt

class UserManager(models.Manager):
    def basic_validator(self, postData):
        errors = {}
        print(postData)
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        if not EMAIL_REGEX.match(postData['email']):            
            errors['email'] = "Invalid email address!"
        
        if len(postData['first_name']) < 2:
            errors["first_name"] = "First Name should be at least 2 characters"
        if len(postData['last_name']) < 2:
            errors["last_name"] = "Last Name should be at least 2 characters"
        if len(postData['email']) < 5:
            errors["email"] = "Email should be at least 5 characters"
        if len(postData['password']) < 8:
            errors["password"] = "Password should be at least 8 characters"

        users = User.objects.filter(email=postData['email'])  
        if users:

        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # create the hash    
            print(pw_hash)
        User.objects.create(username=request.POST['username'], password=pw_hash) 
            return redirect("/")

def reg_Validator(self, postData):
        errors = {}
        if len(postData['first_name']) <= 0:
            errors['first_name'] = 'First Name field is required'
        if len(postData['last_name']) <= 0:
            errors['last_name'] = 'Last Name field is required'
        if len(postData['email']) <= 0:
            errors['emailReq'] = 'Email field is required'
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        if not EMAIL_REGEX.match(postData['email']):
            errors['emailMatch'] = 'Please enter a valid email address!'
        if len(postData['password']) < 8 or len(postData['password']) > 20:
            errors['password'] = 'Password must be between 8 and 20 characters'
        if postData['password'] != postData['confirmPassword']:
            errors['confirmPassword'] = 'Password does not match'
        return errors

class User(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    objects = UserManager()
