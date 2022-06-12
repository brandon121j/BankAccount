from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
import bcrypt

def index(request):
    context = {
        "all": User.objects.all()
    }
    return render(request, "index.html", context)

def register(request):
    errors = User.objects.basic_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        return redirect("/")
    
    password = request.POST['password']
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    print(pw_hash)
        
    this_user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=request.POST['password'])
    request.session['user.id'] = this_user.id
    print(this_user.id)

    return errors

def login(request):
    user = User.objects.filter(email=request.POST['email'])  
    if user:
        found_User = user[0]
        if bcrypt.checkpw(request.POST['password'].encode(), found_User.password.encode()):
            request.session['users_id'] = found_User.id
            return redirect("/success")
    messages.error(request, "invalid log in")
    return redirect("/")

def success(request):
    
    if "user_id" not in request.session:
        return redirect('/')
    context = {
        "users" : User.objects.get(id=request.session['user_id'])
    }
    return render(request, "success.html", context) 

def logout(request):
    del request.session['user_id']
    return redirect('/')