from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate
from .forms import CreateActionForm
from .models import Action
from django.utils import timezone


def home(request):
    return render(request, 'action/home.html')


def loginuser(request):
    if request.method == 'GET':
        return render(request, 'action/loginuser.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'action/loginuser.html',
                          {'form': AuthenticationForm(), 'error': 'Username and password did not match'})
        else:
            login(request, user)
            return redirect('currenttodos')


def signupuser(request):
    if request.method == 'GET':
        return render(request, 'action/signupuser.html', {'form': UserCreationForm()})
    else:
        # Create a new user
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('currenttodos')
            except IntegrityError:
                return render(request, 'action/signupuser.html', {'form': UserCreationForm(),
                                                                  'error': 'Username already taken, please use a different username'})
        else:
            return render(request, 'action/signupuser.html',
                          {'form': UserCreationForm(), 'error': 'Passwords did not match'})


def logoutuser(request):
    if request.method == 'POST':
        logout(request)
        return redirect('home')


def currenttodos(request):
    actions = Action.objects.filter(user=request.user, date_completed__isnull=True)
    return render(request, 'action/currenttodos.html', {'actions':actions})


def createaction(request):
    if request.method == 'GET':
        return render(request, 'action/createaction.html', {'form': CreateActionForm()})
    else:
        try:
            form = CreateActionForm(request.POST)
            newaction = form.save(commit=False)
            newaction.user = request.user
            newaction.save()
            return redirect('currenttodos')
        except ValueError:
            return render(request, 'action/createaction.html', {'form': CreateActionForm(), 'error':'Title too long'})


def viewaction(request, action_pk):
    action = get_object_or_404(Action, pk=action_pk, user=request.user)
    if request.method == 'GET':
            form = CreateActionForm(instance=action)
            return render(request, 'action/viewaction.html', {'action':action, 'form':form})
    else:
        try:
            form = CreateActionForm(request.POST, instance=action)
            form.save()
            return redirect('currenttodos')
        except ValueError:
            return render(request, 'action/viewaction.html', {'action':action, 'form':form, 'error': 'Title too long'})


def completeaction(request, action_pk):
    action = get_object_or_404(Action, pk=action_pk, user=request.user)
    if request.method == 'POST':
        action.date_completed = timezone.now()
        action.save()
        return redirect('currenttodos')


def deleteaction(request, action_pk):
    action = get_object_or_404(Action, pk=action_pk, user=request.user)
    if request.method == 'POST':
        action.delete()
        return redirect('currenttodos')