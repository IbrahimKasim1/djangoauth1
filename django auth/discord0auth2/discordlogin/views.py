import requests
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.utils import datastructures
from django.shortcuts import redirect
from django.http import HttpRequest, HttpResponse, JsonResponse, response
from django.shortcuts import render



# Create your views here.

auth_url_discord = "https://discord.com/api/oauth2/authorize?client_id=809482428712353852&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Foauth2%2Flogin%2Fredirect&response_type=code&scope=identify"


def home(request):
    return render(request, 'base.html')




@login_required(login_url="/oauth2/login")
def get_authenticated_user(request: HttpRequest):
    print(request.user)
    user = request.user
    return JsonResponse({
        "id": user.id,
        "discord_tag": user.discord_tag,
        "avatar": user.avatar,
        "public_flags": user.public_flags,
        "flags": user.flags,
        "locale": user.locale,
        "mfa_enabled": user.mfa_enabled
    })


def discord_login(request: HttpRequest):
    return redirect(auth_url_discord)
  
 
def discord_login2(request):
    return HttpResponse("""<html><script>window.location.replace('/oauth2/login')</script></html>""")


def discord_login_redirect(request: HttpRequest):
    code = request.GET.get('code')
    print(code)
    user = exchange_code(code)
    discord_user = authenticate(request, user=user)
    discord_user = list(discord_user).pop()
    print(discord_user)
    login(request, discord_user)
    return redirect("/auth/user")


def exchange_code(code: str):
    data = {
        "client_id": "809482428712353852",
        "client_secret": "G4hcHi-NoMY3RuoxJJG8xhoRvyuupmUQ",
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost:8000/oauth2/login/redirect",
        "scope": "identify"

    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(
        "https://discord.com/api/oauth2/token", data=data, headers=headers)

    credentials = response.json()
    access_token = credentials['access_token']
    response = requests.get("https://discord.com/api/v6/users/@me", headers={
        'Authorization': 'Bearer %s' % access_token
    })

    print(response)
    user = response.json()
    print(user)
    return user
