from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *
from django.views.decorators.csrf import csrf_protect
# Create your views here.

def firstpage(request):
    return render(request,'firstpage.html')

@login_required
def Home(request):
    return render(request, 'index.html')

def RegisterView(request):
    if request.method=="POST":
        first_name= request.POST.get('first_name')
        second_name=request.POST.get('second_name')
        username=request.POST.get('username')
        email=request.POST.get('email')
        password=request.POST.get('password')

        user_data_has_error=False

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, 'Username already exists')

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, 'Email already exists')
        
        if len(password)<5:
            user_data_has_error=True
            messages.error(request, 'Password must be atleast of 5 characters')

        if user_data_has_error==False:
            new_user= User.objects.create_user(
                first_name=first_name,
                last_name=second_name,
                email=email,
                username=username,
                password=password
            )
            messages.success(request,'Account created, Login now')
            return redirect('login')
        else:
            return redirect('register')


    return render(request, 'register.html')

@csrf_protect
def LoginView(request):
    if request.method=="POST":
            username=request.POST.get('username')
            password=request.POST.get('password')

            # authenticate the user detail
            user= authenticate(request, username=username, password=password)

            if user is not None:
                login(request,user)
                return redirect('home')
            else:
                messages.error(request,'Invalid login credentials')
                return redirect('login')
            
    return render(request, 'login.html')


def LogoutView(request):
    logout(request)
    return redirect('firstpage')


def ForgotPassword(request):
    if request.method=="POST":
        email=request.POST.get('email')

        try:
            user=User.objects.get(email=email)

             # create a new reset id
            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            # creat password reset ur;
            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})
            full_password_reset_url= f'{request.scheme}://{request.get_host()}{password_reset_url}'
            # email content
            email_body = f'Reset your password using the link below:\n\n\n{full_password_reset_url}'
            email_message = EmailMessage(
                'Reset your password',
                email_body,
                settings.EMAIL_HOST_USER, 
                [email] 
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)


        except User.DoesNotExist:
            messages.error(request, f"No user with email {email} found")
            return redirect('forgot-password')


    return render(request, 'forgot_password.html')

# from django.urls import reverse

# def ForgotPassword(request):
#     if request.method == "POST":
#         email = request.POST.get('email')

#         try:
#             user = User.objects.get(email=email)

#             # Create a new reset entry
#             new_password_reset = PasswordReset(user=user)
#             new_password_reset.save()

#             # Create password reset URL with a valid UUID
#             password_reset_url = request.build_absolute_uri(
#                 reverse('reset-password', kwargs={'reset_id': str(new_password_reset.reset_id)})
#             )

#             email_body = f'Reset your password using the link below:\n\n{password_reset_url}'
#             email_message = EmailMessage(
#                 'Reset your password',
#                 email_body,
#                 settings.EMAIL_HOST_USER,
#                 [email]
#             )

#             email_message.fail_silently = True
#             email_message.send()

#             return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

#         except User.DoesNotExist:
#             messages.error(request, f"No user with email {email} found")

#     return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):
        if PasswordReset.objects.filter(reset_id=reset_id).exists():
            return render(request, 'password_reset_sent.html')
        else:
            # redirect to forgot password page if code does not exist
            messages.error(request, 'Invalid reset id')
            return redirect('forgot-password')

def ResetPassword(request, reset_id):
    try:
        reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm password')

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 5 characters long')

            # check to make sure link has not expired
            expiration_time = reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                reset_id.delete()
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')
            
            if not passwords_have_error:
                user = reset_id.user
                user.set_password(password)
                user.save()
                
                # delete reset id after use
                reset_id.delete()

                # redirect to login
                messages.success(request, 'Password reset. Proceed to login')
                return redirect('login')

            else:
                # redirect back to password reset page and display errors
                return redirect('reset-password', reset_id=reset_id)

    except PasswordReset.DoesNotExist:
        
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')