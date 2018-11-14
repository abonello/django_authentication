# Authentication and Authorisation

1. Use the Django Admin Panel
2. Log users in and out using emails and usernames
3. Register users
4. Create users profiles
5. Build the Forgot Password functionality

Show different navigation menus based on whether the user is logged in or not.

----
Install django
```bash 
$ sudo pip3 install django==1.11
```

Start project
```bash 
$ django-admin startproject django_auth .
```

Create a new django app
```bash 
$ django-admin startapp accounts
```

In settings.py update installed apps - add accounts app.

Show home in favorites and hidden files. In .bash_aliases add a run alias:
```python 
alias run='python3 manage.py runserver $IP:$PORT'
```
Rerun the .bash_aliases file to reload the aliases file and take effect.  
Make a migration.  
Try the run command.
```bash 
$ . ~/.bash_aliases
$ python3 manage.py migrate
$ run
```

It will fail at this point but it will also tell us the exact url that we need.
Copy the url as indicated in the error message and add it to the ALLOWED_HOSTS in 
settings.py. Refresh the browser window and now it will work.

We can also avoid this by using an environment variable like:
```python 
ALLOWED_HOSTS = [os.environ.get('C9_HOSTNAME')]
```

Create superuser to be able to login to admin

```bash 
$ python3 manage.py createsuperuser
Username (leave blank to use 'ubuntu'): admin
Email address: test@example.com
Password:
Password (again): 
Superuser created successfully.
```
Password: 123qwe456

Go to the /admin url and login

### Creating templates

Create a templates folder inside our accounts app folder.  
Create index.html in templates.  
Put a boiler plate code in index.html and a simple navigation
```
<nav>  
    <ul>
        <li><a href="#">Login</a></li>
        <li><a href="#">Logout</a></li>
        <li><a href="#">Register</a></li>
        <li><a href="#">Profile</a></li>
    </ul>
</nav>
```

Create a view function called index in views.py  
```python 
def index(request):
    """Return the index.html template"""
    return render(request, 'index.html')
```
Connect the view to a urlpattern in urls.py. Will need to import this view.
```python 
from django.conf.urls import url
from django.contrib import admin
from accounts.views import index

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', index),
]
```

### Enable logout:  
Modify `<a>` tag for logout menu in index.html. point it to the logout url.  
`<li><a href="{% url 'logout' %}">Logout</a></li>`  

Create a url pattern for this in urls.py. Remember to import the view.  
`url(r'^accounts/logout/$', logout, name="logout"),`  

Create a view for logout. Need to import auth from django.contrib. We also need 
to import redirect and reverse  
```
from django.shortcuts import render, redirect, reverse
from django.contrib import auth

def logout(request):
    """Log the user out"""
    auth.logout(request)
    return redirect(reverse('index'))
```


request, used in auth.logout() contains the user object.  
We need to give a name to the urlpattern of index.  

### Using django messages

In views import messages from django.contrib.
```
messages.success(request, "You have successfully logged out.")
```

Then we need to add an area in index.html to receive and display 
the messages.

# NB: VERY IMPORTANT 
This will not work before we update settings.py file  
```
MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"
```
---

### Login mechanism

create a login view.
```python
def login(request):
    """Return a login page."""
    return render(request, 'login.html')
```

Create login.html
Add an H1 to both index and login pages to distinguish between them.  
Update the navigation for the login on both index and login pages.  
```<li><a href="{% url 'login' %}">Login</a></li>```

Add a url pattern for login. Import the login view.  
```
url(r'^accounts/login/$', login, name="login"),
```

Add the Form to the login page.

Create a forms.py file
```python
from django import forms


class UserLoginForm(forms.Form):
    """Form to be used to log in users."""
    
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)
```

Update views.py file. I need to import this new form.
```
from accounts.forms import UserLoginForm
```
Then we need to use this form in the login view. Create an instance of this form 
and pass it to the front end.
```python 
def login(request):
    """Return a login page."""
    login_form = UserLoginForm()
    return render(request, 'login.html', {"login_form": login_form})
```
Then inside the login template we need to use and display this form inside 
<form> tags with a method of POST.  

```jinja
<form method="POST">
    {{ login_form }}
</form>
```

Add button to the form
Add a cross-site request forgery token
```
<form method="POST">
    {% csrf_token %}
    {{ login_form }}
    <button type="submit">Login</button>
</form>
```

Add the logic to the view that will actually log in the user.

Authenticate and login the user.

```python 
def login(request):
    """Return a login page."""
    
    if request.method == 'POST':
        login_form = UserLoginForm(request.POST)
        
        if login_form.is_valid():
            user = auth.authenticate(username=request.POST['username'],
                                     password=request.POST['password'])
            if user:
                auth.login(user=user, request=request)
                messages.success(request, "You have successfully logged in.")
            else:
                login_form.add_error(None, "Your username or password is incorrect.")
    else:
        login_form = UserLoginForm()
    return render(request, 'login.html', {"login_form": login_form})
```

### Template inheritance

Avoiding duplication of code.  
Create a templates directory in the root of the project.  
Inside this templates directory create base.html  
Since we are placing the base.html in a templates directory in the root project  
we need to update the systems.py file  
By default, django looks for templates within the app's folder.  
In systems.py file, find Templates and the DIRS list and update this:
```python 
'DIRS': [os.path.join(BASE_DIR, 'templates')],
```

Modify index.html to extend base.html

Modify login.html

### Check if user is logged in or not

```
<nav>
    <ul>
        {% if user.is_authenticated %}
            <li><a href="#">Profile</a></li>
            <li><a href="{% url 'logout' %}">Logout</a></li>
        {% else %}
            <li><a href="{% url 'login' %}">Login</a></li>
            <li><a href="#">Register</a></li>
        {% endif %}
    </ul>
</nav>
```

### Prevent users from accessing pages when not logged in.
Redirect a user who has successfully logged in to the index page.
```python 
if user:
    auth.login(user=user, request=request)
    messages.success(request, "You have successfully logged in.")
    return redirect(reverse('index'))
```
The reason is we do not want to display the login form to users who are logged in.
To prevent this we need to check if a user is already logged in when they reach 
the log in view. If they are, redirect them to the index page.
```python 
if request.user.is_authenticated:
    return redirect(reverse('index'))
```
This prevents manually trying to reach the log in page when already logged in.

Allow access to the log out page only when a user is logged in (authenticated). 
For this we need a new import.  
```python 
from django.contrib.auth.decorators import login_required
```

It is a decorator and it is used by placing it just above the function signature 
that it wants to protect.
```python 
@login_required
def logout(request):
```

If a user tries to manually reach the logout url when not authenticated, the 
user will be redirected to the login page by default.


### Registration View and Template

in views.py create a registration function
```python 
def registration(request):
    """Render the registration page."""
    return render(request, 'registration.html')
```

Create a url template. Remember to import the view.
```python 
url(r'^accounts/register/$', registration, name="registration"),
```

Update navigation to registration in base.html template.
```
<li><a href="{% url 'registration' %}">Register</a></li>
```

Create a registration template. Use contents of login.html as boilerplate code.
```jinja2
{% extends 'base.html' %}

{% block page_title %}Registration Page{% endblock %}

{% block page_heading %}User Registration{% endblock %}

{% block content %}

<p>If you already have an account, you can <a href="{% url 'login' %}">sign in</a>.</p>

Registration Form will go here . . .

{% endblock %}
```

### Registration Form

In forms.py add a new form for registration. This will be different from the login 
form. The login form performed some validataion to check if the user existed and 
can be authenticated. The registration form however will require to store some 
information about the user in the database. 

For this reason we need to import the **`User` model** provided by django from 
`django.contrib.auth.models`.

We also need to import the UserCreationForm from django.contrib.auth.forms. This 
is a form that django provides us. It will give us usernames and email fields. 
All we need to do is extend it to allow the passwords.

Next we need to import some validation functionality. For this we will import
ValidationError from django.core.exceptions.  

All imports we have at present:
```python 
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
```

Now we create a new class called UserRegistrationForm which will extend 
UserCreationForm. It will contain an inner class called Meta. We can use an 
inner class to provide some information about this form. We can also use it 
to specify the model and the fields we want to use.

```python 
class UserRegistrationForm(UserCreationForm):
    """Form used to register a new user."""
    
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput)
    password2 = forms.CharField(
        label="Password Confirmation", 
        widget=forms.PasswordInput)
        
    class Meta:
        model = User
        fields = ['email', 'username', 'password1', 'password2']
```


Now import this form in the views.py. Then we are going to use it inside the 
registration view and then pass this to the fronend.

```python 
def registration(request):
    """Render the registration page."""
    
    registration_form = UserRegistrationForm()
    return render(request, 'registration.html', {"registration_form": registration_form})
```

Next we need to render this form in the registration.html template.
```
<p>If you already have an account, you can <a href="{% url 'login' %}">sign in</a>.</p>

<form method="POST">
    {% csrf_token %}
    {{ registration_form }}
    <button type="submit">Register</button>
</form>
```

In order to render the from a bit better we are going to render each field as 
a p element instead of one big div.
```
{{ registration_form.as_p }}
```
We can also use `.as_ul` and `.as_table`.

Up to now the form is not creating new users.

Implement form validation in forms.py.  
Django will use any method whose name starts with clean_<fieldname> and use it 
to clean or validate that field. ex clean_email will allow us to clean the 
email field and expects us to return the email once we are done. 
We will check if we already have someone registered with that email address. If 
we do we will return a validation error saying that the Email address must 
be unique.
```python 
def clean_email(self):
    email = self.cleaned_data.get('email')
    username = self.cleaned_data.get('username')
    if User.objects.filter(email=email).exclude(username=username):
        raise forms.ValidationError(u'Email address must be unique.')
    return email
```

Next we will do the same for the password field. We need to check if any of
the passwords was left empty. Then check if both passwords match. If everything 
is OK, then return password2.
```python 
def clean_password2(self):
    password1 = self.cleaned_data.get('password1')
    password2 = self.cleaned_data.get('password2')
    
    if not password1 or not password2:
        raise ValidationError("Please confirm your password.")
        
    if password1 != password2:
        raise ValidationError("Passwords must match")
        
    return password2
```

Improving registration view to make use of the form. We will use similar logic 
that we used in the login form.  


### User Profile

Create view - remember to import User
```python 
from django.contrib.auth.models import User


def user_profile(request):
    """The user's profile page."""
    
    user = User.objects.get(email=request.user.email)
    return render(request, 'profile.html', {"profile": user})
```

Create url - remember to import the view.
```python 
url(r'^accounts/profile/$', user_profile, name="profile"),
```

Update link in nav in base.html for profile.
```jinja2
<li><a href="{% url 'profile' %}">Profile</a></li>
```

Create new template, profile.html, copy boilerplate from index.html
```jinja2 
{% extends 'base.html' %}

{% block page_title %}{{ user }}'s Profile{% endblock %}

{% block page_heading %}{{ user }}'s Profile{% endblock %}
```

Improve the profile page:
```jinja2 
{% block content %}
<p><strong>email:</strong> {{ profile.email }}</p>
{% endblock %}
```

### Password reset
In the accounts app folder create a file called `url_reset.py`.
This will allow us to create reset specific urls. It will be mapped into views. 

```python 
from django.conf.urls import url
from django.core.urlresolvers import reverse_lazy
from django.contrib.auth.views import password_reset, password_reset_done, password_reset_confirm, password_reset_complete

urlpatterns =[
    url(r'^$', password_reset,
        {'post_reset_redirect': reverse_lazy('password_reset_done')}, name="password_reset"),
    url(r'^done/$', password_reset_done, name="password_reset_done"),
    url(r'^(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', password_reset_confirm, 
        {'post_reset_confirm': reverse_lazy('password_reset_complete')}, name="password_reset_confirm"),
    url(r'^complete/$', password_reset_complete, name="password_reset_complete")
]
```

which is correct?
```python 
url(r'^(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', password_reset_confirm, 
        {'post_reset_redirect': reverse_lazy('password_reset_complete')}, name="password_reset_confirm"),
```

### App specific urls.py

Move all the accounts-related urls into this accounts urls.py.

```python 
from django.conf.urls import url, include
from accounts.views import index, logout, login, registration, user_profile
from accounts import url_reset

urlpatterns = [
    url(r'^logout/$', logout, name="logout"),
    url(r'^login/$', login, name="login"),
    url(r'^register/$', registration, name="registration"),
    url(r'^profile/$', user_profile, name="profile"),
    url(r'^password-reset/', include(url_reset))
]
```

while the project main urls.py file is now like:
```python 
from django.conf.urls import url, include
from django.contrib import admin
from accounts.views import index
from accounts import urls as accounts_urls

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', index, name="index"),
    url(r'^accounts/', include(accounts_urls))
]
```

### Configure django to send emails

Needed to reset the password.  

Simplest solution: use the console to print out the email.

In settings.py create new setting.
```python 
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
```

Can test this:
```bash 
$ python3 manage.py sendtestemail <email-address>
Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: Test email from anthonybstudent-django-authentication-6534853 on
 2018-11-14
 07:21:50.165887+00:00
From: webmaster@localhost
To: ab@anthonybonello.co.uk
Date: Wed, 14 Nov 2018 07:21:50 -0000
Message-ID: 
 <20181114072150.36963.35476@anthonybstudent-django-authentication-6534853>

If you're reading this, it was successful.
-------------------------------------------------------------------------------
```

Managed to send email from backend.

### Registration templates

In templates forlder within root folder, create a registration directory. In 
here create a `password_reset_from.html`.

Also add link in login.html to link to password_reset_form.


### Sending a real email

In settings.py file add:
```python 
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = os.environ.get("EMAIL_ADDRESS")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_PORT = 587
```

TLS is a type of encryption used by gmail  
smtp is a protocol used to send emails  
For user we are using an environment variable:  
* export EMAIL_ADDRESS="-----"
* export EMAIL_PASSWORD="-----"


restart .bashrc

```bash 
$ . ~/.bashrc
```

At this point we get an error  
`SMTPAuthenticationError at /accounts/password-reset/`

Go to google https://myaccount.google.com/. In Sign-in & Security, click on 
Apps with account access and activate  
Allow less secure apps 

### Email authentication

By default django supports users logging in by username. What if we want 
to log in using the email instead?  

We need a custom authentication backend.

In settings.py add the following after the  AUTH_PASSWORD_VALIDATORS.

```python 
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'accounts.backends.EmailAuth'
]
```
In the app directory create a new file called `backends.py`

```python 
from django.contrib.auth.models import User

class EmailAuth:
    """Authenticate a user by an exact match on the email and password."""
    
    def authenticate(self, username=None, password=None):
        """
        Get instance of `User` based on the email and verify the 
        password.
        """
            
        try:
            user = User.objects.get(email=username)
            # We are using username because that is the name of the element in the form.
            
            if user.check_password(password):
                return user
            return None
        
        except User.DoesNotExist:
            return None
            
    def get_user(self, user_id):
        """Used by Django authentication system to retrieve a user instance."""
        
        try:
            user = User.objects.get(pk=user_id)
            
            if user.is_active:
                return user
            return None
        except User.DoesNotExist:
            return None
```


## Using Bootstrap

Get cdns as usual and place in header of base.html

Style navigation.

For buttons. Ex. Registration button. place classes.
But we cannot do the same for the form.  
Instead we need a third-party library called `django-forms-bootstrap`.  
pip install this.  
```bash 
$ sudo pip3 install django_forms_bootstrap
```

We need to include this in the installed apps in settings.py.  

How to use this?  

Open registration.html.  
At the top after the extends statement load bootstrap tags:
```jinja2 
{% load bootstrap_tags %}
```

this will import the javascript for bootstrap

change `{{ registration_form.as_p }}` to   
`{{ registration_form | as_bootstrap }}`

Do similar thing to login page.

### Static files.

Custom CSS.  


At the top level of our project create a directory called `static`. Inside 
this create a directory called `css`. Inside this create a file called 
`styles.css`. In `base.html` link to this style sheet.

```html 
<link rel="stylesheet" href="{% static 'css/styles.css' %}" type="text/css" />
```
At the top of `base.html`, before the Doctype add
```
{% load staticfiles %}
```

In settings.py we need to add some code. We already have a line of code saying: 
```
STATIC_URL = '/static/'
```
Just below this add:
```
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static")
]
```