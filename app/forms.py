from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo


username_validator = Regexp(r"^[A-Za-z0-9_.-]{3,32}$", message="Use 3-32 alphanumeric/._- characters")


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), username_validator])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, message="Use at least 12 characters"),
            Regexp(r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])",
                   message="Include upper, lower, digit, and symbol"),
        ],
    )
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign in")


class TwoFactorForm(FlaskForm):
    token = StringField("Authenticator code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")


class GroupForm(FlaskForm):
    name = StringField("Group name", validators=[DataRequired(), Length(max=64)])
    secret = StringField("Group secret", validators=[DataRequired(), Length(min=16, max=128)])
    submit = SubmitField("Create group")


class SettingsForm(FlaskForm):
    preferred_theme = SelectField("Theme", choices=[("system", "System"), ("light", "Light"), ("dark", "Dark")])
    language = SelectField("Language", choices=[("en", "English"), ("es", "Español"), ("fr", "Français")])
    notifications_enabled = BooleanField("Enable notifications")
    timezone = SelectField(
        "Time zone",
        choices=[
            ("UTC", "UTC"),
            ("America/New_York", "New York"),
            ("Europe/London", "London"),
            ("Europe/Paris", "Paris"),
            ("Europe/Athens", "Athens"),
            ("Asia/Dubai", "Dubai"),
            ("Asia/Singapore", "Singapore"),
            ("Asia/Tokyo", "Tokyo"),
            ("Australia/Sydney", "Sydney"),
        ],
        default="UTC",
    )
    enable_totp = BooleanField("Enable TOTP (authenticator app)")
    submit = SubmitField("Save settings")
