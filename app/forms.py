from flask_wtf import FlaskForm
from flask_babel import lazy_gettext as _l
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo


username_validator = Regexp(r"^[A-Za-z0-9_.-]{3,32}$", message=_l("Use 3-32 alphanumeric/._- characters"))


class RegistrationForm(FlaskForm):
    username = StringField(_l("Username"), validators=[DataRequired(), username_validator])
    email = StringField(_l("Email"), validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        _l("Password"),
        validators=[
            DataRequired(),
            Length(min=12, message=_l("Use at least 12 characters")),
            Regexp(r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])",
                   message=_l("Include upper, lower, digit, and symbol")),
        ],
    )
    confirm = PasswordField(_l("Confirm Password"), validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField(_l("Create account"))


class LoginForm(FlaskForm):
    username = StringField(_l("Username or Email"), validators=[DataRequired()])
    password = PasswordField(_l("Password"), validators=[DataRequired()])
    remember = BooleanField(_l("Remember me"))
    submit = SubmitField(_l("Sign in"))


class TwoFactorForm(FlaskForm):
    token = StringField(_l("Authenticator code"), validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField(_l("Verify"))


class GroupForm(FlaskForm):
    name = StringField(_l("Group name"), validators=[DataRequired(), Length(max=64)])
    secret = StringField(_l("Group secret"), validators=[DataRequired(), Length(min=16, max=128)])
    submit = SubmitField(_l("Create group"))


class SettingsForm(FlaskForm):
    preferred_theme = SelectField(_l("Theme"), choices=[("system", _l("System")), ("light", _l("Light")), ("dark", _l("Dark"))])
    language = SelectField(_l("Language"), choices=[("en", "English"), ("el", "Ελληνικά")], default="en")
    notifications_enabled = BooleanField(_l("Enable notifications"))
    timezone = SelectField(
        _l("Time zone"),
        choices=[
            ("UTC", "UTC"),
            ("America/New_York", _l("New York")),
            ("Europe/London", _l("London")),
            ("Europe/Paris", _l("Paris")),
            ("Europe/Athens", _l("Athens")),
            ("Asia/Dubai", _l("Dubai")),
            ("Asia/Singapore", _l("Singapore")),
            ("Asia/Tokyo", _l("Tokyo")),
            ("Australia/Sydney", _l("Sydney")),
        ],
        default="UTC",
    )
    enable_totp = BooleanField(_l("Enable TOTP (authenticator app)"))
    submit = SubmitField(_l("Save settings"))
