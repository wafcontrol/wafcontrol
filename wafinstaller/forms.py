from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.core.validators import RegexValidator

from wafinstaller.models import IpList
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm, UserCreationForm

class AdminLogin(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control mb-0', 'placeholder': 'Enter your username'
        }),
        label='Username'
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control mb-0', 'placeholder': 'Enter your password'
        }),
        label='Password'
    )

class AdminProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'email']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }


class AdminPasswordForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super(AdminPasswordForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'




# -------------------------
# Users management
# -------------------------

class _BootstrapFormMixin:
    """Apply bootstrap classes to every widget."""

    def _apply_bootstrap(self):
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs["class"] = "form-check-input"
            else:
                field.widget.attrs["class"] = "form-control"


class UserCreateForm(_BootstrapFormMixin, UserCreationForm):
    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True
        self.fields["is_active"].initial = True
        self._apply_bootstrap()


class UserEditForm(_BootstrapFormMixin, forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True
        self._apply_bootstrap()


class UserSetPasswordForm(_BootstrapFormMixin, SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._apply_bootstrap()


# -------------------------
# Syslog
# -------------------------

class SyslogConfigForm(_BootstrapFormMixin, forms.Form):
    enabled = forms.BooleanField(required=False, label="Enable syslog forwarding")
    host = forms.CharField(required=False, max_length=255, label="Syslog server",
                           help_text="Hostname or IP address of the syslog / SIEM server.")
    port = forms.IntegerField(min_value=1, max_value=65535, initial=514, label="Port")
    protocol = forms.ChoiceField(choices=[("udp", "UDP"), ("tcp", "TCP")], label="Protocol")
    facility = forms.ChoiceField(label="Facility")
    format = forms.ChoiceField(choices=[("rfc5424", "RFC 5424"), ("rfc3164", "RFC 3164 (BSD)")],
                               label="Message format")
    app_name = forms.CharField(max_length=48, initial="wafcontrol", label="App name / tag",
                               validators=[RegexValidator(r"^[A-Za-z0-9._-]+$",
                                                          "Use letters, digits, '.', '_' or '-'.")])
    send_attacks = forms.BooleanField(required=False, label="Send WAF attacks")
    send_audit = forms.BooleanField(required=False, label="Send user actions (audit log)")

    def __init__(self, *args, **kwargs):
        from wafinstaller.helper.syslog import FACILITIES
        super().__init__(*args, **kwargs)
        self.fields["facility"].choices = [(f, f) for f in FACILITIES]
        self._apply_bootstrap()

    def clean(self):
        data = super().clean()
        if data.get("enabled") and not (data.get("host") or "").strip():
            self.add_error("host", "Required when syslog is enabled.")
        data["host"] = (data.get("host") or "").strip()
        return data


# -------------------------
# IP lists
# -------------------------

class IpListForm(_BootstrapFormMixin, forms.ModelForm):
    class Meta:
        model = IpList
        fields = ["name", "kind", "action", "description", "countries", "entries"]
        widgets = {
            "entries": forms.Textarea(attrs={
                "rows": 10, "spellcheck": "false", "style": "font-family: monospace;",
                "placeholder": "192.168.1.10\n10.0.0.0/8      # office VPN\n2001:db8::/32",
            }),
        }
        labels = {"kind": "List type", "entries": "IP addresses / CIDR ranges"}
        help_texts = {
            "name": "Used as the include file name. Lowercase letters, digits, '-' and '_'.",
        }

    name = forms.CharField(max_length=64, validators=[RegexValidator(
        r"^[a-z0-9][a-z0-9_-]{0,63}$", "Use lowercase letters, digits, '-' or '_'.")])
    countries = forms.MultipleChoiceField(required=False, widget=forms.CheckboxSelectMultiple)

    def __init__(self, *args, country_names=None, **kwargs):
        super().__init__(*args, **kwargs)
        names = country_names or {}
        self.fields["countries"].choices = sorted(names.items(), key=lambda kv: kv[1])
        self.geo_available = bool(names)
        if self.instance.pk:
            self.initial["countries"] = self.instance.country_list
            # Name and type define the files server configs include: keep them stable.
            for field in ("name", "kind"):
                self.fields[field].disabled = True
            self.fields["name"].help_text = "The name cannot be changed: server configs include this file."
        self._apply_bootstrap()
        self.fields["countries"].widget.attrs["class"] = "form-check-input"

    def clean_entries(self):
        from wafinstaller.helper.ip_lists import normalize_entries, parse_entries
        entries, errors = parse_entries(self.cleaned_data.get("entries", ""))
        if errors:
            raise forms.ValidationError(errors)
        return normalize_entries(entries)

    def clean_countries(self):
        return ",".join(sorted(set(self.cleaned_data.get("countries") or [])))

    def clean(self):
        data = super().clean()
        if data.get("kind") == IpList.KIND_GEO:
            if not self.geo_available:
                raise forms.ValidationError("The GeoIP country index is not ready yet. Try again in a minute.")
            if not data.get("countries"):
                self.add_error("countries", "Select at least one country.")
            name = data.get("name") or ""
            # '-' and '_' map to the same nginx variable name.
            twin = IpList.objects.filter(kind=IpList.KIND_GEO, name=name.replace("-", "_")) \
                | IpList.objects.filter(kind=IpList.KIND_GEO, name=name.replace("_", "-"))
            if name and twin.exclude(pk=self.instance.pk).exclude(name=name).exists():
                self.add_error("name", "A geo list with the same name (differing only by '-'/'_') exists.")
        else:
            data["countries"] = ""
        return data
