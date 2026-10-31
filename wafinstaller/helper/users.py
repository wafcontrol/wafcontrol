from typing import Optional

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import F, QuerySet

from wafinstaller.models import UserProfile

User = get_user_model()


class UserManagementError(Exception):
    """Raised when a user operation would violate a panel rule."""


class UserManagementService:
    """Business rules for managing panel administrators.

    Panel login is restricted to superusers, so every managed user is an admin.
    Guards: an admin cannot delete or deactivate their own account, and the last
    active admin can never be deleted or deactivated.
    """

    def __init__(self, actor):
        self.actor = actor

    # ---------- queries ----------

    @staticmethod
    def list_users() -> QuerySet:
        return User.objects.annotate(
            two_factor=F("userprofile__two_factor_enabled")
        ).order_by("username")

    @staticmethod
    def get_user(user_id: int) -> Optional[User]:
        return User.objects.filter(pk=user_id).first()

    @staticmethod
    def two_factor_enabled(user) -> bool:
        profile = UserProfile.objects.filter(user=user).first()
        return bool(profile and profile.two_factor_enabled)

    # ---------- commands ----------

    @transaction.atomic
    def create(self, form):
        user = form.save(commit=False)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        UserProfile.objects.get_or_create(user=user)
        return user

    @transaction.atomic
    def update(self, user, form):
        if not form.cleaned_data.get("is_active", True):
            self._guard_removal(user, action="deactivate")
        return form.save()

    def set_password(self, form):
        return form.save()

    def reset_two_factor(self, user) -> None:
        UserProfile.objects.update_or_create(
            user=user, defaults={"two_factor_enabled": False, "two_factor_secret": ""}
        )

    @transaction.atomic
    def delete(self, user) -> str:
        self._guard_removal(user, action="delete")
        username = user.username
        user.delete()
        return username

    # ---------- rules ----------

    def _guard_removal(self, user, action: str) -> None:
        if user.pk == self.actor.pk:
            raise UserManagementError(f"You cannot {action} your own account.")
        if user.is_superuser and user.is_active:
            others = User.objects.filter(is_superuser=True, is_active=True).exclude(pk=user.pk)
            if not others.exists():
                raise UserManagementError(f"Cannot {action} the last active admin.")
