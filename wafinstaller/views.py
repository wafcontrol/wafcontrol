import base64
import io
import json
import os
import re
import subprocess
from collections import Counter

import matplotlib.pyplot as plt
import pyotp
import qrcode
from celery.result import AsyncResult
from django.contrib import messages
from django.contrib.auth import get_user_model, login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView as DjangoLogoutView
from django.db import models
from django.db.models import Q, Count
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST
from django.views.generic import ListView, TemplateView

from wafinstaller.helper.adapters import get_paths, custom_after_path as _custom_after_path
from wafinstaller.helper.crs import (
    MODSEC_KEYS,
    MODSEC_KEY_DESCRIPTIONS,
    RULE_PATTERN,
    APP_KEYS,
    load_app_settings,
    save_app_settings,
)
from .forms import AdminLogin, AdminPasswordForm, AdminProfileForm
from wafinstaller.helper.helpers import (
    get_installed_crs_version,
    get_latest_crs_version,
    normalize_version,
    run_basic_script,
    run_switch_version_script,
    run_updatecrs_script,
)
from .models import Attack, CrsVersion, DashboardStat, UserProfile
from .tasks import fetch_crs_versions_task, run_waf_install
from wafinstaller.helper.utils import get_crs_full_version, get_rules_dir

User = get_user_model()


# -------------------------
# Auth
# -------------------------

@method_decorator(csrf_protect, name="dispatch")
@method_decorator(sensitive_post_parameters("password"), name="dispatch")
class LoginsView(LoginView):
    template_name = "auth/login.html"
    authentication_form = AdminLogin
    redirect_authenticated_user = True

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("/dashboard/")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.get_user()

        if not user.is_active:
            messages.error(self.request, "Your account is disabled.")
            return self.form_invalid(form)

        if not user.is_superuser:
            messages.error(self.request, "Access denied. Admin only.")
            return self.form_invalid(form)

        profile, _ = UserProfile.objects.get_or_create(user=user)
        self.request.session["pre_2fa_user_id"] = user.id

        if profile.two_factor_enabled:
            return redirect("wafinstaller:verify_2fa")

        login(self.request, user)
        return redirect("/dashboard/")

    def form_invalid(self, form):
        messages.error(self.request, "Invalid username or password.")
        return super().form_invalid(form)


class Verify2FAView(View):
    template_name = "auth/verify_2fa.html"

    def get(self, request):
        if not request.session.get("pre_2fa_user_id"):
            messages.error(request, _("Session expired. Please log in again."))
            return redirect("wafinstaller:login")
        return render(request, self.template_name)

    def post(self, request):
        user_id = request.session.get("pre_2fa_user_id")
        if not user_id:
            messages.error(request, _("Session expired. Please log in again."))
            return redirect("wafinstaller:login")

        try:
            user = User.objects.select_related("userprofile").get(id=user_id)
            secret = user.userprofile.two_factor_secret
        except (User.DoesNotExist, AttributeError):
            messages.error(request, _("Invalid authentication state."))
            return redirect("wafinstaller:login")

        code = request.POST.get("otp", "").strip()
        if not code or len(code) != 6 or not code.isdigit():
            messages.error(request, _("Please enter a valid 6-digit 2FA code."))
            return render(request, self.template_name)

        totp = pyotp.TOTP(secret)
        if not totp.verify(code):
            messages.error(request, _("Invalid 2FA code. Please try again."))
            return render(request, self.template_name)

        login(request, user)
        request.session.pop("pre_2fa_user_id", None)
        messages.success(request, _("Two-factor authentication successful."))
        return redirect("/dashboard/")


class CustomLogoutView(DjangoLogoutView):
    next_page = "wafinstaller:login"

    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class HomeRedirectView(View):
    def get(self, request, *args, **kwargs):
        return redirect("wafinstaller:dashboard")


# -------------------------
# WAF Install / status
# -------------------------

@login_required
@require_POST
def install_waf_page(request):
    """Kick off WAF installation if not installed (uses celery task)."""
    try:
        info = run_basic_script()
        waf_status = info.get("waf", {})
        if waf_status.get("exit_code") == 0:
            messages.error(request, "WAF is already installed.")
        else:
            run_waf_install.delay()
            messages.success(request, "WAF installation has been started.")
    except Exception as e:
        messages.error(request, f"Error checking WAF status: {e}")
    return redirect("wafinstaller:dashboard")


@csrf_exempt
def install_waf(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method Not Allowed"}, status=405)
    task = run_waf_install.delay()
    return JsonResponse({"task_id": task.id})


@csrf_exempt
def install_status(request, task_id):
    result = AsyncResult(task_id)
    data = {"state": result.state, "result": result.result}
    if result.state == "PROGRESS":
        data["line"] = result.info.get("line") if result.info else None
    elif result.state == "FAILURE":
        data["error"] = str(result.result)
    return JsonResponse(data)


# -------------------------
# Dashboard
# -------------------------

@method_decorator(csrf_exempt, name="dispatch")
class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/panel.html"
    login_url = "wafinstaller:login"

    def post(self, request):
        """Manual CRS update from UI (sync)."""
        exit_code, log = run_updatecrs_script()
        return JsonResponse({"status": "done", "exit_code": exit_code, "log": log})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # server/waf state
        service_data = run_basic_script()
        waf_data = service_data.get("waf", {"exit_code": 1, "version": ""})

        installed_crs = get_installed_crs_version()
        latest_crs = get_latest_crs_version()

        context.update(
            {
                "nginx": service_data.get("nginx", {"exit_code": 1, "version": ""}),
                "apache": service_data.get("apache", {"exit_code": 1, "version": ""}),
                "waf": waf_data,
                "installed_crs": installed_crs,
                "latest_crs": latest_crs,
                "update_available": bool(
                    installed_crs and latest_crs and installed_crs != latest_crs
                ),
                "active_server": service_data.get("server", "none"),
            }
        )

        # system stats
        latest_stats = DashboardStat.objects.order_by("-fetched_at").first()
        context.update(
            {
                "cpu_usage": latest_stats.cpu_usage if latest_stats else "0",
                "cpu_load": latest_stats.cpu_load if latest_stats else "0",
                "ram_usage": latest_stats.ram_usage if latest_stats else "0",
                "disk_usage": latest_stats.disk_usage if latest_stats else "0",
                "storage_free": latest_stats.storage_free if latest_stats else "0",
                "total_processes": latest_stats.total_processes if latest_stats else "0",
                "total_threads": latest_stats.total_threads if latest_stats else "0",
                "total_handles": latest_stats.total_handles if latest_stats else "0",
            }
        )

        # attacks pie chart (countries)
        country_counts = Counter(Attack.objects.values_list("country", flat=True))
        if country_counts:
            fig, ax = plt.subplots()
            ax.pie(
                country_counts.values(),
                labels=country_counts.keys(),
                autopct="%1.1f%%",
                startangle=140,
            )
            ax.axis("equal")
            buf = io.BytesIO()
            plt.savefig(buf, format="png", bbox_inches="tight")
            buf.seek(0)
            context["waf_chart_base64"] = base64.b64encode(buf.read()).decode("utf-8")
            buf.close()
        else:
            context["waf_chart_base64"] = ""

        context["recent_attacks"] = Attack.objects.order_by("-timestamp")[:5]
        return context


# -------------------------
# Attacks list / critical / top
# -------------------------

class WafAttacksView(LoginRequiredMixin, ListView):
    model = Attack
    template_name = "dashboard/panel/attacks.html"
    context_object_name = "attacks"
    paginate_by = 30
    login_url = "wafinstaller:login"

    def get_queryset(self):
        qs = Attack.objects.all().order_by("-timestamp")
        ip = self.request.GET.get("ip")
        rule_id = self.request.GET.get("rule_id")
        status = self.request.GET.get("status")
        start_date = self.request.GET.get("start_date")
        end_date = self.request.GET.get("end_date")
        host = self.request.GET.get("host")

        if ip:
            qs = qs.filter(ip__icontains=ip)
        if rule_id:
            qs = qs.filter(rule_id__icontains=rule_id)
        if status:
            qs = qs.filter(status=status)
        if start_date:
            qs = qs.filter(timestamp__date__gte=start_date)
        if end_date:
            qs = qs.filter(timestamp__date__lte=end_date)
        if host:
            qs = qs.filter(host__icontains=host)

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["total_attacks"] = Attack.objects.count()
        context["filtered_count"] = self.get_queryset().count()

        repeated_ips = list(
            Attack.objects.values("ip")
            .annotate(count=Count("ip"))
            .filter(count__gt=3)
            .values_list("ip", flat=True)
        )
        context["repeated_attackers"] = repeated_ips

        for attack in context["attacks"]:
            if attack.severity >= 3:  # High / Critical
                attack.row_class = "table-danger"
            elif attack.severity == 2:  # Medium
                attack.row_class = "table-warning"
            elif attack.ip in repeated_ips:
                attack.row_class = "table-warning"  #
            else:  # Low / Info
                attack.row_class = "table-light"  #

        return context


class TopAttackersView(LoginRequiredMixin, ListView):
    template_name = "dashboard/panel/top_attackers.html"
    context_object_name = "attackers"
    paginate_by = 20
    login_url = "wafinstaller:login"

    def get_queryset(self):
        qs = (
            Attack.objects.values("ip", "country", "flag")
            .annotate(total=Count("id"))
            .order_by("-total")
        )
        ip = self.request.GET.get("ip")
        country = self.request.GET.get("country")
        if ip:
            qs = qs.filter(ip__icontains=ip)
        if country:
            qs = qs.filter(country__icontains=country)
        return qs


class CriticalWafAttacksView(LoginRequiredMixin, ListView):
    model = Attack
    template_name = "dashboard/panel/critical_attacks.html"
    context_object_name = "attacks"
    paginate_by = 20
    ordering = ["-timestamp"]
    login_url = "wafinstaller:login"

    # Rule families considered critical
    CRITICAL_FAMILIES = ("942", "930", "932", "941", "931", "933")
    NOISE_RULES = ("980170",)  # Rules to ignore

    def get_queryset(self):
        # Build base query for critical rule families
        q = Q()
        for fam in self.CRITICAL_FAMILIES:
            q |= Q(rule_id__startswith=fam)
        for rid in self.NOISE_RULES:
            q &= ~Q(rule_id=rid)

        attacks = Attack.objects.filter(q).order_by("-timestamp")

        # Apply filters from GET parameters
        ip = self.request.GET.get("ip")
        rule_id = self.request.GET.get("rule_id")
        status = self.request.GET.get("status")
        start_date = self.request.GET.get("start_date")
        end_date = self.request.GET.get("end_date")
        host = self.request.GET.get("host")

        if ip:
            attacks = attacks.filter(ip__icontains=ip)
        if rule_id:
            attacks = attacks.filter(rule_id__icontains=rule_id)
        if status:
            attacks = attacks.filter(status=status)
        if start_date:
            attacks = attacks.filter(timestamp__date__gte=start_date)
        if end_date:
            attacks = attacks.filter(timestamp__date__lte=end_date)
        if host:
            attacks = attacks.filter(host__icontains=host)

        return attacks

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["total_attacks"] = Attack.objects.count()
        context["filtered_count"] = self.get_queryset().count()
        return context


        # -------------------------
# CRS update (sync)
# -------------------------

@method_decorator(csrf_exempt, name="dispatch")
class CrsUpdateSyncView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request):
        exit_code, log = run_updatecrs_script()
        return JsonResponse({"status": "done", "exit_code": exit_code, "log": log})


@method_decorator(login_required, name="dispatch")
class GetTaskStatusView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request, task_id, *args, **kwargs):
        task_result = AsyncResult(task_id)
        if task_result.state == "PROGRESS":
            return JsonResponse(
                {"status": "progress", "line": task_result.info.get("line")}
            )
        elif task_result.state == "SUCCESS":
            return JsonResponse({"status": "done", "result": task_result.result})
        elif task_result.state == "FAILURE":
            return JsonResponse({"status": "error", "error": str(task_result.result)})
        else:
            return JsonResponse({"status": task_result.state})


# -------------------------
# CRS files/rules browsing
# -------------------------

class CRSRuleListView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/crs_rules.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        version = get_crs_full_version()
        rule_dir = get_rules_dir(version)
        files = []
        try:
            if rule_dir and os.path.isdir(rule_dir):
                for filename in sorted(os.listdir(rule_dir)):
                    if filename.endswith((".conf", ".data")):
                        files.append(filename)
            else:
                files.append(f"[Directory not found]: {rule_dir}")
        except Exception as e:
            files.append(f"[Error]: {str(e)}")

        context.update({"crs_version": version, "rule_files": files})
        return context


class ReadCRSRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request, filename):
        version = get_crs_full_version()
        rule_dir = get_rules_dir(version)
        file_path = os.path.join(rule_dir, filename)

        try:
            if os.path.isfile(file_path):
                with open(file_path, "r") as f:
                    content = f.read()
                return JsonResponse({"success": True, "content": content})
            else:
                return JsonResponse({"success": False, "error": "File not found."})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})


@method_decorator(csrf_exempt, name="dispatch")
class SaveCRSRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request, filename):
        try:
            data = json.loads(request.body)
            content = data.get("content", "")
            version = get_crs_full_version()
            rule_dir = get_rules_dir(version)
            file_path = os.path.join(rule_dir, filename)

            if os.path.isfile(file_path):
                with open(file_path, "w") as f:
                    f.write(content)
                return JsonResponse({"success": True})
            else:
                return JsonResponse({"success": False, "error": "File not found."})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})


class CRSCategoriesView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/crs_categories.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        version = get_crs_full_version()
        rule_dir = get_rules_dir(version)
        rule_files = []
        if rule_dir and os.path.isdir(rule_dir):
            rule_files = [f for f in sorted(os.listdir(rule_dir)) if f.endswith(".conf")]
        context.update({"crs_version": version, "rule_files": rule_files})
        return context


class CRSRuleListByFileView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/crs_rules_by_file.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        version = get_crs_full_version()
        filename = kwargs.get("filename")
        rule_dir = get_rules_dir(version)
        file_path = os.path.join(rule_dir, filename)

        rules = []
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r") as f:
                    lines = f.readlines()

                i = 0
                while i < len(lines):
                    line = lines[i]
                    raw_lines = [line]
                    start_index = i
                    if re.search(r"(SecRule|SecAction)", line):
                        while line.rstrip().endswith("\\") and i + 1 < len(lines):
                            i += 1
                            line = lines[i]
                            raw_lines.append(line)
                        full_rule = "".join(raw_lines)
                        rid = re.search(r'id\s*:\s*"?(\d+)"?', full_rule)
                        msg = re.search(r"msg\s*:\s*'(.*?)'", full_rule)
                        rules.append(
                            {
                                "id": rid.group(1) if rid else "unknown",
                                "msg": msg.group(1) if msg else "",
                                "enabled": not all(
                                    ln.lstrip().startswith("#") for ln in raw_lines
                                ),
                                "filename": filename,
                                "line_number": start_index + 1,
                                "raw": "".join(raw_lines).strip(),
                            }
                        )
                    i += 1
            except Exception as e:
                # Keep silent in UI, only log
                print(f"Error reading {file_path}: {e}")

        context.update({"rules": rules, "filename": filename, "crs_version": version})
        return context


@method_decorator(csrf_exempt, name="dispatch")
class ToggleCRSRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request):
        try:
            data = json.loads(request.body)
            rule_id = data.get("rule_id")
            filename = data.get("filename")
            enable = data.get("enable") is True

            if not rule_id or not filename:
                return JsonResponse(
                    {"success": False, "error": "Missing rule_id or filename"}
                )

            version = get_crs_full_version()
            rule_dir = get_rules_dir(version)
            file_path = os.path.join(rule_dir, filename)

            if not os.path.isfile(file_path):
                return JsonResponse(
                    {"success": False, "error": "Rule file not found."}
                )

            with open(file_path, "r") as f:
                lines = f.readlines()

            new_lines, found, i = [], False, 0
            while i < len(lines):
                line = lines[i]
                if re.search(r"^\s*(#\s*)?(SecRule|SecAction)", line):
                    temp_lines, rule_text = [line], line
                    i += 1
                    while i < len(lines) and (
                        lines[i].rstrip().endswith("\\")
                        or not re.search(
                            r"^\s*(#\s*)?(SecRule|SecAction)", lines[i]
                        )
                    ):
                        temp_lines.append(lines[i])
                        rule_text += lines[i]
                        i += 1
                    if re.search(
                        r'id\s*:\s*"?'
                        + re.escape(rule_id)
                        + r'"?',
                        rule_text,
                    ):
                        found = True
                        if enable:
                            new_lines.extend(
                                [re.sub(r"^\s*#\s*", "", l) for l in temp_lines]
                            )
                        else:
                            new_lines.extend(
                                [
                                    "# " + l
                                    if not l.strip().startswith("#")
                                    else l
                                    for l in temp_lines
                                ]
                            )
                    else:
                        new_lines.extend(temp_lines)
                else:
                    new_lines.append(line)
                    i += 1

            if not found:
                return JsonResponse(
                    {"success": False, "error": f"Rule ID {rule_id} not found."}
                )

            with open(file_path, "w") as f:
                f.writelines(new_lines)

            return JsonResponse({"success": True, "enabled": enable})

        except Exception as e:
            import traceback

            traceback.print_exc()
            return JsonResponse({"success": False, "error": str(e)})


@method_decorator(csrf_exempt, name="dispatch")
class UpdateSingleCRSRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request, filename):
        try:
            body = json.loads(request.body)
            new_rule = body.get("content", "").strip()
            rule_id_match = re.search(
                r"\bid\s*:\s*[\"']?(\d+)[\"']?", new_rule, re.IGNORECASE
            )
            if not rule_id_match:
                return JsonResponse(
                    {"success": False, "error": "Rule ID not found in new content."}
                )
            rule_id = rule_id_match.group(1)

            version = get_crs_full_version()
            rule_dir = get_rules_dir(version)
            file_path = os.path.join(rule_dir, filename)
            if not os.path.isfile(file_path):
                return JsonResponse({"success": False, "error": "File not found."})

            with open(file_path, "r") as f:
                lines = f.readlines()

            new_lines = []
            i = 0
            found = False
            while i < len(lines):
                line = lines[i]
                if line.lstrip().startswith(("SecRule", "SecAction")):
                    rule_lines = [line]
                    i += 1
                    while i < len(lines):
                        current_line = lines[i]
                        rule_lines.append(current_line)
                        i += 1
                        if (
                            not current_line.lstrip().startswith('"')
                            and not current_line.strip().startswith("#")
                            and current_line.strip() != ""
                        ):
                            break
                    full_rule = "".join(rule_lines)
                    if (
                        f"id:{rule_id}" in full_rule
                        or f"id:{rule_id}," in full_rule
                        or f'id:{rule_id}"' in full_rule
                        or f"id: {rule_id}" in full_rule
                    ):
                        new_lines.append(new_rule + "\n")
                        found = True
                    else:
                        new_lines.extend(rule_lines)
                else:
                    new_lines.append(line)
                    i += 1

            if not found:
                return JsonResponse(
                    {"success": False, "error": f"Rule ID {rule_id} not found in file."}
                )

            with open(file_path, "w") as f:
                f.writelines(new_lines)

            return JsonResponse({"success": True})
        except Exception as e:
            import traceback

            traceback.print_exc()
            return JsonResponse({"success": False, "error": str(e)})


# -------------------------
# Server network/traffic
# -------------------------

class ServerTrafficAnalysisView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/server_traffic.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script_path = os.path.join(base_dir, "scripts", "netstat.sh")
            output = subprocess.check_output([script_path], text=True)
        except Exception as e:
            context["error"] = str(e)
            return context

        sections = output.split("---")
        context["connection_count"] = sections[1].strip() if len(sections) > 1 else "0"
        context["top_ips"] = self._parse_ip_counts(
            sections[2] if len(sections) > 2 else ""
        )
        context["syn_recv_ips"] = self._parse_ip_counts(
            sections[3] if len(sections) > 3 else ""
        )
        context["states"] = self._parse_states(sections[4] if len(sections) > 4 else "")
        return context

    def _parse_ip_counts(self, raw: str):
        lines = raw.strip().splitlines()
        return [
            {"ip": line.split()[-1], "count": int(line.split()[0])}
            for line in lines
            if line.strip()
        ]

    def _parse_states(self, raw: str):
        lines = raw.strip().splitlines()
        return [
            {"state": line.split()[-1], "count": int(line.split()[0])}
            for line in lines
            if line.strip()
        ]


# -------------------------
# CRS versions page / switch
# -------------------------

class CrsVersionListView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request):
        versions = CrsVersion.objects.order_by("-published_at")
        installed_version = get_installed_crs_version()
        latest_version = get_latest_crs_version()

        for v in versions:
            v.normalized_tag = normalize_version(v.tag)

        return render(
            request,
            "dashboard/panel/crs_versions.html",
            {
                "versions": versions,
                "fetched_at": versions.first().fetched_at if versions else "N/A",
                "installed_version": installed_version,
                "latest_version": latest_version,
            },
        )


@method_decorator(csrf_exempt, name="dispatch")
class CrsSwitchVersionView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request):
        version = request.POST.get("version")
        if not version:
            messages.error(request, "Invalid version tag.")
            return redirect("wafinstaller:crs_version")

        exit_code, stderr = run_switch_version_script(version)
        if exit_code == 0:
            messages.success(request, f"CRS successfully switched to {version}.")
        else:
            messages.error(request, f"Switch failed: {stderr}")
        return redirect("wafinstaller:crs_version")


# -------------------------
# ModSecurity settings
# -------------------------

class ModSecuritySettingsView(LoginRequiredMixin, View):
    template_name = "dashboard/panel/waf_settings.html"
    login_url = "wafinstaller:login"

    def get(self, request):
        paths = get_paths()
        settings_map = {}
        try:
            with open(paths.modsec_conf, "r") as f:
                content = f.read()
                for key in MODSEC_KEYS:
                    match = re.search(
                        rf"^\s*{re.escape(key)}\s+(.+)", content, re.MULTILINE
                    )
                    value = match.group(1).strip() if match else ""
                    description = MODSEC_KEY_DESCRIPTIONS.get(key, "")
                    settings_map[key] = {"value": value, "description": description}
        except Exception as e:
            messages.error(request, f"Error reading ModSecurity config: {e}")

        return render(request, self.template_name, {"settings": settings_map})

    def post(self, request):
        paths = get_paths()
        try:
            with open(paths.modsec_conf, "r") as f:
                lines = f.readlines()

            updated_lines = []
            for line in lines:
                updated = False
                for key in MODSEC_KEYS:
                    if line.strip().startswith(key):
                        new_value = request.POST.get(key, "").strip()
                        updated_lines.append(f"{key} {new_value}\n")
                        updated = True
                        break
                if not updated:
                    updated_lines.append(line)

            with open(paths.modsec_conf, "w") as f:
                f.writelines(updated_lines)

            try:
                subprocess.run(paths.test_cmd, check=True)
                subprocess.run(paths.reload_cmd, check=True)
                messages.success(
                    request, "WAF settings updated and web server reloaded."
                )
            except subprocess.CalledProcessError:
                messages.warning(
                    request,
                    "Settings saved, but failed to reload the web server. Reload manually.",
                )
        except Exception as e:
            messages.error(request, f"Failed to update modsecurity.conf: {e}")

        return redirect("wafinstaller:crs_settings")


# -------------------------
# AFTER-CRS custom rules
# -------------------------

class CustomRulesView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request):
        actions = ["deny", "pass", "allow", "drop", "log", "nolog"]
        version = get_crs_full_version()
        if not version:
            messages.error(request, "Installed CRS version could not be detected.")
            return render(
                request,
                "dashboard/panel/custom_rules_list.html",
                {"rules": [], "version": None, "actions": actions},
            )

        path = _custom_after_path(version)
        rules = []
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SecRule"):
                        match = RULE_PATTERN.match(line)
                        if match:
                            rule = {
                                "variable": match.group(1),
                                "operator": match.group(2),
                                "id": match.group(3),
                                "phase": match.group(4),
                                "action": match.group(5),
                                "comment": match.group(6) if match.lastindex >= 6 else "",
                            }
                            if "severity:" in line:
                                rule["severity"] = self._extract_value(line, "severity")
                            if "tag:" in line:
                                tags = self._extract_all_values(line, "tag")
                                rule["tag"] = ",".join(tags)
                            if "t:" in line:
                                transforms = self._extract_all_values(line, "t")
                                rule["transformations"] = ",".join(transforms)
                            if "ver:" in line:
                                rule["ver"] = self._extract_value(line, "ver")
                            if "capture" in line:
                                rule["capture"] = True
                            rules.append(rule)
        except Exception as e:
            messages.error(request, f"Error reading custom rules: {e}")

        return render(
            request,
            "dashboard/panel/custom_rules_list.html",
            {"rules": rules, "version": version, "actions": actions},
        )

    def _extract_value(self, text, key):
        m = re.search(rf"{key}:(?:'([^']+)'|([^,\\\"]+))", text)
        if m:
            return (m.group(1) or m.group(2)).strip()
        return ""

    def _extract_all_values(self, text, key):
        matches = re.findall(rf"{key}:(?:'([^']+)'|([^,\\\"]+))", text)
        return [(m[0] or m[1]).strip() for m in matches]


class AddCustomRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request):
        version = request.GET.get("version") or get_crs_full_version()
        return render(
            request, "dashboard/panel/custom_rule_add.html", {"version": version}
        )

    def post(self, request):
        version = request.POST.get("version") or get_crs_full_version()
        path = _custom_after_path(version)

        rule_id = request.POST.get("id")
        phase = request.POST.get("phase")
        action = request.POST.get("action")
        variable = request.POST.get("variable")
        operator = request.POST.get("operator")
        comment = request.POST.get("comment")
        severity = request.POST.get("severity")
        transformations = request.POST.get("transformations", "")
        tag = request.POST.get("tag", "")
        ver = request.POST.get("ver", "OWASP_CRS/4.17.0-dev")
        capture = request.POST.get("capture")

        actions = [f"id:{rule_id}", f"phase:{phase}", action]
        if capture:
            actions.append("capture")
        if comment:
            actions.append(f"msg:'{comment}'")
        if severity:
            actions.append(f"severity:{severity}")
        if tag:
            for t in tag.split(","):
                t = t.strip()
                if t:
                    actions.append(f"tag:'{t}'")
        if ver:
            actions.append(f"ver:'{ver}'")
        if transformations:
            for t in transformations.split(","):
                t_clean = t.strip()
                if t_clean.startswith("t:"):
                    t_clean = t_clean[2:]
                if t_clean:
                    actions.append(f"t:{t_clean}")

        rule_line = f'SecRule {variable} "{operator}" "{",".join(actions)}"\n'

        paths = get_paths()
        try:
            with open(path, "a") as f:
                f.write(rule_line)
            subprocess.run(paths.test_cmd, check=True)
            subprocess.run(paths.reload_cmd, check=True)
            messages.success(
                request, "Custom rule added and web server reloaded successfully."
            )
        except subprocess.CalledProcessError as e:
            messages.warning(request, f"Rule saved but failed to reload server: {e}")
        except Exception as e:
            messages.error(request, f"Failed to add rule: {e}")

        return redirect(reverse("wafinstaller:custom_rules") + f"?version={version}")


class EditCustomRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request, rule_id):
        version = request.POST.get("version")
        if not version:
            messages.error(request, "Missing CRS version.")
            return redirect("wafinstaller:custom_rules")

        path = _custom_after_path(version)

        new_id = request.POST.get("id")
        phase = request.POST.get("phase")
        action = request.POST.get("action")
        variable = request.POST.get("variable")
        operator = request.POST.get("operator")
        comment = request.POST.get("comment")
        severity = request.POST.get("severity")
        transformations = request.POST.get("transformations", "")
        tag = request.POST.get("tag", "")
        ver = request.POST.get("ver", "OWASP_CRS/4.17.0-dev")
        capture = request.POST.get("capture")

        updated_lines = []
        rule_found = False
        paths = get_paths()

        try:
            with open(path, "r") as f:
                for line in f:
                    if f"id:{rule_id}" in line:
                        actions = [f"id:{new_id}", f"phase:{phase}", action]
                        if capture:
                            actions.append("capture")
                        if comment:
                            actions.append(f"msg:'{comment}'")
                        if severity:
                            actions.append(f"severity:{severity}")
                        if tag:
                            for t in tag.split(","):
                                actions.append(f"tag:'{t.strip()}'")
                        if ver:
                            actions.append(f"ver:'{ver}'")
                        if transformations:
                            for t in transformations.split(","):
                                t_clean = t.strip()
                                if t_clean.startswith("t:"):
                                    t_clean = t_clean[2:]
                                if t_clean:
                                    actions.append(f"t:{t_clean}")
                        new_rule = (
                            f'SecRule {variable} "{operator}" "{",".join(actions)}"\n'
                        )
                        updated_lines.append(new_rule)
                        rule_found = True
                    else:
                        updated_lines.append(line)

            if not rule_found:
                messages.error(request, f"Rule ID {rule_id} not found.")
                return redirect("wafinstaller:custom_rules")

            with open(path, "w") as f:
                f.writelines(updated_lines)

            subprocess.run(paths.test_cmd, check=True)
            subprocess.run(paths.reload_cmd, check=True)
            messages.success(
                request, f"Rule {rule_id} updated and web server reloaded successfully."
            )
        except subprocess.CalledProcessError as e:
            messages.warning(request, f"Rule updated but reload failed: {e}")
        except Exception as e:
            messages.error(request, f"Failed to update rule: {e}")

        return redirect(reverse("wafinstaller:custom_rules") + f"?version={version}")


class DeleteCustomRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def post(self, request, rule_id):
        version = request.POST.get("version")
        if not version:
            messages.error(request, "CRS version is missing.")
            return redirect("wafinstaller:custom_rules")

        path = _custom_after_path(version)
        updated_lines = []
        rule_found = False
        paths = get_paths()

        try:
            with open(path, "r") as f:
                for line in f:
                    if f"id:{rule_id}" in line:
                        rule_found = True
                        continue
                    updated_lines.append(line)

            if not rule_found:
                messages.warning(
                    request, f"Rule ID {rule_id} not found. Nothing deleted."
                )
            else:
                with open(path, "w") as f:
                    f.writelines(updated_lines)
                subprocess.run(paths.test_cmd, check=True)
                subprocess.run(paths.reload_cmd, check=True)
                messages.success(
                    request, f"Rule {rule_id} deleted and web server reloaded successfully."
                )

        except subprocess.CalledProcessError as e:
            messages.warning(request, f"Rule deleted but reload failed: {e}")
        except Exception as e:
            messages.error(request, f"Error deleting rule: {e}")

        return redirect(reverse("wafinstaller:custom_rules") + f"?version={version}")


# -------------------------
# App settings (WafControl)
# -------------------------

class AppSettingsView(LoginRequiredMixin, View):
    template_name = "dashboard/panel/app_settings.html"
    login_url = "wafinstaller:login"

    def get(self, request):
        settings_map = {}
        app_config = load_app_settings()
        for key, meta in APP_KEYS.items():
            settings_map[key] = {
                "value": app_config.get(key, meta["default"]),
                "description": meta["description"],
            }
        return render(request, self.template_name, {"settings": settings_map})

    def post(self, request):
        try:
            app_settings = {
                key: request.POST.get(key, APP_KEYS[key]["default"]).strip()
                for key in APP_KEYS
            }
            save_app_settings(app_settings)
            messages.success(request, "Application settings saved successfully.")
        except Exception as e:
            messages.error(request, f"Error saving settings: {e}")
        return redirect("wafinstaller:app_settings")


# -------------------------
# Admin profile (2FA)
# -------------------------

class AdminProfileView(LoginRequiredMixin, View):
    def get(self, request):
        profile_form = AdminProfileForm(instance=request.user)
        password_form = AdminPasswordForm(user=request.user)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        qr_code = None

        if not profile.two_factor_enabled and profile.two_factor_secret:
            totp = pyotp.TOTP(profile.two_factor_secret)
            uri = totp.provisioning_uri(
                name=request.user.email, issuer_name="OWASP WAFControl"
            )
            qr = qrcode.make(uri)
            buffer = io.BytesIO()
            qr.save(buffer, format="PNG")
            qr_code = base64.b64encode(buffer.getvalue()).decode()

        active_tab = request.GET.get("tab", "personal-information")

        return render(
            request,
            "dashboard/panel/admin_profile.html",
            {
                "profile_form": profile_form,
                "password_form": password_form,
                "qr_code": qr_code,
                "secret": profile.two_factor_secret,
                "active_tab": active_tab,
            },
        )

    def post(self, request):
        user = request.user
        profile, _ = UserProfile.objects.get_or_create(user=user)

        if "update_profile" in request.POST:
            profile_form = AdminProfileForm(request.POST, instance=user)
            if profile_form.is_valid():
                profile_form.save()
                messages.success(request, "Profile updated successfully.")
                return redirect("/dashboard/profile/?tab=personal-information")

        elif "change_password" in request.POST:
            password_form = AdminPasswordForm(user=user, data=request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, "Password changed successfully.")
                return redirect("/dashboard/profile/?tab=change-password")
            else:
                messages.error(request, "Password change failed.")
                return redirect("/dashboard/profile/?tab=change-password")

        elif "start_2fa" in request.POST:
            secret = pyotp.random_base32()
            profile.two_factor_secret = secret
            profile.save()
            return redirect("/dashboard/profile/?tab=two-factor")

        elif "enable_2fa" in request.POST:
            otp = request.POST.get("otp")
            totp = pyotp.TOTP(profile.two_factor_secret)
            if totp.verify(otp):
                profile.two_factor_enabled = True
                profile.save()
                messages.success(request, "Two-Factor Authentication enabled.")
            else:
                messages.error(request, "Invalid verification code.")
            return redirect("/dashboard/profile/?tab=two-factor")

        elif "disable_2fa" in request.POST:
            otp = request.POST.get("otp")
            totp = pyotp.TOTP(profile.two_factor_secret)
            if totp.verify(otp):
                profile.two_factor_enabled = False
                profile.two_factor_secret = ""
                profile.save()
                messages.success(request, "Two-Factor Authentication disabled.")
            else:
                messages.error(request, "Invalid 2FA code. Deactivation failed.")
            return redirect("/dashboard/profile/?tab=two-factor")

        return redirect("/dashboard/profile/")


# -------------------------
# Force-fetch CRS versions
# -------------------------

@method_decorator(csrf_exempt, name="dispatch")
class ForceFetchCrsVersionsView(View):
    def post(self, request):
        try:
            fetch_crs_versions_task()
            messages.success(request, "Successfully fetched the latest CRS versions.")
        except Exception as e:
            messages.error(request, f"Failed to fetch CRS versions: {e}")
        return redirect("wafinstaller:crs_version")
