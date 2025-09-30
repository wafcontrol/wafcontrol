from django.urls import path

from . import views
from wafinstaller.views import (
    LoginsView, DashboardView, install_waf_page, WafAttacksView, CriticalWafAttacksView,
    GetTaskStatusView, CRSRuleListView, ReadCRSRuleView, SaveCRSRuleView,
    ToggleCRSRuleView, CRSCategoriesView, CRSRuleListByFileView, UpdateSingleCRSRuleView,
    ServerTrafficAnalysisView, TopAttackersView, CrsVersionListView, CrsSwitchVersionView,
    ModSecuritySettingsView, CustomRulesView, AddCustomRuleView, DeleteCustomRuleView,
    EditCustomRuleView, AppSettingsView, AdminProfileView, Verify2FAView,
    CustomLogoutView, HomeRedirectView, CrsUpdateSyncView, ForceFetchCrsVersionsView
)

app_name = 'wafinstaller'
urlpatterns = [
    path('', HomeRedirectView.as_view(), name='home'),

    # Auth
    path('login/', LoginsView.as_view(), name='login'),
    path('verify-2fa/', Verify2FAView.as_view(), name='verify_2fa'),
    path('dashboard/logout/', CustomLogoutView.as_view(), name='logout'),

    # Dashboard
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path("dashboard/update-crs/", CrsUpdateSyncView.as_view(), name="update_crs_sync"),
    path('dashboard/dos/ddos/', ServerTrafficAnalysisView.as_view(), name='ddos'),

    # WAF install
    path('dashboard/install-waf/', install_waf_page, name='install_waf_page'),

    # Attacks
    path('dashboard/attacks/', WafAttacksView.as_view(), name='waf_attacks'),
    path('dashboard/critical/', CriticalWafAttacksView.as_view(), name='critical_attacks'),
    path('dashboard/top-attacker/', TopAttackersView.as_view(), name='top-attacker'),

    # CRS Rules – browse & edit
    path('dashboard/crs-rules/', CRSRuleListView.as_view(), name='crs_rules'),
    path('crs/rules/view/<str:filename>/', ReadCRSRuleView.as_view(), name='view_crs_rule'),
    path('crs/rules/save/<str:filename>/', SaveCRSRuleView.as_view(), name='save_crs_rule'),

    # Rules Setting / categories / toggle / inline update
    path('dashboard/crs/categories/', CRSCategoriesView.as_view(), name='categorized_files'),
    path('dashboard/crs/rules/<str:filename>/', CRSRuleListByFileView.as_view(), name='rules_by_file'),
    path('dashboard/crs/rules/toggle/', ToggleCRSRuleView.as_view(), name='toggle_crs_rule'),
    path('dashboard/crs/rules/update/<str:filename>/', UpdateSingleCRSRuleView.as_view(), name='update_crs_rule'),

    # CRS versions
    path('dashboard/crs/version/', CrsVersionListView.as_view(), name='crs_version'),
    path("crs/switch/", CrsSwitchVersionView.as_view(), name="switch_crs_version"),
    path("dashboard/crs/settings/", ModSecuritySettingsView.as_view(), name="crs_settings"),
    path('crs/force-fetch/', ForceFetchCrsVersionsView.as_view(), name='force_fetch_crs_versions'),

    # Custom rules AFTER-CRS
    path('dashboard/crs/custom-rules/', CustomRulesView.as_view(), name="custom_rules"),
    path('dashboard/crs/custom-rules/add/', AddCustomRuleView.as_view(), name="add_custom_rule"),
    path('custom-rules/delete/<int:rule_id>/', DeleteCustomRuleView.as_view(), name="delete_custom_rule"),
    path("custom-rules/edit/<str:rule_id>/", EditCustomRuleView.as_view(), name="edit_custom_rule"),

    # App config + Admin profile
    path("dashboard/settings/", AppSettingsView.as_view(), name="app_settings"),
    path('dashboard/profile/', AdminProfileView.as_view(), name='admin_profile'),
]
