from django.urls import path

from . import views
from wafinstaller.views import (
    LoginsView, DashboardView, install_waf_page, WafAttacksView, CriticalWafAttacksView,
    GetTaskStatusView, CRSRuleListView, ReadCRSRuleView, SaveCRSRuleView,
    ToggleCRSRuleView, CRSCategoriesView, CRSRuleListByFileView, UpdateSingleCRSRuleView,
    ServerTrafficAnalysisView, TopAttackersView, CrsVersionListView, CrsSwitchVersionView,
    ModSecuritySettingsView, CustomRulesView, AddCustomRuleView, DeleteCustomRuleView,
    EditCustomRuleView, AppSettingsView, AdminProfileView, Verify2FAView,
    CustomLogoutView, HomeRedirectView, CrsUpdateSyncView, ForceFetchCrsVersionsView,
    ServerConfListView, ServerConfReadView, ServerConfSaveView,
    UserListView, UserCreateView, UserEditView, UserDeleteView,
    SyslogConfigView, IpListListView, IpListCreateView, IpListEditView, IpListDeleteView,
    IpListRefreshGeoView, AttackRequestView
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
    path('dashboard/attacks/<int:attack_id>/request/', AttackRequestView.as_view(), name='attack_request'),
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

    # Web server config files (server = nginx | apache)
    path('dashboard/<str:server>/conf/', ServerConfListView.as_view(), name='server_conf'),
    path('<str:server>/conf/view/<str:filename>/', ServerConfReadView.as_view(), name='server_conf_view'),
    path('<str:server>/conf/save/<str:filename>/', ServerConfSaveView.as_view(), name='server_conf_save'),

    # Users management
    path('dashboard/users/', UserListView.as_view(), name='users'),
    path('dashboard/users/add/', UserCreateView.as_view(), name='user_add'),
    path('dashboard/users/<int:user_id>/', UserEditView.as_view(), name='user_edit'),
    path('dashboard/users/<int:user_id>/delete/', UserDeleteView.as_view(), name='user_delete'),

    # IP lists
    path('dashboard/ip-lists/', IpListListView.as_view(), name='ip_lists'),
    path('dashboard/ip-lists/add/', IpListCreateView.as_view(), name='ip_list_add'),
    path('dashboard/ip-lists/<int:list_id>/', IpListEditView.as_view(), name='ip_list_edit'),
    path('dashboard/ip-lists/refresh-geo/', IpListRefreshGeoView.as_view(), name='ip_lists_refresh_geo'),
    path('dashboard/ip-lists/<int:list_id>/delete/', IpListDeleteView.as_view(), name='ip_list_delete'),

    # Syslog
    path('dashboard/syslog/', SyslogConfigView.as_view(), name='syslog_config'),

    # App config + Admin profile
    path("dashboard/settings/", AppSettingsView.as_view(), name="app_settings"),
    path('dashboard/profile/', AdminProfileView.as_view(), name='admin_profile'),
]
